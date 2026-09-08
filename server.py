import cgi
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse


ROOT = Path(__file__).parent
DATA_DIR = ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)
JOBS = {}
JOBS_LOCK = threading.Lock()
MAX_IMAGE_BYTES = 2 * 1024 * 1024 * 1024


def find_volatility():
    configured = os.environ.get("VOLATILITY_PATH")
    candidates = [configured] if configured else []
    configured_command = shutil.which(configured) if configured else None
    if configured_command:
        return [configured_command]
    configured_path = next((candidate for candidate in candidates if candidate and Path(candidate).exists()), None)
    if configured_path:
        if Path(configured_path).suffix.lower() == ".py":
            return [sys.executable, configured_path]
        return [configured_path]
    bundled_runner = ROOT / "volatility_runner.py"
    if bundled_runner.exists():
        try:
            import volatility3
            return [sys.executable, str(bundled_runner)]
        except ImportError:
            pass
    candidates = [str(ROOT / "vol.py"), str(ROOT / "volatility3" / "vol.py")]
    local_script = next((candidate for candidate in candidates if candidate and Path(candidate).suffix.lower() == ".py" and Path(candidate).exists()), None)
    if local_script:
        return [sys.executable, local_script]
    local_executable = next((candidate for candidate in candidates if candidate and Path(candidate).suffix.lower() in (".exe", ".cmd", ".bat") and Path(candidate).exists()), None)
    if local_executable:
        return [local_executable]
    command = shutil.which(configured) if configured else shutil.which("vol")
    return [command] if command else None


def json_response(handler, payload, status=200):
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.end_headers()
    try:
        handler.wfile.write(body)
    except (BrokenPipeError, ConnectionAbortedError):
        # The client may cancel a large upload before the job id is returned.
        pass


def run_analysis(job_id, image_path, plugin):
    volatility_command = find_volatility()
    with JOBS_LOCK:
        job = JOBS[job_id]
        job["status"] = "running"
        job["message"] = "Running Volatility 3"

    if not volatility_command:
        with JOBS_LOCK:
            job.update({"status": "error", "message": "Volatility was not found. Set VOLATILITY_PATH or place vol.py in this folder."})
        return

    command = volatility_command + ["-f", str(image_path), "-r", "json", plugin]
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        with JOBS_LOCK:
            JOBS[job_id]["process"] = process
        output, progress = process.communicate()
        with JOBS_LOCK:
            cancelled = JOBS[job_id]["status"] == "cancelled"
        if cancelled:
            return
        return_code = process.returncode
        if return_code != 0:
            detail = progress.strip().splitlines()[-1] if progress.strip() else "No diagnostic output"
            raise RuntimeError("Volatility exited with code %s: %s" % (return_code, detail))
        parsed = parse_volatility_json(output)
        with JOBS_LOCK:
            JOBS[job_id].update({"status": "complete", "message": "Analysis complete", "result": parsed})
    except Exception as error:
        with JOBS_LOCK:
            JOBS[job_id].update({"status": "error", "message": str(error)})


def parse_volatility_json(raw_output):
    try:
        document = json.loads(raw_output)
    except json.JSONDecodeError:
        lines = [line for line in raw_output.splitlines() if line.strip()]
        document = [json.loads(line) for line in lines if line.lstrip().startswith(("{", "["))]
    rows = document if isinstance(document, list) else document.get("rows", document.get("data", []))
    return {"rows": rows if isinstance(rows, list) else [], "raw": raw_output}


def evidence_path(filename):
    candidate = Path(unquote(filename)).name
    path = DATA_DIR / candidate
    return path if candidate == filename and path.is_file() and DATA_DIR in path.parents else None


def evidence_catalog():
    return [{"filename": path.name, "size": path.stat().st_size, "modified": path.stat().st_mtime}
            for path in sorted(DATA_DIR.iterdir(), key=lambda item: item.stat().st_mtime, reverse=True)
            if path.is_file() and not path.name.startswith(".")]


class Handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        route = urlparse(self.path).path
        if route == "/api/health":
            json_response(self, {"volatility": bool(find_volatility()), "imageLimit": MAX_IMAGE_BYTES})
            return
        if route == "/api/evidence":
            json_response(self, {"items": evidence_catalog()})
            return
        if route.startswith("/api/jobs/"):
            job_id = route.rsplit("/", 1)[-1]
            with JOBS_LOCK:
                job = dict(JOBS.get(job_id, {}))
            job.pop("process", None)
            if not job:
                json_response(self, {"error": "Job not found"}, 404)
            else:
                json_response(self, job)
            return
        file_path = ROOT / ("index.html" if route == "/" else route.lstrip("/"))
        if not file_path.exists() or not file_path.is_file() or ROOT not in file_path.parents and file_path != ROOT / "index.html":
            self.send_error(404)
            return
        content_type = {".css": "text/css", ".js": "application/javascript", ".html": "text/html", ".svg": "image/svg+xml"}.get(file_path.suffix, "application/octet-stream")
        body = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        route = urlparse(self.path).path
        if route == "/api/analyze-existing":
            length = int(self.headers.get("Content-Length", "0"))
            fields = parse_qs(self.rfile.read(length).decode("utf-8"))
            filename = fields.get("filename", [""])[0]
            plugin = fields.get("plugin", ["windows.info.Info"])[0]
            image_path = evidence_path(filename)
            if not image_path:
                json_response(self, {"error": "Evidence image not found"}, 404)
                return
            job_id = uuid.uuid4().hex[:12]
            with JOBS_LOCK:
                JOBS[job_id] = {"id": job_id, "status": "queued", "plugin": plugin, "filename": filename, "message": "Queued"}
            threading.Thread(target=run_analysis, args=(job_id, image_path, plugin), daemon=True).start()
            json_response(self, {"id": job_id})
            return
        if route != "/api/analyze":
            self.send_error(404)
            return
        form = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ={"REQUEST_METHOD": "POST", "CONTENT_TYPE": self.headers.get("Content-Type", "")})
        image = form["image"] if "image" in form else None
        plugin = form.getfirst("plugin", "windows.pslist.PsList")
        if image is None or not getattr(image, "filename", None):
            json_response(self, {"error": "A memory image is required"}, 400)
            return
        job_id = uuid.uuid4().hex[:12]
        image_path = DATA_DIR / (job_id + "-" + Path(image.filename).name)
        with image.file as source, image_path.open("wb") as target:
            shutil.copyfileobj(source, target)
        if image_path.stat().st_size > MAX_IMAGE_BYTES:
            image_path.unlink(missing_ok=True)
            json_response(self, {"error": "Memory images must be 2 GB or smaller"}, 413)
            return
        with JOBS_LOCK:
            JOBS[job_id] = {"id": job_id, "status": "queued", "plugin": plugin, "filename": image.filename, "message": "Queued"}
        threading.Thread(target=run_analysis, args=(job_id, image_path, plugin), daemon=True).start()
        json_response(self, {"id": job_id, "filename": image_path.name})

    def do_DELETE(self):
        route = urlparse(self.path).path
        if route.startswith("/api/evidence/"):
            filename = unquote(route.rsplit("/", 1)[-1])
            image_path = evidence_path(filename)
            if not image_path:
                json_response(self, {"error": "Evidence image not found"}, 404)
                return
            with JOBS_LOCK:
                active = any(job.get("filename") == filename and job.get("status") in ("queued", "running") for job in JOBS.values())
            if active:
                json_response(self, {"error": "Cannot delete evidence while it is being analyzed"}, 409)
                return
            image_path.unlink()
            json_response(self, {"status": "deleted", "filename": filename})
            return
        if not route.startswith("/api/jobs/"):
            self.send_error(404)
            return
        job_id = route.rsplit("/", 1)[-1]
        with JOBS_LOCK:
            job = JOBS.get(job_id)
            if not job:
                json_response(self, {"error": "Job not found"}, 404)
                return
            process = job.get("process")
            if process and process.poll() is None:
                process.terminate()
            job["status"] = "cancelled"
            job["message"] = "Analysis cancelled; image remains in data/"
        json_response(self, {"status": "cancelled"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "4173"))
    print("VolViewer running at http://localhost:%s" % port)
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()