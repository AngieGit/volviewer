<h1 align="left">
  <img src="favicon.svg" alt="VolViewer favicon" width="40" height="40" />
  VolViewer
</h1>

VolViewer is a local web workspace for inspecting memory images with the [Volatility 3](https://github.com/volatilityfoundation/volatility3) framework. It provides a browser interface for uploading an image, running a supported plugin, and reviewing JSON results in a searchable, sortable, paginated table.

VolViewer is intended for local forensic analysis. The Python server binds to `127.0.0.1` by default and does not provide authentication or multi-user access.

## Features

- Local browser UI with drag-and-drop memory-image loading
- Windows process, network, registry, command-line, memory-injection, and timeline plugins
- Volatility JSON output rendered as a searchable and sortable table
- Automatic `windows.info.Info` overview when an image is loaded
- Alternate timeline view for timestamped plugin output
- Per-plugin job status, cancellation, and browser print-to-PDF export
- Court-style report cover page with explicit examination disclaimer
- 2 GB client and server upload limit
- Volatility executable discovery through the installed `vol` command, a local `vol.py`, or `VOLATILITY_PATH`

## Requirements

- Python 3.8 or newer
- Volatility Framework 3. The pinned dependency in `requirements.txt` is `volatility3==2.28.0`.
- A compatible memory image and any symbol files required by Volatility for that image
- A modern browser with JavaScript enabled

## Installation

Installing VolViewer also installs the pinned Volatility 3 dependency. From a cloned checkout:

Clone the repository and create a virtual environment:

```powershell
git clone https://github.com/angiegit/VolViewer.git
cd VolViewer
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install .
```

On macOS or Linux, use the equivalent commands:

```bash
git clone https://github.com/angiegit/VolViewer.git
cd VolViewer
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
```

To install directly from GitHub:

```bash
python -m pip install "git+https://github.com/angiegit/VolViewer.git"
```

For editable development installs, use `python -m pip install -e .`. The `requirements.txt` file also points to the local package and can be used with `python -m pip install -r requirements.txt`.

## Run

Start the local server from the repository directory:

```powershell
py server.py
```

```bash
python3 server.py
```

Open [http://localhost:4173](http://localhost:4173) in your browser. Set `PORT` before starting the server to use another local port:

```powershell
$env:PORT = '8080'
py server.py
```

The UI shows whether the Volatility engine was detected. The server looks for Volatility in this order:

1. The path in `VOLATILITY_PATH`
2. `vol.py` in the repository directory
3. `volatility3/vol.py` in the repository directory
4. The `vol` command on `PATH`

If the installed command is not found automatically, configure it explicitly:

```powershell
$env:VOLATILITY_PATH = 'C:\path\to\vol.exe'
py server.py
```

For a Python script installation:

```powershell
$env:VOLATILITY_PATH = 'C:\path\to\vol.py'
py server.py
```

## Using VolViewer

1. Choose or drop a memory image into the **Evidence source** panel. The first-run workspace explains supported evidence and expected analysis.
2. VolViewer automatically runs `windows.info.Info` for a quick image overview.
3. Select another plugin and press its run button. The status icon beside each plugin shows queued, running, complete, or error state.
4. Search, sort, and page through the returned rows. Use **Timeline view** for timestamped results.
5. Use **Export PDF** to open the browser print dialog and save the current view with an examination cover page.

The initial catalog contains `windows.info.Info`, process, network, registry, command-line, `windows.malfind.Malfind`, `windows.suspicious_threads.SuspiciousThreads`, and `timeliner.Timeliner`. These identifiers were checked against the Volatility CLI help for the pinned framework version. Plugin availability still depends on the installed Volatility version and the target image.

## Data and privacy

Uploaded images are written to `data/` using a generated job identifier. In this workspace, that directory contains the retained memory-image files, typically with `.winddramimage` or `.mddramimage` extensions. These are binary evidence captures, not screenshots or ordinary image files, and may be approximately 1 GB each.

The sidebar's **Saved evidence** history reads this directory and lets you reuse a stored capture for another plugin run or delete it explicitly. Deletion is permanent and is blocked while the image is being analyzed. Results are held in the current browser session; loading a saved capture reruns the selected plugin rather than uploading a second copy.

They are not removed when a job is cancelled, so delete evidence files from **Saved evidence** when they are no longer needed. Treat this directory as sensitive forensic material and do not expose the server beyond the local machine without adding authentication, access controls, and a deployment-specific security review.

VolViewer passes the selected plugin and image path to Volatility and displays its JSON output. It does not modify the source image. Volatility may download or use symbol files depending on its configuration and the image being analyzed.

## API endpoints

The browser uses these local endpoints:

- `GET /api/health` - reports engine detection and the upload limit
- `GET /api/evidence` - lists retained evidence filenames, sizes, and modification dates
- `POST /api/analyze` - accepts multipart fields `image` and `plugin`
- `POST /api/analyze-existing` - reruns a plugin against a stored evidence filename
- `DELETE /api/evidence/<filename>` - permanently deletes a stored evidence file
- `GET /api/jobs/<id>` - returns queued, running, complete, error, or cancelled job state
- `DELETE /api/jobs/<id>` - requests cancellation of a running job

## Development notes

The application has no frontend build step or JavaScript package manager. `server.py` serves `index.html`, `app.js`, and `styles.css` directly. Run it from the repository root so the static files and `data/` directory resolve correctly.

The project is currently a preview release. The plugin catalog and result presentation are intentionally focused on the current local workflow; add and verify plugin names against the Volatility version installed in the target environment before relying on them in an investigation.

## Acknowledgements

- [Volatility Foundation](https://github.com/volatilityfoundation/volatility3) for creating and maintaining the Volatility 3 framework that powers the main application.
- [Anant Shrivastava](https://github.com/anantshri) for the initial guidance and improvements.