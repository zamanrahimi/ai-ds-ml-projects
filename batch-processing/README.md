# Batch PDF download with change detection

**Discovers all PDFs** in the server’s **source_pdf** folder (no need to list every URL). Downloads them into **download_pdf** and only re-downloads when content has changed (ETag or SHA-256 hash).

## Folders

| Folder | Purpose | GitHub |
|--------|---------|--------|
| **source_pdf/** | Config only: `config.json` (server URL + optional list API). No manual URL list. | ✅ Commit this |
| **download_pdf/** | Where PDFs are downloaded. | ❌ Ignored (in .gitignore) |

## Setup

From the **batch-processing** folder, install dependencies (use the same Python you will use to run the script):

```bash
cd batch-processing
pip install -r requirements.txt
```

**If you get `ModuleNotFoundError: No module named 'requests'`:** the Python that runs the script doesn’t have `requests`. Install for that Python, for example:
- `py -3 -m pip install -r requirements.txt` then `py -3 batch_processing.py` (Windows), or
- Activate your venv then `pip install -r requirements.txt` and `python batch_processing.py`.

## Run

```bash
python batch_processing.py
```

The script **lists every PDF** in the server’s source_pdf folder (via your list URL or directory listing), then downloads new or changed files into **download_pdf**. You don’t need to maintain urls.txt.

Verify that the server list works (no download):

```bash
python batch_processing.py --verify
```

## Config: discover all PDFs on the server (recommended)

Put **source_pdf/config.json** (copy from **config.json.example**):

```json
{
  "source_pdf_base_url": "https://your-server.com/source_pdf/",
  "source_pdf_list_url": "https://your-server.com/api/source_pdf/list"
}
```

- **source_pdf_base_url** – Base URL of the folder on the server where PDFs live. Used to build full URLs when the list returns filenames only. Must end with `/`.
- **source_pdf_list_url** – (Optional) URL that returns the list of files in that folder.  
  - If **omitted**, the script GETs **source_pdf_base_url** and parses the response as **HTML directory listing** or **JSON** (e.g. `["file1.pdf", "file2.pdf"]` or `{"files": ["a.pdf", ...]}`).  
  - If **set**, the script GETs this URL instead. Response can be:
    - **JSON**: array of filenames (`["a.pdf", "b.pdf"]`) or full URLs; or object with key `files` / `pdfs` / `items` / `data` containing that array.
    - **HTML**: page with links like `<a href="x.pdf">`; the script collects all `.pdf` links.

The script then downloads each discovered PDF into **download_pdf** and skips unchanged ones (ETag/hash).

## Fallbacks

- **api_endpoint** in config – If you already have an API that returns a list of PDF URLs, set this instead; the script will use it and ignore source_pdf_*.
- **source_pdf/urls.txt** – If no server config works, the script falls back to this file (one URL per line). Use only for small manual lists.

## Files

| File / folder | Purpose |
|---------------|--------|
| `batch_processing.py` | Main script |
| `source_pdf/config.json` | Server base URL + optional list URL. Commit to GitHub (or .gitignore if secret). |
| `source_pdf/urls.txt` | Fallback manual list (one URL per line) when server discovery is not used. |
| `download_pdf/` | Downloaded PDFs (local only). |
| `download_state.json` | ETag/hash per URL; used to skip unchanged files (local only). |
