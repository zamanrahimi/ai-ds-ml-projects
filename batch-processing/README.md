# Batch PDF download with change detection

Reads the PDF list from **source_pdf** (commit to GitHub). Downloads PDFs into **download_pdf** and only re-downloads when content has changed (ETag or SHA-256 hash).

## Folders

| Folder | Purpose | GitHub |
|--------|---------|--------|
| **source_pdf/** | Source of the list: `urls.txt` and optional `config.json` (API endpoint). | ✅ Commit this |
| **download_pdf/** | Where PDFs are downloaded. | ❌ Ignored (in .gitignore) |

## Setup

```bash
pip install -r requirements.txt
```

## Run

```bash
python batch_processing.py
```

The script reads from **source_pdf** (urls.txt or API from config.json) and downloads into **download_pdf**. New or changed PDFs are downloaded; unchanged ones are skipped.

To verify URLs without downloading:

```bash
python batch_processing.py --verify
```

## Source: source_pdf (for GitHub)

**Option A – API**  
Put **source_pdf/config.json** with your API URL:
```json
{ "api_endpoint": "https://your-server.com/api/pdfs" }
```
The script GETs the API and discovers PDF URLs. Copy **config.json.example** to **config.json** and edit.

**Option B – Manual list**  
Put PDF URLs in **source_pdf/urls.txt** (one per line). Lines starting with `#` are ignored.

API response can be: array of URL strings; array of objects with `url`/`link`/`href`; or object with key `files`/`pdfs`/`urls`/`items`/`data`.

## Files

| File / folder | Purpose |
|---------------|--------|
| `batch_processing.py` | Main script |
| `source_pdf/urls.txt` | List of PDF URLs (one per line). Commit to GitHub. |
| `source_pdf/config.json` | Optional. `{ "api_endpoint": "https://..." }`. Commit to GitHub (or add to .gitignore if secret). |
| `download_pdf/` | Downloaded PDFs (local only, not committed). |
| `download_state.json` | ETag/hash per URL; used to skip unchanged files (local only). |
