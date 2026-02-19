# =============================================================================
# BATCH PDF DOWNLOADER — HOW THIS SCRIPT WORKS (top-to-bottom execution)
#
# STEP 1  — Figure out WHERE to get the PDF list
#           (server folder  →  API endpoint  →  urls.txt fallback)
# STEP 2  — Load last-run state from download_state.json
#           (remembers ETag / hash of every previously downloaded file)
# STEP 3  — Clear unprocessed_pdf/ so it only holds THIS run's new/changed files
# STEP 4  — For each PDF URL:
#     STEP 4a  Check if content has changed (ETag or SHA-256 hash)
#     STEP 4b  Skip if unchanged; download if new or changed
#     STEP 4c  Save to processed_pdf/ (full mirror) AND unprocessed_pdf/ (new/changed only)
#     STEP 4d  Update the state record for that URL
# STEP 5  — Save updated state to download_state.json
# STEP 6  — Print summary (downloaded vs skipped)
#
# Run normally :  python batch_processing.py
# Verify URLs  :  python batch_processing.py --verify
# =============================================================================

"""
Batch download PDFs from a server. Discovers all PDFs in the server's source_pdf folder
(list API or directory listing); only re-downloads when content has changed (ETag/hash).
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from urllib.parse import urljoin

# ── Dependency guard ─────────────────────────────────────────────────────────
# If 'requests' is not installed the script tells the user how to fix it and exits
# cleanly instead of showing a cryptic ImportError.
try:
    import requests
except ModuleNotFoundError:
    print("Missing dependency: requests. Install with:", file=sys.stderr)
    print("  pip install -r requirements.txt", file=sys.stderr)
    print("Or: pip install requests", file=sys.stderr)
    sys.exit(1)

# ── Folder layout ─────────────────────────────────────────────────────────────
# All paths are relative to this script's own directory so the project is portable.
BASE_DIR = Path(__file__).resolve().parent
SOURCE_PDF_DIR = BASE_DIR / "source_pdf"    # holds urls.txt and config.json
URLS_FILE = SOURCE_PDF_DIR / "urls.txt"     # manual list of PDF URLs (fallback)
CONFIG_FILE = SOURCE_PDF_DIR / "config.json"

STATE_FILE = BASE_DIR / "download_state.json"   # remembers what was downloaded before
DOWNLOAD_DIR = BASE_DIR / "download_pdf"
# processed_pdf  → full mirror of the server; every PDF that exists remotely lives here
PROCESSED_DIR = DOWNLOAD_DIR / "processed_pdf"
# unprocessed_pdf → only new/changed PDFs from the CURRENT run; cleared at start of each run
UNPROCESSED_DIR = DOWNLOAD_DIR / "unprocessed_pdf"

# ── Shared HTTP session ───────────────────────────────────────────────────────
# One session is reused for all requests (connection pooling, shared headers).
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "BatchPDFProcessor/1.0"})


# =============================================================================
# UTILITY HELPERS
# =============================================================================

def sha256_hash(data: bytes) -> str:
    """Return the SHA-256 hex digest of raw bytes.
    Used to detect whether a file's content has changed when the server
    does not provide an ETag header."""
    return hashlib.sha256(data).hexdigest()


def filename_from_url(url: str) -> str:
    """Derive a safe local filename from a URL's last path segment.
    Example: https://example.com/docs/report.pdf  →  report.pdf
    Strips query strings and replaces unsafe characters with underscores."""
    name = url.rstrip("/").split("/")[-1] or "document.pdf"
    name = name.split("?")[0]               # remove ?query=string
    if not name.lower().endswith(".pdf"):
        name += ".pdf"
    name = re.sub(r"[^\w\-_.]", "_", name)  # keep only safe characters
    return name or "document.pdf"


# =============================================================================
# STEP 1A — SOURCE OPTION 3 (fallback): load URLs from source_pdf/urls.txt
# =============================================================================

def load_urls_from_source_pdf() -> list[str]:
    """Load PDF URLs from source_pdf/urls.txt (one URL per line).
    Lines starting with '#' are treated as comments and ignored.
    If the file does not exist yet it is created with a usage comment."""
    SOURCE_PDF_DIR.mkdir(parents=True, exist_ok=True)
    if not URLS_FILE.exists():
        # First run: create a blank template so the user knows what to put here
        URLS_FILE.write_text(
            "# One PDF URL per line. Lines starting with # are ignored.\n"
            "# Used when source_pdf/config.json has no api_endpoint.\n",
            encoding="utf-8",
        )
    urls = []
    for line in URLS_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            urls.append(line)
    return urls


# =============================================================================
# STEP 1 HELPERS — read config.json to choose the right URL source
# =============================================================================

def load_config() -> dict:
    """Load source_pdf/config.json if it exists.
    Returns an empty dict when the file is missing or malformed.
    Possible keys: source_pdf_base_url, source_pdf_list_url, api_endpoint."""
    if not CONFIG_FILE.exists():
        return {}
    try:
        return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _normalize_base_url(url: str) -> str:
    """Ensure a base URL ends with '/' so urljoin works correctly when
    appending filenames like 'report.pdf'."""
    url = url.strip().rstrip("/")
    return url + "/"


# =============================================================================
# STEP 1A — SOURCE OPTION 1: discover PDFs from a server folder listing
#           (JSON response or HTML directory listing)
# =============================================================================

def _extract_pdf_urls_from_json(data: object, base_url: str) -> list[str]:
    """Walk a JSON response and collect every .pdf URL found.

    Handles three common shapes:
      • Plain list of URL strings:          ["a.pdf", "b.pdf"]
      • List of objects (e.g. GitHub API):  [{"name": "a.pdf", "download_url": "..."}]
      • Object with a known collection key: {"files": [...], "pdfs": [...], ...}

    Relative paths are resolved against base_url."""
    base_normalized = _normalize_base_url(base_url) if base_url else ""
    urls: list[str] = []

    def add(item: str) -> None:
        """Resolve a single filename/URL and append to urls if it ends in .pdf."""
        s = item.strip()
        if not s or not s.lower().endswith(".pdf"):
            return
        if s.startswith(("http://", "https://")):
            urls.append(s)
        elif base_normalized:
            urls.append(urljoin(base_normalized, s.lstrip("/")))

    # Case 1: top-level JSON array
    if isinstance(data, list):
        for item in data:
            if isinstance(item, str):
                add(item)
            elif isinstance(item, dict):
                # GitHub API shape: prefer download_url when present
                download_url = item.get("download_url") if isinstance(item.get("download_url"), str) else None
                if download_url and (item.get("name") or "").lower().endswith(".pdf"):
                    urls.append(download_url)
                    continue
                # Generic object: try common key names
                u = item.get("url") or item.get("name") or item.get("filename") or item.get("file")
                if u and isinstance(u, str):
                    add(u)
        return urls

    # Case 2: top-level JSON object — look inside known collection keys
    if isinstance(data, dict):
        for key in ("files", "pdfs", "urls", "items", "data", "results", "names"):
            arr = data.get(key)
            if isinstance(arr, list):
                for item in arr:
                    if isinstance(item, str):
                        add(item)
                    elif isinstance(item, dict):
                        download_url = item.get("download_url") if isinstance(item.get("download_url"), str) else None
                        if download_url and (item.get("name") or "").lower().endswith(".pdf"):
                            urls.append(download_url)
                        else:
                            u = item.get("url") or item.get("name") or item.get("filename") or item.get("file")
                            if u and isinstance(u, str):
                                add(u)
                if urls:
                    return urls  # stop at the first key that gave results

    return urls


def _extract_pdf_urls_from_html(html: str, base_url: str) -> list[str]:
    """Parse an HTML directory listing page and return all .pdf href links.
    Handles both absolute URLs and relative paths (resolved against base_url)."""
    base_url = _normalize_base_url(base_url)
    pattern = re.compile(r'href\s*=\s*["\']([^"\']+\.pdf)["\']', re.IGNORECASE)
    urls = []
    for match in pattern.finditer(html):
        path = match.group(1).strip()
        if path.startswith(("http://", "https://")):
            urls.append(path)
        else:
            urls.append(urljoin(base_url, path))
    return list(dict.fromkeys(urls))  # deduplicate while preserving order


def fetch_pdf_list_from_server(source_pdf_base_url: str, list_url: str | None = None) -> list[str]:
    """STEP 1A (Option 1) — GET the server's source_pdf folder to get a list of all PDFs.

    Priority:
      1. If list_url is provided, fetch that specific endpoint (e.g. /api/list-pdfs).
      2. Otherwise fetch source_pdf_base_url directly.

    The response is tried as JSON first, then as an HTML directory listing.
    Returns a list of fully-qualified PDF download URLs."""
    base_url = _normalize_base_url(source_pdf_base_url)
    url_to_fetch = (list_url or source_pdf_base_url).strip()

    r = SESSION.get(url_to_fetch, timeout=60)
    r.raise_for_status()
    content_type = (r.headers.get("Content-Type") or "").lower()

    # Try JSON first (Content-Type or .json suffix)
    if "json" in content_type or url_to_fetch.rstrip("/").endswith(".json"):
        try:
            data = r.json()
            return _extract_pdf_urls_from_json(data, base_url)
        except Exception:
            pass

    # Some APIs forget to set Content-Type: application/json — try parsing anyway
    try:
        data = r.json()
        return _extract_pdf_urls_from_json(data, base_url)
    except Exception:
        pass

    # Last resort: treat as HTML directory listing
    return _extract_pdf_urls_from_html(r.text, base_url)


# =============================================================================
# STEP 1A — SOURCE OPTION 2: fetch URL list from a dedicated API endpoint
# =============================================================================

def fetch_urls_from_api(api_endpoint: str) -> list[str]:
    """GET the configured api_endpoint and parse the JSON body for PDF URLs.
    Supports the same JSON shapes as _extract_pdf_urls_from_json.
    No base_url needed when the API returns full absolute URLs."""
    r = SESSION.get(api_endpoint, timeout=30)
    r.raise_for_status()
    data = r.json()
    # Pass empty base_url — _extract will keep full URLs as-is
    return _extract_pdf_urls_from_json(data, "")


# =============================================================================
# STEP 1 — DECIDE WHERE TO GET THE PDF LIST (called first by run_batch)
# =============================================================================

def get_urls_to_process() -> tuple[list[str], str]:
    """Determine the list of PDF URLs to process using the priority chain:

    Priority 1 — source_pdf_base_url in config.json
                  → auto-discovers ALL PDFs in the server folder (no manual list needed)
    Priority 2 — api_endpoint in config.json
                  → calls a custom API that returns a list of PDF URLs
    Priority 3 — source_pdf/urls.txt
                  → plain text file with one URL per line (manual fallback)

    Returns (list_of_urls, human_readable_source_description)."""
    SOURCE_PDF_DIR.mkdir(parents=True, exist_ok=True)
    config = load_config()

    # Priority 1: server folder auto-discovery
    base_url = config.get("source_pdf_base_url")
    if base_url and isinstance(base_url, str):
        list_url = config.get("source_pdf_list_url")
        if isinstance(list_url, str):
            list_url = list_url.strip() or None
        try:
            urls = fetch_pdf_list_from_server(base_url.strip(), list_url)
            if urls:
                return urls, f"server folder ({base_url.strip()})"
        except Exception as e:
            print(f"Server list failed: {e}. Trying api_endpoint or urls.txt.")

    # Priority 2: API endpoint
    api_endpoint = config.get("api_endpoint", "").strip() if isinstance(config.get("api_endpoint"), str) else None
    if api_endpoint:
        try:
            urls = fetch_urls_from_api(api_endpoint)
            if urls:
                return urls, f"API ({api_endpoint})"
        except Exception as e:
            print(f"API request failed: {e}. Falling back to source_pdf/urls.txt.")

    # Priority 3: manual urls.txt
    urls = load_urls_from_source_pdf()
    return urls, "source_pdf/urls.txt"


# =============================================================================
# STEP 2 — STATE MANAGEMENT: load and save download_state.json
# =============================================================================

def load_state() -> dict:
    """Load the state file that remembers the ETag and hash of every
    previously downloaded PDF. Returns empty dict on first run."""
    if not STATE_FILE.exists():
        return {}
    with open(STATE_FILE, encoding="utf-8") as f:
        return json.load(f)


def save_state(state: dict) -> None:
    """Persist the updated state (ETag + hash + local filename) back to
    download_state.json so the next run can skip unchanged files."""
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


# =============================================================================
# STEP 4A — CHECK WHETHER A FILE HAS CHANGED (ETag via HEAD request)
# =============================================================================

def head_etag(url: str) -> str | None:
    """Send a lightweight HEAD request to retrieve the server's ETag header.
    ETag is a fingerprint the server gives each file version.
    Returns None if the server doesn't support ETag or the request fails."""
    try:
        r = SESSION.head(url, timeout=15, allow_redirects=True)
        r.raise_for_status()
        return r.headers.get("ETag", "").strip('"') or None
    except Exception:
        return None


# =============================================================================
# STEP 4B — DOWNLOAD A SINGLE PDF
# =============================================================================

def download_pdf(url: str) -> tuple[bytes, str | None]:
    """Download the PDF at url and return its raw bytes plus the ETag header
    (if the server provides one, else None)."""
    r = SESSION.get(url, timeout=30, allow_redirects=True)
    r.raise_for_status()
    return r.content, r.headers.get("ETag", "").strip('"') or None


# =============================================================================
# STEP 4 — PROCESS ONE URL (called for every URL in the list)
# =============================================================================

def process_url(url: str, state: dict) -> tuple[bool, str]:
    """Decide whether to download the PDF at `url` or skip it, then act.

    Decision logic (STEP 4A):
      • Server has ETag AND we stored the same ETag last time  → SKIP (unchanged)
      • Server has no ETag but we stored a hash               → download silently,
        compare SHA-256; skip if hash matches (unchanged content)
      • File is missing from disk                             → always download
      • New URL (not in state at all)                         → always download

    If downloaded (STEP 4B / 4C):
      • Write to processed_pdf/  (full mirror of everything on the server)
      • Write to unprocessed_pdf/ (only new/changed files — cleared each run)

    STEP 4D: update the state dict entry for this URL with the new ETag/hash.

    Returns (was_downloaded: bool, local_path_or_message: str)."""

    # STEP 4A: quick ETag check before downloading
    etag = head_etag(url)
    entry = state.get(url, {})
    stored_etag = entry.get("etag")
    stored_hash = entry.get("hash")

    name = filename_from_url(url)
    local_file = PROCESSED_DIR.resolve() / name

    # If the file is missing on disk, always re-download regardless of state
    if not local_file.exists():
        pass  # fall through to download below

    # ETag match → content is identical → skip
    elif etag and stored_etag and etag == stored_etag:
        return False, str(local_file)

    # No ETag from server → compare by downloading and hashing
    elif not etag and stored_hash:
        try:
            content, _ = download_pdf(url)
            new_hash = sha256_hash(content)
            if new_hash == stored_hash and local_file.exists():
                return False, str(local_file)   # hash unchanged → skip
        except Exception as e:
            return False, f"skip (hash check failed): {e}"

    # STEP 4B: download (new file, changed file, or file missing from disk)
    try:
        content, response_etag = download_pdf(url)
    except requests.RequestException as e:
        return False, f"error: {e}"

    file_hash = sha256_hash(content)

    # STEP 4C: write to both output folders
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    UNPROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    local_file.write_bytes(content)                 # full mirror
    (UNPROCESSED_DIR / name).write_bytes(content)   # only this run's new/changed

    # STEP 4D: update state so next run can compare against this version
    state[url] = {
        "etag": response_etag or stored_etag,
        "hash": file_hash,
        "path": name,
    }
    return True, str(local_file)


# =============================================================================
# MAIN ORCHESTRATOR — run_batch ties all steps together
# =============================================================================

def run_batch() -> None:
    """Entry point for a normal batch run.

    Execution order:
      STEP 1 — get_urls_to_process()  : decide URL source and fetch the list
      STEP 2 — load_state()           : load previous run's ETag/hash records
      STEP 3 — clear unprocessed_pdf/ : start fresh so only THIS run's files appear
      STEP 4 — loop over every URL    : process_url() decides skip or download
      STEP 5 — save_state()           : persist updated records to disk
      STEP 6 — print summary          : how many downloaded vs skipped
    """

    # STEP 1: determine which URLs to process
    urls, source = get_urls_to_process()
    if not urls:
        print("No PDF URLs to process. Set source_pdf/config.json api_endpoint or add URLs to source_pdf/urls.txt.")
        return

    # STEP 2: load what was downloaded in previous runs
    state = load_state()
    downloaded = []
    skipped = []

    # STEP 3: ensure folders exist; clear unprocessed_pdf so it only holds new/changed PDFs from THIS run
    DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    UNPROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    for f in UNPROCESSED_DIR.iterdir():
        if f.is_file():
            f.unlink()  # delete leftover files from the previous run

    print(f"Source: {source}")
    print(f"PDF(s) to process: {len(urls)}")
    print(f"Processed (all):   download_pdf/processed_pdf/")
    print(f"Unprocessed (new/changed only): download_pdf/unprocessed_pdf/\n")

    # STEP 4: process each URL — skip unchanged, download new/changed
    for url in urls:
        name = filename_from_url(url)
        was_downloaded, path_or_msg = process_url(url, state)
        if was_downloaded:
            downloaded.append((name, path_or_msg))
            print(f"  {name}  ->  downloaded")
        else:
            skipped.append((name, path_or_msg))
            print(f"  {name}  ->  unchanged (skipped)")

    # STEP 5: save updated state (new ETags / hashes) so next run can compare
    save_state(state)

    # STEP 6: summary
    print("\nBatch processing complete.")
    print(f"  Downloaded: {len(downloaded)}  |  Unchanged: {len(skipped)}")


# =============================================================================
# OPTIONAL: --verify mode — just check whether each URL is reachable
# =============================================================================

def verify_urls() -> None:
    """Run through the URL list and send a HEAD request to each one.
    Prints OK / FAIL per URL and a total count. Does NOT download anything."""
    urls, source = get_urls_to_process()
    if not urls:
        print("No URLs to verify. Set source_pdf/config.json api_endpoint or add URLs to source_pdf/urls.txt.")
        return
    print(f"Verifying {len(urls)} URL(s) from {source}:\n")
    ok = 0
    for url in urls:
        name = filename_from_url(url)
        try:
            r = SESSION.head(url, timeout=15, allow_redirects=True)
            if r.status_code == 200:
                size = r.headers.get("Content-Length", "?")
                print(f"  OK    {name}  ({size} bytes)")
                ok += 1
            else:
                print(f"  FAIL  {name}  (HTTP {r.status_code})")
        except Exception as e:
            print(f"  FAIL  {name}  ({e})")
    print(f"\n{ok}/{len(urls)} URL(s) reachable.")


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    import sys
    # Pass --verify to only check reachability without downloading anything
    if len(sys.argv) > 1 and sys.argv[1] == "--verify":
        verify_urls()
    else:
        run_batch()
