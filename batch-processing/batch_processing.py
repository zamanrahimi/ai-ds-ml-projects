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

try:
    import requests
except ModuleNotFoundError:
    print("Missing dependency: requests. Install with:", file=sys.stderr)
    print("  pip install -r requirements.txt", file=sys.stderr)
    print("Or: pip install requests", file=sys.stderr)
    sys.exit(1)

BASE_DIR = Path(__file__).resolve().parent
SOURCE_PDF_DIR = BASE_DIR / "source_pdf"
URLS_FILE = SOURCE_PDF_DIR / "urls.txt"
CONFIG_FILE = SOURCE_PDF_DIR / "config.json"

STATE_FILE = BASE_DIR / "download_state.json"
DOWNLOAD_DIR = BASE_DIR / "download_pdf"

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "BatchPDFProcessor/1.0"})


def sha256_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def filename_from_url(url: str) -> str:
    """Derive a safe local filename from URL (last path segment)."""
    name = url.rstrip("/").split("/")[-1] or "document.pdf"
    # remove query string if any
    name = name.split("?")[0]
    if not name.lower().endswith(".pdf"):
        name += ".pdf"
    # sanitize
    name = re.sub(r"[^\w\-_.]", "_", name)
    return name or "document.pdf"


def load_urls_from_source_pdf() -> list[str]:
    """Load PDF URLs from source_pdf/urls.txt (one URL per line). Fallback when no API is configured."""
    SOURCE_PDF_DIR.mkdir(parents=True, exist_ok=True)
    if not URLS_FILE.exists():
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


def load_config() -> dict:
    """Load source_pdf/config.json if present."""
    if not CONFIG_FILE.exists():
        return {}
    try:
        return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _normalize_base_url(url: str) -> str:
    """Ensure base URL ends with / for joining filenames."""
    url = url.strip().rstrip("/")
    return url + "/"


def _extract_pdf_urls_from_json(data: object, base_url: str) -> list[str]:
    """From JSON response, extract list of PDF URLs (full URLs or filenames)."""
    base_normalized = _normalize_base_url(base_url) if base_url else ""
    urls: list[str] = []

    def add(item: str) -> None:
        s = item.strip()
        if not s or not s.lower().endswith(".pdf"):
            return
        if s.startswith(("http://", "https://")):
            urls.append(s)
        elif base_normalized:
            urls.append(urljoin(base_normalized, s.lstrip("/")))

    if isinstance(data, list):
        for item in data:
            if isinstance(item, str):
                add(item)
            elif isinstance(item, dict):
                # GitHub API: { "name": "file.pdf", "download_url": "https://...", "type": "file" }
                download_url = item.get("download_url") if isinstance(item.get("download_url"), str) else None
                if download_url and (item.get("name") or "").lower().endswith(".pdf"):
                    urls.append(download_url)
                    continue
                u = item.get("url") or item.get("name") or item.get("filename") or item.get("file")
                if u and isinstance(u, str):
                    add(u)
        return urls

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
                    return urls

    return urls


def _extract_pdf_urls_from_html(html: str, base_url: str) -> list[str]:
    """Parse HTML directory listing for links to .pdf files."""
    base_url = _normalize_base_url(base_url)
    # Match href="...something.pdf" or href='...something.pdf'
    pattern = re.compile(r'href\s*=\s*["\']([^"\']+\.pdf)["\']', re.IGNORECASE)
    urls = []
    for match in pattern.finditer(html):
        path = match.group(1).strip()
        if path.startswith(("http://", "https://")):
            urls.append(path)
        else:
            urls.append(urljoin(base_url, path))
    return list(dict.fromkeys(urls))  # dedupe


def fetch_pdf_list_from_server(source_pdf_base_url: str, list_url: str | None = None) -> list[str]:
    """
    Discover all PDFs in the server's source_pdf folder.
    - If list_url is set: GET that URL (JSON or HTML). Expects list of filenames or full URLs.
    - Else: GET source_pdf_base_url and parse as JSON or HTML directory listing.
    Returns list of full PDF URLs.
    """
    base_url = _normalize_base_url(source_pdf_base_url)
    url_to_fetch = (list_url or source_pdf_base_url).strip()

    r = SESSION.get(url_to_fetch, timeout=60)
    r.raise_for_status()
    content_type = (r.headers.get("Content-Type") or "").lower()

    # Try JSON first
    if "json" in content_type or url_to_fetch.rstrip("/").endswith(".json"):
        try:
            data = r.json()
            return _extract_pdf_urls_from_json(data, base_url)
        except Exception:
            pass

    # Try parsing as JSON anyway (some APIs don't set Content-Type)
    try:
        data = r.json()
        return _extract_pdf_urls_from_json(data, base_url)
    except Exception:
        pass

    # Parse as HTML (directory listing)
    text = r.text
    return _extract_pdf_urls_from_html(text, base_url)


def fetch_urls_from_api(api_endpoint: str) -> list[str]:
    """
    GET the API endpoint and parse JSON to extract a list of PDF URLs.
    Supports: array of URLs, array of objects with 'url'/'link'/'href', or object with key 'files'/'pdfs'/'urls'/'items'/'data'.
    """
    r = SESSION.get(api_endpoint, timeout=30)
    r.raise_for_status()
    data = r.json()
    # If API returns full URLs we don't have a base; use empty base and _extract will keep full URLs
    return _extract_pdf_urls_from_json(data, "")


def get_urls_to_process() -> tuple[list[str], str]:
    """
    Get list of PDF URLs:
    1. If config has source_pdf_base_url: list all PDFs from that folder on the server (no urls.txt).
    2. Else if config has api_endpoint: GET API for list of URLs.
    3. Else: read source_pdf/urls.txt (manual list).
    Returns (urls, source_description).
    """
    SOURCE_PDF_DIR.mkdir(parents=True, exist_ok=True)
    config = load_config()

    # Prefer: discover every PDF in server's source_pdf folder
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

    # Fallback: API that returns list of PDF URLs
    api_endpoint = config.get("api_endpoint", "").strip() if isinstance(config.get("api_endpoint"), str) else None
    if api_endpoint:
        try:
            urls = fetch_urls_from_api(api_endpoint)
            if urls:
                return urls, f"API ({api_endpoint})"
        except Exception as e:
            print(f"API request failed: {e}. Falling back to source_pdf/urls.txt.")

    urls = load_urls_from_source_pdf()
    return urls, "source_pdf/urls.txt"


def load_state() -> dict:
    if not STATE_FILE.exists():
        return {}
    with open(STATE_FILE, encoding="utf-8") as f:
        return json.load(f)


def save_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def head_etag(url: str) -> str | None:
    """Get ETag for URL via HEAD request. Returns None if not present or on error."""
    try:
        r = SESSION.head(url, timeout=15, allow_redirects=True)
        r.raise_for_status()
        return r.headers.get("ETag", "").strip('"') or None
    except Exception:
        return None


def download_pdf(url: str) -> tuple[bytes, str | None]:
    """Download PDF; returns (content, etag)."""
    r = SESSION.get(url, timeout=30, allow_redirects=True)
    r.raise_for_status()
    return r.content, r.headers.get("ETag", "").strip('"') or None


def process_url(url: str, state: dict) -> tuple[bool, str]:
    """
    Process one URL: skip if unchanged (same ETag/hash), else download.
    Returns (was_downloaded, local_path_or_message).
    """
    etag = head_etag(url)
    entry = state.get(url, {})
    stored_etag = entry.get("etag")
    stored_hash = entry.get("hash")
    local_path = entry.get("path")

    # Resolve local file path once (always use name from URL so state path can't point to wrong file)
    name = filename_from_url(url)
    local_file = DOWNLOAD_DIR.resolve() / name

    # If the file is missing on disk, always re-download (do not skip)
    if not local_file.exists():
        pass  # fall through to download below
    # Skip only if content unchanged AND the file actually exists on disk
    elif etag and stored_etag and etag == stored_etag:
        return False, str(local_file)
    elif not etag and stored_hash:
        # Server doesn't send ETag: we must download to compare hash (still only overwrite if changed)
        try:
            content, _ = download_pdf(url)
            new_hash = sha256_hash(content)
            if new_hash == stored_hash and local_file.exists():
                return False, str(local_file)
        except Exception as e:
            return False, f"skip (hash check failed): {e}"

    # Download (new or changed or file missing)
    try:
        content, response_etag = download_pdf(url)
    except requests.RequestException as e:
        return False, f"error: {e}"

    file_hash = sha256_hash(content)
    DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)
    path = local_file
    path.write_bytes(content)

    state[url] = {
        "etag": response_etag or stored_etag,
        "hash": file_hash,
        "path": name,
    }
    return True, str(path)


def run_batch() -> None:
    urls, source = get_urls_to_process()
    if not urls:
        print("No PDF URLs to process. Set source_pdf/config.json api_endpoint or add URLs to source_pdf/urls.txt.")
        return

    state = load_state()
    downloaded = []
    skipped = []

    DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Source: {source}")
    print(f"PDF(s) to process: {len(urls)}")
    print(f"Download folder: download_pdf/ ({DOWNLOAD_DIR.resolve()})\n")
    for url in urls:
        name = filename_from_url(url)
        was_downloaded, path_or_msg = process_url(url, state)
        if was_downloaded:
            downloaded.append((name, path_or_msg))
            print(f"  {name}  ->  downloaded")
        else:
            skipped.append((name, path_or_msg))
            print(f"  {name}  ->  unchanged (skipped)")

    save_state(state)

    print("\nBatch processing complete.")
    print(f"  Downloaded: {len(downloaded)}  |  Unchanged: {len(skipped)}")


def verify_urls() -> None:
    """Check that each URL (from API or pdfs/urls.txt) exists (HEAD request)."""
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


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--verify":
        verify_urls()
    else:
        run_batch()
