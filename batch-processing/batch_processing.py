"""
Batch download PDFs from a test server. Only re-downloads files when their content
has changed (using ETag from server, then SHA-256 hash comparison).
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import requests

BASE_DIR = Path(__file__).resolve().parent
# source_pdf: list/config (urls.txt, config.json). Commit this folder to GitHub.
SOURCE_PDF_DIR = BASE_DIR / "source_pdf"
URLS_FILE = SOURCE_PDF_DIR / "urls.txt"
CONFIG_FILE = SOURCE_PDF_DIR / "config.json"  # Optional: { "api_endpoint": "https://..." }

STATE_FILE = BASE_DIR / "download_state.json"
# download_pdf: PDFs are downloaded here (from URLs in source_pdf or from API).
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


def fetch_urls_from_api(api_endpoint: str) -> list[str]:
    """
    GET the API endpoint and parse JSON to extract a list of PDF URLs.
    Supports: array of URLs, array of objects with 'url'/'link'/'href', or object with key 'files'/'pdfs'/'urls'/'items'/'data'.
    """
    r = SESSION.get(api_endpoint, timeout=30)
    r.raise_for_status()
    data = r.json()

    # Direct array of strings (URLs)
    if isinstance(data, list):
        urls = []
        for item in data:
            if isinstance(item, str) and item.startswith(("http://", "https://")):
                urls.append(item)
            elif isinstance(item, dict):
                u = item.get("url") or item.get("link") or item.get("href")
                if u and isinstance(u, str):
                    urls.append(u)
        return urls

    # Object: look for common keys that hold the list
    if isinstance(data, dict):
        for key in ("files", "pdfs", "urls", "items", "data", "results"):
            arr = data.get(key)
            if isinstance(arr, list):
                urls = []
                for item in arr:
                    if isinstance(item, str) and item.startswith(("http://", "https://")):
                        urls.append(item)
                    elif isinstance(item, dict):
                        u = item.get("url") or item.get("link") or item.get("href") or item.get("file_url")
                        if u and isinstance(u, str):
                            urls.append(u)
                if urls:
                    return urls

    return []


def get_urls_to_process() -> tuple[list[str], str]:
    """
    Get list of PDF URLs: from API if config has api_endpoint, else from source_pdf/urls.txt.
    Returns (urls, source_description).
    """
    SOURCE_PDF_DIR.mkdir(parents=True, exist_ok=True)
    config = load_config()
    api_endpoint = config.get("api_endpoint", "").strip() if isinstance(config.get("api_endpoint"), str) else None

    if api_endpoint:
        try:
            urls = fetch_urls_from_api(api_endpoint)
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
