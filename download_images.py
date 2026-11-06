#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
download_images.py
==================

Make a Markdown-based repository fully offline with respect to its images.

The tool walks a repository recursively, finds every Markdown file, extracts
the images that are hosted on the internet, downloads them into an ``images/``
folder that sits **next to** the Markdown file using them, and finally rewrites
only the image destinations so that they point to the local copies.

Nothing else in the Markdown files is touched: alt texts, headings, code
blocks, prose, ordinary (non-image) links and the order of the images are
preserved.

Typical usage
-------------

    python3 download_images.py /path/to/Portswigger_labs
    python3 download_images.py /path/to/Portswigger_labs --dry-run
    python3 download_images.py /path/to/Portswigger_labs --check

Safety
------

* every download is validated (HTTP status + real image magic bytes, never HTML),
* Markdown files are written atomically (temp file + fsync + os.replace),
* originals are backed up before the first modification,
* interrupted or repeated runs are safe: images that are already local are left
  alone and images already on disk are not downloaded again,
* a JSON report with the failure list is produced.

Supported image syntax
----------------------

* ``![alt](https://host/path)`` and ``![alt](<https://host/a b.png>)``
* ``<img src="https://host/path" />`` (event-handler tags are treated as
  exploit payloads and never touched)
* reference style: ``![alt][ref]``, ``![ref][]``, ``![ref]`` + ``[ref]: url``

Regions that are never modified: fenced/indented code blocks, inline code
spans, HTML comments, YAML front matter and ordinary links.

Requires: Python 3.8+ and the ``requests`` library.
"""

from __future__ import annotations

import argparse
import bisect
import concurrent.futures
import dataclasses
import hashlib
import json
import os
import posixpath
import random
import re
import shutil
import sys
import tempfile
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Sequence, Set, Tuple

try:
    import requests
except ImportError:  # pragma: no cover - handled at startup
    sys.stderr.write(
        "ERROR: the 'requests' package is required.\n"
        "  pip3 install requests        (or: apt install python3-requests)\n"
    )
    raise SystemExit(3)


__version__ = "1.0.0"

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

MARKDOWN_SUFFIXES = {".md", ".markdown", ".mdown", ".mkd", ".mdwn"}

DEFAULT_EXCLUDED_DIRS = {
    ".git", ".hg", ".svn", ".bzr", "CVS",
    "node_modules", "bower_components",
    ".venv", "venv", "env", "virtualenv",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox",
    ".idea", ".vscode", ".vs",
    "site-packages", "dist", "build", ".next", ".nuxt", ".cache",
}

STATE_DIR_NAME = ".image_tool"
DEFAULT_IMAGES_DIR = "images"
DEFAULT_WORKERS = 8
MAX_WORKERS = 32
DEFAULT_TIMEOUT = 30.0
DEFAULT_RETRIES = 3
DEFAULT_MAX_SIZE = 32 * 1024 * 1024  # 32 MiB
MAX_ERROR_LENGTH = 400

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36 download_images/" + __version__
)

HTTP_RETRY_STATUS = {408, 425, 429, 500, 502, 503, 504, 522, 524}

# <img> tags that carry event handlers are exploit payloads (XSS/CSRF PoCs),
# not screenshots: they must never be downloaded or rewritten.
HTML_IMG_RE = re.compile(r"<img\b[^>]*>", re.IGNORECASE | re.DOTALL)
HTML_ATTR_RE = re.compile(
    r"""([A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*("[^"]*"|'[^']*'|[^\s"'=<>`]+)"""
)

REF_DEF_RE = re.compile(
    r"""^[ \t]{0,3}\[([^\[\]\n]+)\]:[ \t]*(?:<([^<>]*?)>|(\S+?))"""
    r"""(?:[ \t]+(?:"[^"]*"|'[^']*'|\([^)]*\)))?[ \t]*$""",
    re.MULTILINE,
)

FENCE_RE = re.compile(r"^(?P<indent>[ ]{0,3})(?P<fence>`{3,}|~{3,})(?P<info>.*)$")
INDENTED_CODE_RE = re.compile(r"^(?: {4,}|\t)")

IMAGE_NAME_RE = re.compile(r"^image-(\d+)\.([A-Za-z0-9]+)$")
SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*):")

PENDING = "pending"
DOWNLOADED = "downloaded"
EXISTING = "existing"
WOULD_DOWNLOAD = "would_download"
FAILED = "failed"

REWRITABLE = (DOWNLOADED, EXISTING, WOULD_DOWNLOAD)


# --------------------------------------------------------------------------- #
# Console helpers
# --------------------------------------------------------------------------- #


def _emit(stream, *args: object) -> None:
    msg = " ".join(str(a) for a in args)
    encoding = getattr(stream, "encoding", None) or "utf-8"
    try:
        stream.write(msg + "\n")
    except UnicodeEncodeError:
        stream.write(msg.encode(encoding, "replace").decode(encoding, "replace") + "\n")
    except ValueError:  # stream already closed
        return
    try:
        stream.flush()
    except (ValueError, OSError):
        pass


def say(*args: object) -> None:
    _emit(sys.stdout, *args)


def eprint(*args: object) -> None:
    _emit(sys.stderr, *args)


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def describe_error(exc: BaseException) -> str:
    """Readable one-line description of a network/library exception."""
    name = type(exc).__name__
    text = str(exc)
    text = re.sub(
        r"^HTTPS?ConnectionPool\(host='[^']*', port=\d+\): Max retries exceeded with url: \S+ "
        r"\(Caused by ", "", text)
    while text.endswith(")") and text.count(")") > text.count("("):
        text = text[:-1].rstrip()
    text = " ".join(text.split())
    if name.lower() in text.lower():
        return shorten(text, 240)
    return shorten(f"{name}: {text}", 240)


def shorten(text: str, limit: int = MAX_ERROR_LENGTH) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


# --------------------------------------------------------------------------- #
# General helpers
# --------------------------------------------------------------------------- #


def norm_label(label: str) -> str:
    """Normalise a Markdown reference label (case/whitespace insensitive)."""
    return re.sub(r"\s+", " ", label.strip()).casefold()


def is_http_url(url: str) -> bool:
    try:
        scheme = urllib.parse.urlsplit(url.strip()).scheme.lower()
    except ValueError:
        return False
    return scheme in ("http", "https")


def url_key(url: str) -> str:
    """Normalised cache key for a remote URL (the fragment is dropped)."""
    raw = url.strip()
    try:
        parts = urllib.parse.urlsplit(raw)
    except ValueError:
        return raw
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))


def atomic_write_bytes(path: Path, data: bytes, like: Optional[Path] = None) -> None:
    """Write ``data`` to ``path`` atomically (temporary file in the same folder)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix="." + path.name + ".", suffix=".tmp", dir=str(path.parent)
    )
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        mode_source = like if (like and like.exists()) else (path if path.exists() else None)
        if mode_source is not None:
            try:
                shutil.copymode(str(mode_source), tmp_name)
            except OSError:
                pass
        os.replace(tmp_name, str(path))
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    try:  # make the rename durable
        dir_fd = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError:
        pass


def copy_atomic(src: Path, dst: Path) -> None:
    with open(src, "rb") as handle:
        data = handle.read()
    atomic_write_bytes(dst, data)


def rel_posix(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


# --------------------------------------------------------------------------- #
# Image sniffing / validation
# --------------------------------------------------------------------------- #


def looks_like_html(data: bytes) -> bool:
    head = data[:2048].lstrip().lower()
    if b"<html" in head or b"<body" in head or head.startswith(b"<!doctype html"):
        return True
    if head.startswith(b"<?xml") and b"<svg" not in data[:4096].lower():
        return True
    return False


def looks_like_svg(data: bytes) -> bool:
    head = data[:4096].lower()
    return b"<svg" in head and b"<html" not in head


def sniff_image(data: bytes) -> Optional[Tuple[str, str]]:
    """Return ``(extension, format)`` when ``data`` starts with a known image signature."""
    if not data:
        return None
    head = data[:4096]
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png", "png"
    if head.startswith(b"\xff\xd8\xff"):
        return "jpg", "jpeg"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "gif", "gif"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "webp", "webp"
    if head[:2] == b"BM" and len(head) > 14:
        return "bmp", "bmp"
    if head[:4] in (b"II*\x00", b"MM\x00*"):
        return "tiff", "tiff"
    if head[:4] == b"\x00\x00\x01\x00":
        return "ico", "ico"
    if head[4:8] == b"ftyp":
        brand = head[8:12]
        if brand in (b"avif", b"avis"):
            return "avif", "avif"
        if brand in (b"heic", b"heix", b"mif1", b"msf1", b"hevc"):
            return "heic", "heif"
    if looks_like_svg(head):
        return "svg", "svg"
    return None


def extension_from_url(url: str) -> Optional[str]:
    """Best-effort extension guess from the URL path (used only for --dry-run)."""
    path = urllib.parse.urlsplit(url).path
    ext = posixpath.splitext(path)[1].lower().lstrip(".")
    if ext in {"png", "jpg", "jpeg", "gif", "webp", "bmp", "tif", "tiff", "ico", "svg", "avif", "heic"}:
        return "jpg" if ext == "jpeg" else ("tiff" if ext == "tif" else ext)
    return None


# --------------------------------------------------------------------------- #
# Markdown: protected regions (code, comments, front matter)
# --------------------------------------------------------------------------- #


def _inline_code_spans(text: str) -> List[Tuple[int, int]]:
    spans: List[Tuple[int, int]] = []
    i, n = 0, len(text)
    while i < n:
        if text[i] != "`":
            i += 1
            continue
        run_start = i
        while i < n and text[i] == "`":
            i += 1
        run = i - run_start
        search = i
        close = -1
        while search < n:
            if text[search] == "`":
                marker = search
                while search < n and text[search] == "`":
                    search += 1
                if search - marker == run:
                    close = marker
                    break
            else:
                search += 1
        if close < 0:
            continue
        spans.append((run_start, close + run))
        i = close + run
    return spans


def compute_code_ranges(text: str) -> List[Tuple[int, int]]:
    """Offsets of regions that must never be modified (code, comments, front matter)."""
    ranges: List[Tuple[int, int]] = []
    lines = text.splitlines(keepends=True)
    offsets: List[int] = []
    pos = 0
    for line in lines:
        offsets.append(pos)
        pos += len(line)

    if not lines:
        return ranges

    # YAML front matter
    if lines[0].strip() == "---":
        for index in range(1, len(lines)):
            if lines[index].strip() in ("---", "..."):
                ranges.append((0, min(offsets[index] + len(lines[index]), len(text))))
                break

    in_fence = False
    fence_char = ""
    fence_len = 0
    fence_start = 0
    in_indented = False
    prev_blank = True

    for index, line in enumerate(lines):
        stripped = line.rstrip("\r\n")

        if in_fence:
            match = FENCE_RE.match(stripped)
            if (
                match
                and match.group("fence")[0] == fence_char
                and len(match.group("fence")) >= fence_len
                and match.group("info").strip() == ""
            ):
                ranges.append((fence_start, min(offsets[index] + len(line), len(text))))
                in_fence = False
            prev_blank = False
            continue

        match = FENCE_RE.match(stripped)
        if match and not (match.group("fence")[0] == "`" and "`" in match.group("info")):
            in_fence = True
            fence_char = match.group("fence")[0]
            fence_len = len(match.group("fence"))
            fence_start = offsets[index]
            in_indented = False
            prev_blank = False
            continue

        if stripped.strip() == "":
            if in_indented:
                ranges.append((offsets[index], offsets[index] + len(line)))
            prev_blank = True
            continue

        if INDENTED_CODE_RE.match(line):
            if in_indented or prev_blank:
                in_indented = True
                ranges.append((offsets[index], offsets[index] + len(line)))
            prev_blank = False
            continue

        in_indented = False
        prev_blank = False

    if in_fence:  # unterminated fence: the rest of the file is code
        ranges.append((fence_start, len(text)))

    for match in re.finditer(r"<!--.*?-->", text, re.DOTALL):
        ranges.append((match.start(), match.end()))

    merged = _merge_ranges(ranges)
    for span in _inline_code_spans(text):
        if not _in_ranges(span[0], merged):
            ranges.append(span)
            merged = _merge_ranges(ranges)
    return _merge_ranges(ranges)


def _merge_ranges(ranges: Sequence[Tuple[int, int]]) -> List[Tuple[int, int]]:
    merged: List[Tuple[int, int]] = []
    for start, end in sorted(ranges):
        if end <= start:
            continue
        if merged and start <= merged[-1][1]:
            if end > merged[-1][1]:
                merged[-1] = (merged[-1][0], end)
        else:
            merged.append((start, end))
    return merged


def _in_ranges(offset: int, ranges: Sequence[Tuple[int, int]]) -> bool:
    if not ranges:
        return False
    starts = [item[0] for item in ranges]
    index = bisect.bisect_right(starts, offset) - 1
    if index < 0:
        return False
    return ranges[index][0] <= offset < ranges[index][1]


# --------------------------------------------------------------------------- #
# Markdown: image syntax scanners
# --------------------------------------------------------------------------- #


@dataclasses.dataclass
class RawImage:
    alt: str
    style: str  # inline | ref | shortcut | html
    start: int
    end: int
    url: Optional[str] = None
    span: Optional[Tuple[int, int]] = None
    label: Optional[str] = None
    label_span: Optional[Tuple[int, int]] = None


def _parse_inline_destination(text: str, open_paren: int) -> Optional[Tuple[str, int, int, int]]:
    """Parse ``(dest "title")`` starting at ``open_paren``.

    Returns ``(destination, dest_start, dest_end, end_offset)`` or ``None``.
    Handles ``<...>`` destinations, balanced parentheses, titles and line breaks
    inside the parentheses.
    """
    n = len(text)
    p = open_paren + 1
    while p < n and text[p] in " \t":
        p += 1
    if p < n and text[p] == "\n":
        p += 1
        while p < n and text[p] in " \t":
            p += 1

    if p < n and text[p] == "<":
        close = text.find(">", p + 1)
        if close < 0 or "\n" in text[p + 1:close]:
            return None
        dest = text[p + 1:close]
        dest_start, dest_end = p + 1, close
        p = close + 1
    else:
        dest_start = p
        depth = 0
        while p < n:
            char = text[p]
            if char == "\\":
                p += 2
                continue
            if char == "(":
                depth += 1
            elif char == ")":
                if depth == 0:
                    break
                depth -= 1
            elif char in " \t\r\n":
                break
            p += 1
        dest_end = min(p, n)
        dest = text[dest_start:dest_end]

    q = p
    while q < n and text[q] in " \t\r\n":
        q += 1
    if q < n and text[q] in "\"'(":
        closer = {'"': '"', "'": "'", "(": ")"}[text[q]]
        end_quote = text.find(closer, q + 1)
        if end_quote < 0:
            return None
        q = end_quote + 1
        while q < n and text[q] in " \t\r\n":
            q += 1

    if q >= n or text[q] != ")":
        return None
    return dest, dest_start, dest_end, q + 1


def scan_markdown_images(text: str) -> List[RawImage]:
    """Find ``![alt](url)``, ``![alt][ref]``, ``![alt][]`` and ``![ref]`` images."""
    found: List[RawImage] = []
    n = len(text)
    i = 0
    while i < n - 1:
        start = text.find("![", i)
        if start < 0:
            break
        if start > 0 and text[start - 1] == "\\":
            i = start + 2
            continue

        p = start + 2
        depth = 1
        while p < n:
            char = text[p]
            if char == "\\":
                p += 2
                continue
            if char == "[":
                depth += 1
            elif char == "]":
                depth -= 1
                if depth == 0:
                    break
            p += 1
        if p >= n:
            break
        alt = text[start + 2:p]
        after = p + 1

        if after < n and text[after] == "(":
            parsed = _parse_inline_destination(text, after)
            if parsed is None:
                i = after
                continue
            url, span_start, span_end, end = parsed
            found.append(
                RawImage(alt=alt, style="inline", start=start, end=end, url=url,
                         span=(span_start, span_end))
            )
            i = end
            continue

        if after < n and text[after] == "[":
            close = text.find("]", after + 1)
            if close < 0:
                i = after
                continue
            label = text[after + 1:close]
            if close - (after + 1) > 200:
                i = close + 1
                continue
            found.append(
                RawImage(alt=alt, style="ref", start=start, end=close + 1,
                         label=label if label.strip() else alt,
                         label_span=(after + 1, close))
            )
            i = close + 1
            continue

        if alt.strip() and len(alt) <= 200:
            found.append(
                RawImage(alt=alt, style="shortcut", start=start, end=after,
                         label=alt, label_span=(start + 2, p))
            )
        i = after
    return found


def scan_html_images(text: str) -> List[RawImage]:
    """Find ``<img src="...">`` tags, skipping exploit payloads with event handlers."""
    found: List[RawImage] = []
    for match in HTML_IMG_RE.finditer(text):
        tag = match.group(0)
        attrs = {item.group(1).lower(): item for item in HTML_ATTR_RE.finditer(tag)}
        if any(name in attrs for name in ("onerror", "onload", "onclick", "onmouseover")):
            continue  # XSS / CSRF payload, not a screenshot
        src = attrs.get("src")
        if not src:
            continue
        raw_value = src.group(2)
        value_start = match.start() + src.start(2)
        if raw_value[:1] in ("'", '"'):
            span = (value_start + 1, value_start + len(raw_value) - 1)
            value = raw_value[1:-1]
        else:
            span = (value_start, value_start + len(raw_value))
            value = raw_value
        if not value.strip():
            continue
        if "&amp;" in value:
            value = value.replace("&amp;", "&")
        found.append(
            RawImage(alt="", style="html", start=match.start(), end=match.end(),
                     url=value, span=span)
        )
    return found


def scan_reference_definitions(
    text: str, blocked: Sequence[Tuple[int, int]]
) -> Dict[str, Tuple[str, Tuple[int, int], int]]:
    """Map normalised label -> (url, url span, end-of-line offset)."""
    defs: Dict[str, Tuple[str, Tuple[int, int], int]] = {}
    for match in REF_DEF_RE.finditer(text):
        if _in_ranges(match.start(), blocked):
            continue  # definition inside code: not a real definition
        if match.group(2) is not None:
            url = match.group(2)
            span = (match.start(2), match.end(2))
        else:
            url = match.group(3)
            span = (match.start(3), match.end(3))
        line_end = text.find("\n", match.end())
        if line_end < 0:
            line_end = len(text)
        defs.setdefault(norm_label(match.group(1)), (url, span, line_end))
    return defs


def label_used_by_links(
    text: str, label: str, image_spans: Sequence[Tuple[int, int]]
) -> bool:
    """True when a reference label is (also) used by an ordinary, non-image link.

    Brackets that belong to an image construct (``![alt][label]``) are ignored,
    otherwise an image would look like a link that shares its own definition.
    """
    wanted = norm_label(label)
    for match in re.finditer(r"\[([^\[\]\n]*)\]", text):
        if match.start() > 0 and text[match.start() - 1] == "!":
            continue  # the alt text of an image
        if any(start <= match.start() < end for start, end in image_spans):
            continue  # the second bracket of an image
        if norm_label(match.group(1)) != wanted:
            continue
        line_start = text.rfind("\n", 0, match.start()) + 1
        prefix = text[line_start:match.start()]
        following = text[match.end():match.end() + 1]
        if following == ":" and prefix.strip() == "":
            continue  # the definition itself
        return True
    return False


class LineIndex:
    """Offset -> line number lookup."""

    def __init__(self, text: str) -> None:
        self._newlines = [index for index, char in enumerate(text) if char == "\n"]

    def line(self, offset: int) -> int:
        return bisect.bisect_right(self._newlines, offset) + 1


# --------------------------------------------------------------------------- #
# Markdown documents
# --------------------------------------------------------------------------- #


@dataclasses.dataclass
class DocImage:
    url: str
    style: str  # inline | html | ref-def | ref-def-new
    alt: str
    line: int
    span: Optional[Tuple[int, int]] = None
    label: Optional[str] = None
    label_span: Optional[Tuple[int, int]] = None
    alt_span: Optional[Tuple[int, int]] = None
    insert_at: Optional[int] = None


@dataclasses.dataclass
class Document:
    path: Path
    rel: str
    text: str
    newline: str
    bom: bool
    images: List[DocImage] = dataclasses.field(default_factory=list)
    stats: Dict[str, int] = dataclasses.field(default_factory=dict)


def decode_markdown(raw: bytes) -> Tuple[str, str, bool]:
    """Return ``(text, newline, had_bom)`` keeping the original line endings."""
    bom = raw.startswith(b"\xef\xbb\xbf")
    if bom:
        raw = raw[3:]
    text = raw.decode("utf-8")
    crlf = text.count("\r\n")
    lone_lf = text.count("\n") - crlf
    return text, ("\r\n" if crlf > lone_lf else "\n"), bom


def parse_document(path: Path, rel: str) -> Document:
    raw = path.read_bytes()
    text, newline, bom = decode_markdown(raw)
    doc = Document(path=path, rel=rel, text=text, newline=newline, bom=bom)
    doc.stats = {
        "discovered": 0,
        "skipped_code": 0,
        "unresolved_refs": 0,
        "non_http": 0,
    }
    blocked = compute_code_ranges(text)
    lines = LineIndex(text)
    definitions = scan_reference_definitions(text, blocked)

    candidates = scan_markdown_images(text) + scan_html_images(text)
    candidates.sort(key=lambda item: item.start)
    image_spans = [(item.start, item.end) for item in candidates]

    for candidate in candidates:
        if _in_ranges(candidate.start, blocked):
            doc.stats["skipped_code"] += 1
            continue

        if candidate.style in ("ref", "shortcut"):
            label = candidate.label or ""
            entry = definitions.get(norm_label(label))
            if entry is None:
                doc.stats["unresolved_refs"] += 1
                continue
            url, url_span, line_end = entry
            if label_used_by_links(text, label, image_spans):
                # The definition is shared with an ordinary link: never touch it,
                # give the image its own fresh definition instead.
                doc.images.append(
                    DocImage(url=url, style="ref-def-new", alt=candidate.alt,
                             line=lines.line(candidate.start), label=label,
                             label_span=candidate.label_span, insert_at=line_end)
                )
            else:
                doc.images.append(
                    DocImage(url=url, style="ref-def", alt=candidate.alt,
                             line=lines.line(candidate.start), span=url_span, label=label)
                )
            continue

        url = (candidate.url or "").strip()
        if not url:
            continue
        alt_span = None
        if candidate.style == "inline":
            alt_span = (candidate.start + 2, candidate.start + 2 + len(candidate.alt))
        doc.images.append(
            DocImage(url=url, style=candidate.style, alt=candidate.alt,
                     line=lines.line(candidate.start), span=candidate.span,
                     alt_span=alt_span)
        )

    doc.stats["discovered"] = len(doc.images)
    doc.stats["non_http"] = sum(
        1 for image in doc.images if SCHEME_RE.match(image.url) and not is_http_url(image.url)
    )
    return doc


# --------------------------------------------------------------------------- #
# Downloading
# --------------------------------------------------------------------------- #


@dataclasses.dataclass
class Fetched:
    ok: bool
    url: str
    final_url: str = ""
    temp_path: Optional[Path] = None
    ext: Optional[str] = None
    fmt: Optional[str] = None
    size: int = 0
    sha256: str = ""
    status: Optional[int] = None
    content_type: str = ""
    error: str = ""
    attempts: int = 0
    retry: bool = False
    retry_after: float = 0.0


class Downloader:
    """Thread-safe HTTP fetcher with retries, exponential backoff and validation."""

    def __init__(
        self,
        temp_dir: Path,
        timeout: float,
        retries: int,
        max_size: int,
        insecure: bool = False,
    ) -> None:
        self.temp_dir = temp_dir
        self.timeout = timeout
        self.retries = max(0, retries)
        self.max_size = max_size
        self.insecure = insecure
        self._local = threading.local()
        self._lock = threading.Lock()
        self._cache: Dict[str, Fetched] = {}

    # -- session ---------------------------------------------------------- #
    def _session(self) -> "requests.Session":
        session = getattr(self._local, "session", None)
        if session is None:
            session = requests.Session()
            session.headers.update(
                {
                    "User-Agent": USER_AGENT,
                    "Accept": (
                        "image/avif,image/webp,image/apng,image/png,image/jpeg,"
                        "image/svg+xml,image/*;q=0.9,*/*;q=0.5"
                    ),
                    "Accept-Language": "en-US,en;q=0.9",
                }
            )
            adapter = requests.adapters.HTTPAdapter(
                pool_connections=4, pool_maxsize=8, max_retries=0
            )
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            self._local.session = session
        return session

    # -- public API ------------------------------------------------------- #
    def fetch(self, url: str) -> Fetched:
        """Fetch ``url`` once per run (results are memoised per normalised URL)."""
        key = url_key(url)
        with self._lock:
            cached = self._cache.get(key)
        if cached is not None:
            return cached
        result = self._fetch_with_retries(url)
        with self._lock:
            self._cache[key] = result
        return result

    # -- internals -------------------------------------------------------- #
    def _fetch_with_retries(self, url: str) -> Fetched:
        attempts = self.retries + 1
        last = Fetched(ok=False, url=url, error="not attempted")
        for attempt in range(1, attempts + 1):
            try:
                result = self._fetch_once(url)
            except Exception as exc:  # noqa: BLE001 - the network layer is untrusted
                result = Fetched(ok=False, url=url, error=describe_error(exc), retry=True)
            result.attempts = attempt
            if result.ok:
                return result
            last = result
            if not result.retry or attempt == attempts:
                break
            delay = min(2.0 ** (attempt - 1), 30.0) + random.uniform(0.0, 0.5)
            if result.retry_after:
                delay = max(delay, result.retry_after)
            time.sleep(delay)

        if last.attempts > 1:
            last.error = f"{last.error} (after {last.attempts} attempts)"
        return last

    def _fetch_once(self, url: str) -> Fetched:
        session = self._session()
        connect_timeout = min(10.0, self.timeout)
        response = session.get(
            request_url(url),
            stream=True,
            timeout=(connect_timeout, self.timeout),
            allow_redirects=True,
            verify=not self.insecure,
        )
        with response:
            status = response.status_code
            content_type = (response.headers.get("Content-Type") or "")
            content_type = content_type.split(";")[0].strip().lower()
            final_url = response.url or url

            if status >= 400 or (status != 200 and status != 206):
                retry = status in HTTP_RETRY_STATUS
                return Fetched(
                    ok=False, url=url, final_url=final_url, status=status,
                    content_type=content_type,
                    error=shorten(f"HTTP {status} {response.reason or ''}".strip()),
                    retry=retry,
                    retry_after=_parse_retry_after(response.headers.get("Retry-After")),
                )

            declared = response.headers.get("Content-Length")
            if declared and declared.isdigit() and int(declared) > self.max_size:
                return Fetched(
                    ok=False, url=url, final_url=final_url, status=status,
                    content_type=content_type,
                    error=f"file too large ({int(declared)} bytes > limit {self.max_size})",
                )

            chunks: List[bytes] = []
            total = 0
            for chunk in response.iter_content(chunk_size=65536):
                if not chunk:
                    continue
                chunks.append(chunk)
                total += len(chunk)
                if total > self.max_size:
                    return Fetched(
                        ok=False, url=url, final_url=final_url, status=status,
                        content_type=content_type,
                        error=f"file too large (> {self.max_size} bytes)",
                    )
            data = b"".join(chunks)

        if not data:
            return Fetched(
                ok=False, url=url, final_url=final_url, status=status,
                content_type=content_type, error="empty response body",
            )

        sniffed = sniff_image(data)
        if sniffed is None:
            if looks_like_html(data):
                reason = (
                    "response is an HTML page, not an image (the link does not "
                    "point to a raw image file)"
                )
            elif content_type.startswith("text/"):
                reason = f"response is text, not an image (content-type: {content_type or 'n/a'})"
            else:
                reason = f"unrecognised image format (content-type: {content_type or 'n/a'})"
            return Fetched(
                ok=False, url=url, final_url=final_url, status=status,
                content_type=content_type, error=reason,
            )

        ext, fmt = sniffed
        digest = hashlib.sha256(data).hexdigest()
        name = hashlib.sha1(url_key(url).encode("utf-8")).hexdigest()[:16]
        temp_path = self.temp_dir / f"{name}.{ext}"
        atomic_write_bytes(temp_path, data)
        return Fetched(
            ok=True, url=url, final_url=final_url, temp_path=temp_path, ext=ext, fmt=fmt,
            size=len(data), sha256=digest, status=status, content_type=content_type,
        )


def request_url(url: str) -> str:
    """Make a URL safe to put on a request line (spaces, parentheses, non-ASCII)."""
    try:
        parts = urllib.parse.urlsplit(url.strip())
    except ValueError:
        return url.strip()
    safe_path = urllib.parse.quote(parts.path, safe="/%:@!$&'()*+,;=~-._")
    safe_query = urllib.parse.quote(parts.query, safe="=&%:@!$'()*+,;/?~-._")
    netloc = parts.netloc
    if not netloc.isascii():
        try:
            netloc = netloc.encode("idna").decode("ascii")
        except UnicodeError:
            pass
    return urllib.parse.urlunsplit((parts.scheme, netloc, safe_path, safe_query, ""))


def _parse_retry_after(value: Optional[str]) -> float:
    if not value:
        return 0.0
    try:
        return max(0.0, min(float(value.strip()), 120.0))
    except ValueError:
        return 0.0


# --------------------------------------------------------------------------- #
# Manifest, naming
# --------------------------------------------------------------------------- #


class Manifest:
    """Persisted knowledge about downloaded images (enables clean re-runs)."""

    VERSION = 1

    def __init__(self, path: Path) -> None:
        self.path = path
        self.entries: Dict[str, dict] = {}
        self._lock = threading.Lock()
        self.dirty = False
        self.load()

    @staticmethod
    def key(directory_rel: str, url: str) -> str:
        return directory_rel + "\x00" + url_key(url)

    def load(self) -> None:
        if not self.path.is_file():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            eprint("warning: could not read " + str(self.path) + ", starting with an empty index")
            return
        if isinstance(data, dict) and isinstance(data.get("entries"), dict):
            self.entries = {
                str(key): value
                for key, value in data["entries"].items()
                if isinstance(value, dict)
            }

    def get(self, directory_rel: str, url: str) -> Optional[dict]:
        with self._lock:
            return self.entries.get(self.key(directory_rel, url))

    def put(self, directory_rel: str, url: str, payload: dict) -> None:
        with self._lock:
            self.entries[self.key(directory_rel, url)] = payload
            self.dirty = True

    def save(self) -> None:
        with self._lock:
            if not self.dirty:
                return
            payload = {
                "version": self.VERSION,
                "updated_at": utcnow(),
                "entries": dict(self.entries),
            }
            data = json.dumps(payload, ensure_ascii=False, indent=1, sort_keys=True)
            self.dirty = False
        try:
            atomic_write_bytes(self.path, data.encode("utf-8"))
        except OSError as exc:
            eprint(f"warning: could not save {self.path}: {exc}")


class NameAllocator:
    """Allocates ``image-001.ext`` style names inside each ``images/`` folder."""

    def __init__(self, images_dir_name: str) -> None:
        self.images_dir_name = images_dir_name
        self._next: Dict[str, int] = {}
        self._lock = threading.Lock()

    def _seed(self, directory: Path) -> int:
        next_index = 1
        images_dir = directory / self.images_dir_name
        if images_dir.is_dir():
            try:
                for entry in images_dir.iterdir():
                    match = IMAGE_NAME_RE.match(entry.name)
                    if match:
                        next_index = max(next_index, int(match.group(1)) + 1)
            except OSError:
                pass
        return next_index

    def reserve_stem(self, directory: Path) -> Path:
        key = str(directory)
        with self._lock:
            if key not in self._next:
                self._next[key] = self._seed(directory)
            index = self._next[key]
            self._next[key] = index + 1
        return directory / self.images_dir_name / f"image-{index:03d}"


# --------------------------------------------------------------------------- #
# Planning
# --------------------------------------------------------------------------- #


@dataclasses.dataclass
class PlannedImage:
    url: str
    status: str
    directory: Optional[Path] = None
    target: Optional[Path] = None
    stem: Optional[Path] = None
    error: str = ""
    ext: Optional[str] = None
    sha256: str = ""
    size: int = 0
    final_url: str = ""


def local_link_target(md_path: Path, target: Path) -> str:
    """Relative link (POSIX style) from the Markdown file to the image file."""
    try:
        link = os.path.relpath(str(target), str(md_path.parent))
    except ValueError:
        link = target.as_posix()
    link = Path(link).as_posix()
    # Percent-encode only what would break Markdown parsing (spaces, parens, ...)
    return urllib.parse.quote(link, safe="/-._~!$&'*,;=:@")


def resolve_local_link(md_path: Path, url: str) -> Optional[Path]:
    """Resolve a Markdown image destination to a filesystem path."""
    cleaned = url.strip()
    if cleaned.startswith("<") and cleaned.endswith(">"):
        cleaned = cleaned[1:-1]
    cleaned = cleaned.split("#", 1)[0].split("?", 1)[0]
    if not cleaned:
        return None
    cleaned = urllib.parse.unquote(cleaned).replace("\\", "/")
    candidate = Path(cleaned)
    if candidate.is_absolute():
        return candidate
    return md_path.parent / candidate


# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #


class Runner:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.root: Path = args.repo
        self.state_dir = Path(args.state_dir).expanduser() if args.state_dir \
            else self.root / STATE_DIR_NAME
        self.temp_dir = self.state_dir / "tmp"
        self.images_dir_name = args.images_dir
        self.manifest = Manifest(self.state_dir / "manifest.json")
        self.allocator = NameAllocator(self.images_dir_name)
        self.excluded = set(DEFAULT_EXCLUDED_DIRS) | set(args.exclude or [])
        self.stats = {
            "markdown_files": 0,
            "markdown_with_images": 0,
            "markdown_modified": 0,
            "images_discovered": 0,
            "unique_urls": 0,
            "downloaded": 0,
            "already_present": 0,
            "would_download": 0,
            "reused_same_url": 0,
            "local_already": 0,
            "failed": 0,
            "links_rewritten": 0,
            "would_rewrite": 0,
            "skipped_code": 0,
            "unresolved_refs": 0,
        }
        self.failures: List[dict] = []
        self.doc_reports: List[dict] = []
        self._plan: Dict[str, PlannedImage] = {}
        self._failure_keys: Set[Tuple[str, str]] = set()
        self._lock = threading.Lock()
        self.backup_root = self.state_dir / "backups" / datetime.now().strftime("%Y%m%d-%H%M%S")

    # -- helpers ---------------------------------------------------------- #
    def bump(self, key: str, amount: int = 1) -> None:
        with self._lock:
            self.stats[key] = self.stats.get(key, 0) + amount

    @staticmethod
    def plan_key(doc: Document, url: str) -> str:
        return doc.rel + "\x00" + url_key(url)

    def record_failure(self, file_rel: str, line: int, url: str, reason: str) -> None:
        """Keep exactly one failure record per (file, url) pair."""
        key = (file_rel, url_key(url))
        with self._lock:
            if key in self._failure_keys:
                return
            self._failure_keys.add(key)
            self.failures.append(
                {"file": file_rel, "line": line, "url": url, "reason": reason}
            )

    def backup(self, doc: Document) -> None:
        if self.args.no_backup:
            return
        destination = self.backup_root / doc.rel
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(doc.path), str(destination))
        except OSError as exc:
            eprint(f"warning: could not back up {doc.rel}: {exc}")

    def discover_markdown(self) -> List[Path]:
        results: List[Path] = []
        state_resolved = self.state_dir.resolve()
        include = self.args.include or []

        def on_error(exc: OSError) -> None:
            eprint("warning: cannot read directory:", exc)

        for dirpath, dirnames, filenames in os.walk(str(self.root), onerror=on_error,
                                                     followlinks=False):
            current = Path(dirpath)
            kept: List[str] = []
            for name in sorted(dirnames):
                if name in self.excluded or name.startswith("."):
                    continue
                try:
                    if (current / name).resolve() == state_resolved:
                        continue
                except OSError:
                    pass
                kept.append(name)
            dirnames[:] = kept

            for filename in sorted(filenames):
                if Path(filename).suffix.lower() not in MARKDOWN_SUFFIXES:
                    continue
                path = current / filename
                if include:
                    relative = rel_posix(path, self.root)
                    if not any(path.match(pattern) or Path(relative).match(pattern)
                               for pattern in include):
                        continue
                results.append(path)

        results.sort()
        return results

    def load_documents(self) -> List[Document]:
        docs: List[Document] = []
        for path in self.discover_markdown():
            rel = rel_posix(path, self.root)
            try:
                doc = parse_document(path, rel)
            except UnicodeDecodeError:
                eprint(f"warning: {rel} is not valid UTF-8, skipped")
                continue
            except OSError as exc:
                eprint(f"warning: cannot read {rel}: {exc}")
                continue
            docs.append(doc)
        return docs

    # -- planning --------------------------------------------------------- #
    def build_plan(self, docs: Sequence[Document]) -> List[PlannedImage]:
        plans: List[PlannedImage] = []
        per_directory: Dict[Tuple[str, str], PlannedImage] = {}

        for doc in docs:
            directory = doc.path.parent
            directory_rel = rel_posix(directory, self.root)
            for image in doc.images:
                if not is_http_url(image.url):
                    continue
                key = (directory_rel, url_key(image.url))

                planned = per_directory.get(key)
                if planned is not None:
                    self.bump("reused_same_url")
                else:
                    planned = self.plan_one(directory, directory_rel, image.url)
                    per_directory[key] = planned
                    plans.append(planned)
                self._plan[self.plan_key(doc, image.url)] = planned

        return plans

    def plan_one(self, directory: Path, directory_rel: str, url: str) -> PlannedImage:
        entry = self.manifest.get(directory_rel, url)
        recorded_file: Optional[Path] = None
        if entry and entry.get("file"):
            recorded_file = self.root / entry["file"]

        if recorded_file is not None and recorded_file.is_file() and recorded_file.stat().st_size > 0:
            if not self.args.overwrite:
                self.bump("already_present")
                return PlannedImage(
                    url=url, status=EXISTING, target=recorded_file,
                    stem=recorded_file.with_suffix(""), ext=recorded_file.suffix.lstrip("."),
                    sha256=entry.get("sha256", ""), size=int(entry.get("size") or 0),
                    final_url=entry.get("final_url", ""),
                )
            return PlannedImage(url=url, status=PENDING, target=recorded_file,
                                stem=recorded_file.with_suffix(""))

        if self.args.dry_run:
            self.bump("would_download")
            stem = self.allocator.reserve_stem(directory)
            ext = extension_from_url(url) or "png"
            return PlannedImage(url=url, status=WOULD_DOWNLOAD, directory=directory,
                                stem=stem, target=stem.with_name(stem.name + "." + ext),
                                ext=ext)

        # The final name (and therefore the extension) is only known once the
        # image has been fetched, so the name is allocated at store time.
        return PlannedImage(url=url, status=PENDING, directory=directory)

    # -- execution -------------------------------------------------------- #
    def execute(self, plans: Sequence[PlannedImage]) -> None:
        pending = [item for item in plans if item.status == PENDING]
        if not pending:
            say("")
            say("Nothing to download: every image is already local.")
            return

        unique: List[str] = []
        seen: Set[str] = set()
        for item in pending:
            key = url_key(item.url)
            if key not in seen:
                seen.add(key)
                unique.append(item.url)

        downloader = Downloader(
            temp_dir=self.temp_dir,
            timeout=self.args.timeout,
            retries=self.args.retry,
            max_size=self.args.max_size,
            insecure=self.args.insecure,
        )

        say("")
        say(f"Downloading {len(unique)} unique image(s) with {self.args.workers} worker(s) ...")
        results: Dict[str, Fetched] = {}
        finished = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.args.workers) as pool:
            futures = {pool.submit(downloader.fetch, url): url for url in unique}
            for future in concurrent.futures.as_completed(futures):
                url = futures[future]
                try:
                    results[url_key(url)] = future.result()
                except Exception as exc:  # noqa: BLE001
                    results[url_key(url)] = Fetched(
                        ok=False, url=url, error=describe_error(exc)
                    )
                finished += 1
                if finished % 25 == 0 or finished == len(unique):
                    say(f"  ... {finished}/{len(unique)} processed")

        for item in pending:
            fetched = results.get(url_key(item.url))
            if fetched is None or not fetched.ok:
                item.status = FAILED
                item.error = fetched.error if fetched else "no download result"
                self.bump("failed")
                continue
            try:
                target = self.store(item, fetched)
            except OSError as exc:
                item.status = FAILED
                item.error = shorten(f"cannot write image: {exc}")
                self.bump("failed")
                continue
            item.status = DOWNLOADED
            item.target = target
            item.ext = fetched.ext
            item.sha256 = fetched.sha256
            item.size = fetched.size
            item.final_url = fetched.final_url
            self.bump("downloaded")

    def store(self, item: PlannedImage, fetched: Fetched) -> Path:
        """Copy a downloaded image into the lab's ``images/`` folder."""
        assert fetched.temp_path is not None
        stem = item.stem
        for _ in range(64):
            if stem is None:
                if item.directory is None:  # pragma: no cover - defensive
                    raise OSError('image folder unknown')
                stem = self.allocator.reserve_stem(item.directory)
            target = stem.with_name(stem.name + "." + str(fetched.ext))
            if item.target is not None and item.target.resolve() == target.resolve():
                pass  # --overwrite of the very same file: rewriting is expected
            elif target.exists() and not self.args.overwrite:
                stem = self.allocator.reserve_stem(stem.parent.parent)
                continue
            copy_atomic(fetched.temp_path, target)
            item.stem = stem
            directory_rel = rel_posix(target.parent.parent, self.root)
            self.manifest.put(
                directory_rel,
                item.url,
                {
                    "file": rel_posix(target, self.root),
                    "url": item.url,
                    "final_url": fetched.final_url,
                    "ext": fetched.ext,
                    "size": fetched.size,
                    "sha256": fetched.sha256,
                    "content_type": fetched.content_type,
                    "updated_at": utcnow(),
                },
            )
            return target
        raise OSError("no free image name could be allocated")

    # -- rewriting -------------------------------------------------------- #
    def rewrite_documents(self, docs: Sequence[Document]) -> None:
        for doc in docs:
            self.rewrite_document(doc)

    def rewrite_document(self, doc: Document) -> None:
        edits: List[Tuple[int, int, str]] = []
        used_spans: Set[Tuple[int, int]] = set()
        image_report: List[dict] = []
        used_labels = {
            norm_label(match.group(1))
            for match in re.finditer(r"^[ \t]{0,3}\[([^\[\]\n]+)\]:", doc.text, re.MULTILINE)
        }

        for image in doc.images:
            if not is_http_url(image.url):
                continue
            planned = self._plan.get(self.plan_key(doc, image.url))
            if planned is None or planned.status not in REWRITABLE or planned.target is None:
                reason = (planned.error if planned else "") or "download failed"
                image_report.append(
                    {"url": image.url, "line": image.line, "local": None,
                     "status": FAILED, "reason": reason}
                )
                self.record_failure(doc.rel, image.line, image.url, reason)
                continue

            link = local_link_target(doc.path, planned.target)
            status = planned.status

            if image.style in ("inline", "html"):
                if image.span is None:  # pragma: no cover - defensive
                    continue
                start, end = image.span
            elif image.style == "ref-def":
                if image.span is None or image.span in used_spans:  # pragma: no cover
                    image_report.append({"url": image.url, "line": image.line,
                                         "local": link, "status": status})
                    continue
                used_spans.add(image.span)
                start, end = image.span
            elif image.style == "ref-def-new":
                if image.label_span is None or image.insert_at is None:  # pragma: no cover
                    continue
                index = 1
                new_label = f"local-image-{index}"
                while norm_label(new_label) in used_labels:
                    index += 1
                    new_label = f"local-image-{index}"
                used_labels.add(norm_label(new_label))
                edits.append((image.label_span[0], image.label_span[1], new_label))
                edits.append((image.insert_at, image.insert_at, f"\n[{new_label}]: {link}"))
                image_report.append({"url": image.url, "line": image.line,
                                     "local": link, "status": status})
                continue
            else:  # pragma: no cover - defensive
                continue

            if image.style == "inline" and image.alt_span is not None \
                    and image.alt.strip() and image.alt.strip() == image.url.strip():
                # the alt text only repeats the remote URL: it would become
                # noise once the URL is replaced by a local path.
                edits.append((image.alt_span[0], image.alt_span[1], ""))
            edits.append((start, end, link))
            image_report.append({"url": image.url, "line": image.line,
                                 "local": link, "status": status})

        if not edits:
            self.doc_reports.append(
                {"file": doc.rel, "modified": False, "images": image_report}
            )
            return

        edits.sort(key=lambda item: (item[0], item[1]))
        accepted: List[Tuple[int, int, str]] = []
        for start, end, replacement in edits:
            if accepted and start < accepted[-1][1]:
                eprint(f"warning: conflicting edit skipped in {doc.rel} at offset {start}")
                continue
            accepted.append((start, end, replacement))

        new_text = doc.text
        for start, end, replacement in reversed(accepted):
            new_text = new_text[:start] + replacement + new_text[end:]

        if new_text == doc.text:
            self.doc_reports.append(
                {"file": doc.rel, "modified": False, "images": image_report}
            )
            return

        if not self.args.dry_run:
            self.backup(doc)
            payload = new_text.encode("utf-8")
            if doc.bom:
                payload = b"\xef\xbb\xbf" + payload
            try:
                atomic_write_bytes(doc.path, payload, like=doc.path)
            except OSError as exc:
                eprint(f"error: cannot write {doc.rel}: {exc}")
                self.failures.append({"file": doc.rel, "line": 0, "url": "",
                                      "reason": shorten(str(exc))})
                self.doc_reports.append(
                    {"file": doc.rel, "modified": False, "images": image_report}
                )
                return
            self.bump("markdown_modified")

        counter = "would_rewrite" if self.args.dry_run else "links_rewritten"
        for entry in image_report:
            if entry.get("local"):
                self.bump(counter)

        self.doc_reports.append(
            {"file": doc.rel, "modified": not self.args.dry_run, "images": image_report}
        )

    # -- top level -------------------------------------------------------- #
    def run(self) -> int:
        if not self.args.dry_run:
            self.temp_dir.mkdir(parents=True, exist_ok=True)
        try:
            say(f"Repository : {self.root}")
            if self.args.dry_run:
                say("Mode       : dry run (nothing is downloaded or written)")

            docs = self.load_documents()
            self.stats["markdown_files"] = len(docs)
            for doc in docs:
                images = [image for image in doc.images if is_http_url(image.url)]
                if images:
                    self.stats["markdown_with_images"] += 1
                self.stats["images_discovered"] += len(doc.images)
                self.stats["local_already"] += len(doc.images) - len(images)
                for key in ("skipped_code", "unresolved_refs"):
                    self.stats[key] += doc.stats.get(key, 0)

            say(f"Markdown   : {len(docs)} file(s)")
            say(f"Images     : {self.stats['images_discovered']} reference(s)")

            plans = self.build_plan(docs)
            self.stats["unique_urls"] = len({url_key(item.url) for item in plans})

            if self.args.dry_run:
                self.report_plan(plans)
            else:
                self.execute(plans)

            self.rewrite_documents(docs)
            self.manifest.save()
            return self.finish()
        finally:
            if not self.args.dry_run:
                shutil.rmtree(self.temp_dir, ignore_errors=True)

    def report_plan(self, plans: Sequence[PlannedImage]) -> None:
        todo = [item for item in plans if item.status in (PENDING, WOULD_DOWNLOAD)]
        say("")
        say(f"Would download {len(todo)} image(s) (one per lab folder):")
        for item in todo[: self.args.max_list]:
            say(f"  - {item.url}")
        if len(todo) > self.args.max_list:
            say(f"  ... and {len(todo) - self.args.max_list} more")
        existing = [item for item in plans if item.status == EXISTING]
        if existing:
            say(f"Already local: {len(existing)} image(s) would be reused as-is.")
        say("")
        say("Note: a dry run does not test the downloads, so the file extensions")
        say("shown in the JSON report are only a guess based on the URL.")

    def finish(self) -> int:
        report = {
            "tool": "download_images.py",
            "version": __version__,
            "generated_at": utcnow(),
            "mode": "dry-run" if self.args.dry_run else "download",
            "repository": str(self.root),
            "summary": dict(self.stats),
            "failures": self.failures,
            "files": self.doc_reports,
        }
        self.print_summary(report)
        self.write_report(report)
        if self.args.strict and self.failures:
            return 1
        return 0

    def print_summary(self, report: dict) -> None:
        stats = report["summary"]
        dry = self.args.dry_run
        pad = "."
        say("")
        say("=" * 64)
        say("Summary" + (" (dry run)" if dry else ""))
        say("=" * 64)
        rows = [
            ("Markdown files processed", stats["markdown_files"]),
            ("Markdown files with images", stats["markdown_with_images"]),
            ("Markdown files modified", stats["markdown_modified"]),
            ("Images discovered", stats["images_discovered"]),
            ("Unique remote URLs", stats["unique_urls"]),
            ("Downloaded", stats["downloaded"]),
            ("Already present (reused)", stats["already_present"]),
            ("Would be downloaded", stats["would_download"]),
            ("Duplicate references reused", stats["reused_same_url"]),
            ("Local links already in place", stats["local_already"]),
            ("Failed", stats["failed"]),
            ("Links rewritten to local paths", stats["links_rewritten"]),
            ("Links that would be rewritten", stats["would_rewrite"]),
            ("Skipped (inside code blocks)", stats["skipped_code"]),
            ("Skipped (unresolved references)", stats["unresolved_refs"]),
        ]
        for label, value in rows:
            if value == 0 and label in ("Would be downloaded", "Links that would be rewritten"):
                continue
            dots = pad * max(3, 40 - len(label))
            say(f"  {label} {dots} {value}")

        if self.failures:
            say("")
            say(f"Failures ({len(self.failures)}):")
            for item in self.failures[: self.args.max_list]:
                where = item["file"] + (f":{item['line']}" if item.get("line") else "")
                say(f"  x {where}")
                if item.get("url"):
                    say(f"    url    : {item['url']}")
                say(f"    reason : {item['reason']}")
            if len(self.failures) > self.args.max_list:
                say(f"  ... and {len(self.failures) - self.args.max_list} more "
                    f"(see the JSON report)")
            if any("CERTIFICATE_VERIFY_FAILED" in item["reason"]
                   or "certificate verify failed" in item["reason"]
                   for item in self.failures):
                say("")
                say("  hint: the TLS certificate could not be verified. Update your CA")
                say("        bundle (apt install ca-certificates) or, if you are behind a")
                say("        corporate proxy, point REQUESTS_CA_BUNDLE at it.")
        elif not dry:
            say("")
            say("All external images were localised successfully.")

        if dry:
            say("")
            say("Dry run: nothing was downloaded and no file was modified.")

    def write_report(self, report: dict) -> None:
        if self.args.dry_run and not self.args.report:
            return
        path = Path(self.args.report).expanduser() if self.args.report \
            else self.state_dir / "image_report.json"
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_bytes(
                path, json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8")
            )
            say("")
            say(f"Report: {path}")
        except OSError as exc:
            eprint(f"warning: cannot write report {path}: {exc}")

    # -- check mode ------------------------------------------------------- #
    def check(self) -> int:
        say(f"Repository : {self.root}")
        docs = self.load_documents()

        problems: List[dict] = []
        known_failures = self.load_known_failures()
        stats = {
            "markdown_files": 0,
            "images_referenced": 0,
            "external_links": 0,
            "external_known_failures": 0,
            "local_links": 0,
            "missing_local_files": 0,
            "corrupt_files": 0,
            "orphan_files": 0,
        }
        referenced: Set[Path] = set()

        for doc in docs:
            stats["markdown_files"] += 1
            for image in doc.images:
                stats["images_referenced"] += 1
                if is_http_url(image.url):
                    if url_key(image.url) in known_failures:
                        stats["external_known_failures"] += 1
                        continue
                    stats["external_links"] += 1
                    problems.append(
                        {"kind": "external_image", "file": doc.rel, "line": image.line,
                         "url": image.url, "detail": "image is still hosted externally"}
                    )
                    continue
                if SCHEME_RE.match(image.url) and not is_http_url(image.url):
                    continue  # data: URI and friends are not our business
                stats["local_links"] += 1
                local = resolve_local_link(doc.path, image.url)
                if local is None or not local.is_file():
                    stats["missing_local_files"] += 1
                    problems.append(
                        {"kind": "missing_local_image", "file": doc.rel, "line": image.line,
                         "url": image.url, "detail": "referenced local image does not exist"}
                    )
                    continue
                referenced.add(local.resolve())
                self.validate_file(local, doc.rel, image, stats, problems)

        for images_dir in self.discover_images_dirs():
            try:
                entries = sorted(images_dir.iterdir())
            except OSError:
                continue
            for entry in entries:
                if not entry.is_file() or entry.name.startswith("."):
                    continue
                if entry.resolve() in referenced:
                    continue
                if entry.stat().st_size == 0:
                    stats["corrupt_files"] += 1
                    problems.append({"kind": "empty_image", "file": rel_posix(entry, self.root),
                                     "detail": "image file is empty"})
                    continue
                with open(entry, "rb") as handle:
                    head = handle.read(4096)
                if sniff_image(head) is None:
                    stats["corrupt_files"] += 1
                    problems.append({"kind": "corrupt_image", "file": rel_posix(entry, self.root),
                                     "detail": "file does not look like a valid image"})
                    continue
                stats["orphan_files"] += 1

        say("")
        say("=" * 64)
        say("Check mode")
        say("=" * 64)
        rows = [
            ("Markdown files checked", stats["markdown_files"]),
            ("Image references", stats["images_referenced"]),
            ("Local references", stats["local_links"]),
            ("External references remaining", stats["external_links"]),
            ("External references (known failures)", stats["external_known_failures"]),
            ("Missing local files", stats["missing_local_files"]),
            ("Corrupt or empty files", stats["corrupt_files"]),
            ("Unreferenced files (info)", stats["orphan_files"]),
        ]
        for label, value in rows:
            dots = "." * max(3, 40 - len(label))
            say(f"  {label} {dots} {value}")

        if problems:
            say("")
            say(f"Problems ({len(problems)}):")
            for problem in problems[: self.args.max_list]:
                where = problem.get("file", "?")
                if problem.get("line"):
                    where += f":{problem['line']}"
                extra = f" - {problem['url']}" if problem.get("url") else ""
                say(f"  x [{problem['kind']}] {where}{extra}")
                if problem.get("detail"):
                    say(f"    {problem['detail']}")
            if len(problems) > self.args.max_list:
                say(f"  ... and {len(problems) - self.args.max_list} more")
            say("")
            say("Result: PROBLEMS FOUND")
            exit_code = 1
        else:
            say("")
            say("Result: OK - the repository is fully offline for images.")
            exit_code = 0

        report = {
            "tool": "download_images.py",
            "version": __version__,
            "generated_at": utcnow(),
            "mode": "check",
            "repository": str(self.root),
            "summary": stats,
            "problems": problems,
        }
        self.write_report(report)
        return exit_code

    def validate_file(self, path: Path, rel: str, image: DocImage,
                      stats: dict, problems: List[dict]) -> None:
        try:
            size = path.stat().st_size
        except OSError as exc:  # pragma: no cover - race with deletion
            problems.append({"kind": "unreadable_image", "file": rel, "line": image.line,
                             "url": image.url, "detail": shorten(str(exc))})
            return
        if size == 0:
            stats["corrupt_files"] += 1
            problems.append({"kind": "empty_image", "file": rel, "line": image.line,
                             "url": image.url, "detail": "image file is empty"})
            return
        try:
            with open(path, "rb") as handle:
                head = handle.read(4096)
        except OSError as exc:  # pragma: no cover
            problems.append({"kind": "unreadable_image", "file": rel, "line": image.line,
                             "url": image.url, "detail": shorten(str(exc))})
            return
        if sniff_image(head) is None:
            stats["corrupt_files"] += 1
            problems.append({"kind": "corrupt_image", "file": rel, "line": image.line,
                             "url": image.url,
                             "detail": "file does not look like a valid image"})

    def load_known_failures(self) -> Set[str]:
        path = Path(self.args.report).expanduser() if self.args.report \
            else self.state_dir / "image_report.json"
        if not path.is_file():
            return set()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return set()
        failures = data.get("failures") or []
        return {
            url_key(item["url"])
            for item in failures
            if isinstance(item, dict) and item.get("url")
        }

    def discover_images_dirs(self) -> Iterator[Path]:
        state_resolved = self.state_dir.resolve()
        for dirpath, dirnames, _ in os.walk(str(self.root), followlinks=False):
            current = Path(dirpath)
            kept: List[str] = []
            for name in dirnames:
                if name in self.excluded or name.startswith("."):
                    continue
                try:
                    if (current / name).resolve() == state_resolved:
                        continue
                except OSError:
                    pass
                kept.append(name)
            dirnames[:] = kept
            candidate = current / self.images_dir_name
            if candidate.is_dir():
                yield candidate


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="download_images.py",
        description=(
            "Localise every external image referenced by the Markdown files of a "
            "repository into per-directory 'images/' folders and rewrite the links."
        ),
        epilog=(
            "examples:\n"
            "  python3 download_images.py .               # localise everything\n"
            "  python3 download_images.py . --dry-run     # preview, no changes\n"
            "  python3 download_images.py . --check       # audit the repository\n"
            "  python3 download_images.py . --workers 4 --timeout 60 --retry 5\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("repo", help="path of the repository to process")
    parser.add_argument("--dry-run", action="store_true",
                        help="show what would happen; download and modify nothing")
    parser.add_argument("--check", action="store_true",
                        help="audit mode: verify the repository is fully offline")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS,
                        help=f"parallel downloads (default {DEFAULT_WORKERS}, max {MAX_WORKERS})")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help=f"HTTP timeout in seconds (default {DEFAULT_TIMEOUT:g})")
    parser.add_argument("--retry", type=int, default=DEFAULT_RETRIES,
                        help=f"extra attempts after a transient failure (default {DEFAULT_RETRIES})")
    parser.add_argument("--overwrite", action="store_true",
                        help="re-download images that are already present")
    parser.add_argument("--no-backup", action="store_true",
                        help="do not keep backups of the Markdown files")
    parser.add_argument("--images-dir", default=DEFAULT_IMAGES_DIR, metavar="NAME",
                        help=f"name of the per-directory image folder (default {DEFAULT_IMAGES_DIR})")
    parser.add_argument("--exclude", action="append", default=[], metavar="NAME",
                        help="additional directory name to skip (repeatable)")
    parser.add_argument("--include", action="append", default=[], metavar="GLOB",
                        help="only process Markdown files matching this glob (repeatable)")
    parser.add_argument("--state-dir", default=None, metavar="PATH",
                        help=f"where manifest/backups/report live (default <repo>/{STATE_DIR_NAME})")
    parser.add_argument("--report", default=None, metavar="PATH",
                        help="path of the JSON report")
    parser.add_argument("--max-size", type=int, default=DEFAULT_MAX_SIZE, metavar="BYTES",
                        help="maximum accepted image size (default 32 MiB)")
    parser.add_argument("--max-list", type=int, default=40, metavar="N",
                        help="maximum number of list items printed (default 40)")
    parser.add_argument("--strict", action="store_true",
                        help="exit with status 1 if any image could not be downloaded")
    parser.add_argument("--insecure", action="store_true",
                        help="do not verify TLS certificates (not recommended)")
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    repo = Path(args.repo).expanduser()
    if not repo.is_dir():
        eprint(f"error: {repo} is not a directory")
        return 2
    args.repo = repo.resolve()
    args.workers = max(1, min(int(args.workers), MAX_WORKERS))
    args.timeout = max(1.0, float(args.timeout))
    args.retry = max(0, int(args.retry))
    args.max_size = max(1024, int(args.max_size))

    if args.dry_run and args.check:
        parser.error("--dry-run and --check cannot be combined")

    runner = Runner(args)
    try:
        if args.check:
            return runner.check()
        return runner.run()
    except KeyboardInterrupt:
        eprint("")
        eprint("Interrupted. Markdown files are written atomically, so none of them")
        eprint("was left half-written; just run the script again to continue.")
        runner.manifest.save()
        return 130
    except Exception as exc:  # noqa: BLE001
        eprint(f"fatal: {type(exc).__name__}: {exc}")
        if os.environ.get("DOWNLOAD_IMAGES_DEBUG"):
            raise
        runner.manifest.save()
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
