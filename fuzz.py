#!/usr/bin/env python3
# fuzz - fast web fuzzer with practical defaults. beats nmap in its niche area resoundingly
# author - Vahe Demirkhanyan

import argparse
import sys
import re
import time
import json
import warnings
import itertools
import gzip
import random
import string
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote, urlparse, urljoin
from typing import Optional, Set, Iterable
import threading
import signal

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3.exceptions import InsecureRequestWarning
from tqdm import tqdm

# ---------- Optional deps ----------
try:
    from colorama import init as colorama_init, Fore, Style
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False

# ---------- Globals ----------
USE_COLOR = False
STOP_EVENT = threading.Event()
SIGINT_COUNT = 0  # for double-press hard exit

# internal (not user-configurable) to keep memory/socket pressure stable
_INTERNAL_BATCH_SIZE = 1000

# Realistic default UA — many WAFs/servers reject bare or bot-like User-Agents,
# causing false-negative 403s.  Override with -H '{"User-Agent":"..."}' if needed.
_DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0.0.0 Safari/537.36"
)

# Pentester default match set (mirrors gobuster/feroxbuster/dirsearch).
_DEFAULT_STATUS_CODES = "200,204,301-303,307,308,401,403,405,500"

_DRAIN_MAX_BYTES = 262_144  # 256 KB

# Threshold (seconds) above which a response is flagged as slow.
# Helps spot blind injection, SSRF, or back-end hangs.
_SLOW_THRESHOLD = 1.5

# Error-rate checkpoints: warn the user if errors exceed this fraction
# at these total-processed counts.
_ERROR_WARN_FRACTION = 0.30
_ERROR_CHECK_AT = frozenset({100, 500, 2000})


# ═══════════════════════════════════════════════════════════════
#  Formatting helpers
# ═══════════════════════════════════════════════════════════════

def _fmt_size(n) -> str:
    """Human-readable byte size."""
    if n is None or n == "N/A":
        return "—"
    try:
        n = int(n)
    except (ValueError, TypeError):
        return str(n)
    if n < 1024:
        return f"{n}B"
    elif n < 1024 * 1024:
        v = n / 1024
        return f"{v:.1f}kB" if v < 100 else f"{v:.0f}kB"
    else:
        return f"{n / (1024 * 1024):.1f}MB"


def _fmt_time(t: float) -> str:
    """Human-readable response time."""
    if t < 1.0:
        return f"{t * 1000:.0f}ms"
    elif t < 10.0:
        return f"{t:.2f}s"
    else:
        return f"{t:.1f}s"


def _install_sigint_handler():
    def _handler(signum, frame):
        global SIGINT_COUNT
        SIGINT_COUNT += 1
        STOP_EVENT.set()
        if SIGINT_COUNT == 1:
            try:
                print("\n[!] Ctrl+C received — stopping new work (press again to force quit).", file=sys.stderr)
            except Exception:
                pass
        else:
            raise KeyboardInterrupt
    signal.signal(signal.SIGINT, _handler)


def color_status(status):
    if not USE_COLOR:
        return f"[{status}]"
    if status == "error":
        return Fore.RED + "[error]" + Style.RESET_ALL
    if status == "cancelled":
        return Fore.YELLOW + "[cancelled]" + Style.RESET_ALL
    try:
        code = int(status)
    except (ValueError, TypeError):
        return f"[{status}]"
    if 200 <= code < 300:
        return Fore.GREEN + f"[{code}]" + Style.RESET_ALL
    elif 300 <= code < 400:
        return Fore.YELLOW + f"[{code}]" + Style.RESET_ALL
    elif 400 <= code < 500:
        return Fore.RED + f"[{code}]" + Style.RESET_ALL
    elif 500 <= code < 600:
        return Fore.MAGENTA + f"[{code}]" + Style.RESET_ALL
    else:
        return f"[{code}]"


def _dim(text: str) -> str:
    """Dim text if color is available; otherwise return unchanged."""
    if USE_COLOR and COLORAMA_AVAILABLE:
        return Style.DIM + text + Style.RESET_ALL
    return text


def _bold(text: str) -> str:
    """Bold/bright text if color is available."""
    if USE_COLOR and COLORAMA_AVAILABLE:
        return Style.BRIGHT + text + Style.RESET_ALL
    return text


def _expand_status_alias(s: str) -> str:
    if s.strip().lower() == "common":
        return "200,204,301-303,307,308,401,403,405,500"
    return s


def parse_status_selector(selector: str) -> Set[int]:
    out: Set[int] = set()
    parts = [p.strip() for p in selector.split(",") if p.strip()]
    for p in parts:
        pl = p.lower()
        if pl in ("-1", "error"):
            out.add(-1)
        elif re.fullmatch(r"\d{3}", p):
            out.add(int(p))
        elif re.fullmatch(r"[1-5]xx", pl):
            base = int(p[0]) * 100
            out.update(range(base, base + 100))
        elif re.fullmatch(r"\d{3}\s*-\s*\d{3}", p):
            a, b = [int(x) for x in re.split(r"\s*-\s*", p)]
            if a > b:
                a, b = b, a
            out.update(range(a, b + 1))
        else:
            raise ValueError(f"Invalid status selector: {p}")
    return out


def _is_hit(status, status_codes: Set[int]) -> bool:
    return (isinstance(status, int) and status in status_codes) or (status == "error" and (-1 in status_codes))


def _open_text(path: str):
    return gzip.open(path, "rt", encoding="utf-8", errors="ignore") if path.lower().endswith(".gz") \
        else open(path, "r", encoding="utf-8", errors="ignore")


def _fmt_status_set(s: Set[int]) -> str:
    """Pretty-print a set of status codes (compact ranges)."""
    if not s:
        return "—"
    parts = []
    nums = sorted(n for n in s if n >= 0)
    if -1 in s:
        parts.append("error")
    i = 0
    while i < len(nums):
        start = nums[i]
        while i + 1 < len(nums) and nums[i + 1] == nums[i] + 1:
            i += 1
        end = nums[i]
        if end - start >= 99 and start % 100 == 0:
            parts.append(f"{start // 100}xx")
        elif start == end:
            parts.append(str(start))
        elif end - start <= 4:
            parts.extend(str(x) for x in range(start, end + 1))
        else:
            parts.append(f"{start}-{end}")
        i += 1
    return ", ".join(parts)


def _fmt_int_set(s: Set[int]) -> str:
    return ", ".join(str(x) for x in sorted(s)) if s else "—"


def _fmt_counter(counter: Counter) -> str:
    """Pretty-print status distribution, e.g. '404×4521  200×3  301×12'."""
    if not counter:
        return "—"
    def _sort_key(item):
        code, count = item
        if isinstance(code, str):
            return (1, -1)
        return (0, -count)
    parts = []
    for code, count in sorted(counter.items(), key=_sort_key):
        parts.append(f"{code}×{count}")
    return "  ".join(parts)


# ═══════════════════════════════════════════════════════════════
#  Wordlist reading
# ═══════════════════════════════════════════════════════════════

def read_wordlist_in_batches(wordlist_path: str, batch_size: int) -> Iterable[list[str]]:
    current_batch: list[str] = []
    with _open_text(wordlist_path) as f:
        for line in f:
            w = line.strip()
            if w:
                current_batch.append(w)
            if len(current_batch) == batch_size:
                yield current_batch
                current_batch = []
    if current_batch:
        yield current_batch


def read_iter_in_batches(iterator: Iterable[str], batch_size: int) -> Iterable[list[str]]:
    batch: list[str] = []
    for item in iterator:
        batch.append(item)
        if len(batch) == batch_size:
            yield batch
            batch = []
    if batch:
        yield batch


def count_lines(wordlist_path: str) -> int:
    c = 0
    try:
        with _open_text(wordlist_path) as f:
            for line in f:
                if line.strip():
                    c += 1
    except FileNotFoundError:
        print(f"Error: Wordlist file '{wordlist_path}' not found.")
        sys.exit(1)
    return c


# ═══════════════════════════════════════════════════════════════
#  Response filtering
# ═══════════════════════════════════════════════════════════════

def should_filter_response(status,
                           header_content_length,
                           body_size_bytes,
                           word_count,
                           filter_status: Set[int],
                           filter_size_header: Set[int],
                           filter_size_bytes: Set[int],
                           filter_words: Set[int],
                           words_filter_active: bool) -> bool:
    if isinstance(status, int) and status in filter_status:
        return True
    if status == "error" and (-1 in filter_status):
        return True

    if header_content_length != "N/A":
        try:
            if int(header_content_length) in filter_size_header:
                return True
        except ValueError:
            pass

    if (body_size_bytes is not None) and (body_size_bytes in filter_size_bytes):
        return True

    if words_filter_active and word_count is not None and word_count in filter_words:
        return True

    return False


# ═══════════════════════════════════════════════════════════════
#  Connection management
# ═══════════════════════════════════════════════════════════════

def _drain_and_close(response, max_bytes: int = _DRAIN_MAX_BYTES):
    """Drain a small response body so the underlying connection is returned to
    the pool for reuse (preserving TCP + TLS state)."""
    if response is None:
        return
    try:
        cl = response.headers.get("Content-Length")
        if cl is not None and int(cl) > max_bytes:
            response.close()
            return
        drained = 0
        for chunk in response.iter_content(chunk_size=16384):
            drained += len(chunk)
            if drained > max_bytes:
                response.close()
                return
    except Exception:
        try:
            response.close()
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════
#  Auto-calibration
# ═══════════════════════════════════════════════════════════════

def _auto_calibrate(*,
                    session: requests.Session,
                    url_template: str,
                    timeout: float,
                    follow_redirects: bool) -> dict:
    """
    Send 3 canary requests with random gibberish words to detect the baseline
    'not found' response.  Returns a dict describing the baseline:
        {
          'status': 404,
          'header_cl': 1234,       # consistent header Content-Length, or None
          'body_size': 1234,       # consistent body size, or None
          'filter_field': 'fs',    # 'fs' (header CL) | 'fbs' (body bytes) | None
          'filter_value': 1234,    # value to add to the appropriate filter set
        }
    Empty dict if calibration was inconclusive.
    """
    canary_results = []
    for _ in range(3):
        word = "fzcal_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=14))
        result = check_url(
            session=session,
            word=word,
            url_template=url_template,
            follow_redirects=follow_redirects,
            timeout=timeout,
            need_word_count=False,
            need_snippet=False,
            need_body_size=True,
            stop_event=None,
        )
        canary_results.append(result)

    statuses = [r[1] for r in canary_results]
    header_cls_raw = [r[3] for r in canary_results]
    body_sizes = [r[4] for r in canary_results if r[4] is not None]

    baseline = {}

    # Status consistency
    if len(set(statuses)) == 1 and isinstance(statuses[0], int):
        baseline["status"] = statuses[0]
    else:
        return {}  # different statuses for random words — inconclusive

    # Prefer header Content-Length (zero scan overhead when filtering by -fs)
    header_cls = []
    for raw in header_cls_raw:
        if raw != "N/A":
            try:
                header_cls.append(int(raw))
            except ValueError:
                pass
    if len(header_cls) == 3 and len(set(header_cls)) == 1 and header_cls[0] >= 50:
        baseline["header_cl"] = header_cls[0]
        baseline["filter_field"] = "fs"
        baseline["filter_value"] = header_cls[0]
        return baseline

    # Fall back to body-size consistency
    if len(body_sizes) == 3:
        avg = sum(body_sizes) / 3
        tolerance = max(64, avg * 0.05)
        if all(abs(s - avg) <= tolerance for s in body_sizes) and avg >= 50:
            val = round(avg)
            baseline["body_size"] = val
            baseline["filter_field"] = "fbs"
            baseline["filter_value"] = val
            return baseline

    # Sizes vary too much — can't reliably auto-filter
    baseline["filter_field"] = None
    return baseline


# ═══════════════════════════════════════════════════════════════
#  Core request function
# ═══════════════════════════════════════════════════════════════

def check_url(*,
              session: requests.Session,
              word: str,
              url_template: str,
              follow_redirects: bool = False,
              timeout: float = 5.0,
              need_word_count: bool = False,
              need_snippet: bool = False,
              need_body_size: bool = False,
              stop_event: Optional[threading.Event] = None):
    """
    GET request after replacing 'fuzz' with URL-encoded word (strict encoding).
    Returns:
      (actual_url, status_code or 'error'/'cancelled', redirect_url, header_content_length,
       body_size_bytes or None, word_count or None, total_time, snippet)
    """
    if stop_event is not None and stop_event.is_set():
        return (
            url_template.replace("fuzz", quote(word, safe="")),
            "cancelled",
            None,
            "N/A",
            None,
            None,
            0.0,
            "cancelled",
        )

    injected = quote(word, safe="")  # strict encoding
    actual_url = url_template.replace("fuzz", injected)

    req_headers = {}
    if need_body_size:
        req_headers["Accept-Encoding"] = "identity"

    response = None
    start_time = time.perf_counter()
    try:
        if stop_event is not None and stop_event.is_set():
            return (actual_url, "cancelled", None, "N/A", None, None, 0.0, "cancelled")

        response = session.get(
            actual_url,
            headers=req_headers or None,
            allow_redirects=follow_redirects,
            timeout=(timeout, timeout),
            stream=True,
        )

        redirect_url = None
        if response.status_code in (301, 302, 303, 307, 308) and not follow_redirects:
            loc = response.headers.get("Location")
            redirect_url = urljoin(actual_url, loc) if loc else None

        header_content_length = response.headers.get("Content-Length", "N/A")

        body_size_bytes = None
        snippet = ""
        word_count = None

        # ── Fast path: only need status code + headers ────────────────
        if not (need_snippet or need_body_size or need_word_count):
            status_code = response.status_code
            total_time = time.perf_counter() - start_time
            _drain_and_close(response, _DRAIN_MAX_BYTES)
            response = None
            return (actual_url, status_code,
                    redirect_url, header_content_length, None, None, total_time, "")

        # ── Full-body path (word count needs decoded text) ────────────
        if need_word_count:
            try:
                raw_bytes = response.content or b""
            except Exception:
                raw_bytes = b""

            if need_body_size:
                body_size_bytes = len(raw_bytes)

            try:
                text = raw_bytes.decode(response.encoding or "utf-8", errors="replace")
            except Exception:
                text = ""

            word_count = len(text.split()) if text else 0
            if need_snippet:
                snippet = (text[:120].replace("\n", "\\n") if text else "")

        # ── Streaming path (snippet and/or byte-size, no word count) ──
        else:
            seen = 0
            snip_buf = b""
            if need_body_size:
                body_size_bytes = 0

            for chunk in response.iter_content(chunk_size=8192):
                if stop_event is not None and stop_event.is_set():
                    try:
                        response.close()
                    except Exception:
                        pass
                    response = None
                    return (actual_url, "cancelled", None, "N/A", None, None, 0.0, "cancelled")

                if not chunk:
                    continue

                if need_body_size and body_size_bytes is not None:
                    body_size_bytes += len(chunk)

                if need_snippet and seen < 2048:
                    remain = 2048 - seen
                    snip_buf += chunk[:remain]
                    seen += min(len(chunk), remain)
                    if (not need_body_size) and seen >= 2048:
                        break

            if need_snippet and snip_buf:
                try:
                    snippet = snip_buf.decode(response.encoding or "utf-8", errors="replace")[:120].replace("\n", "\\n")
                except Exception:
                    snippet = ""

        status_code = response.status_code
        total_time = time.perf_counter() - start_time
        return (
            actual_url,
            status_code,
            redirect_url,
            header_content_length,
            body_size_bytes,
            word_count,
            total_time,
            snippet,
        )

    except requests.RequestException as e:
        total_time = time.perf_counter() - start_time
        err_snippet = f"{type(e).__name__}: {str(e)}"[:120]
        return (actual_url, "error", None, "N/A", None, None, total_time, err_snippet)
    finally:
        try:
            if response is not None:
                response.close()
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════
#  Output helpers
# ═══════════════════════════════════════════════════════════════

def _flush_hits(output_file, hits_buf, url_template, wrote_header):
    """Append buffered hits to the output file."""
    try:
        with open(output_file, "a", encoding="utf-8") as f:
            if not wrote_header:
                f.write(f"\n{'─' * 80}\n")
                f.write(f"Results for: {url_template}\n")
                f.write(f"{'─' * 80}\n")
            for word, u, st, r in hits_buf:
                redir = f"  ->  {r}" if r else ""
                f.write(f"[{st}] {word} → {u}{redir}\n")
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════
#  Main fuzzing loop
# ═══════════════════════════════════════════════════════════════

def fuzz_target(*,
                url_template: str,
                word_source_type: str,        # "file" | "iter"
                wordlist_path: Optional[str],
                generated_iter: Optional[Iterable[str]],
                session: requests.Session,
                follow_redirects: bool,
                verbose: bool,
                status_codes: Set[int],
                filter_size_header: Set[int],
                filter_size_bytes: Set[int],
                filter_words: Set[int],
                filter_status: Set[int],
                output_file: Optional[str],
                max_workers: int,
                timeout: float,
                total_words: Optional[int]):
    if "fuzz" not in url_template:
        print("Error: TEMPLATE must include 'fuzz' for GET fuzzing.")
        return 0, 0.0, Counter()

    # ── Auto-calibration ──────────────────────────────────────────────
    cal = _auto_calibrate(
        session=session,
        url_template=url_template,
        timeout=timeout,
        follow_redirects=follow_redirects,
    )
    cal_active = False
    cal_desc = ""
    if cal and cal.get("filter_field"):
        fld = cal["filter_field"]
        val = cal["filter_value"]
        bstatus = cal.get("status", "?")
        if fld == "fs":
            if val not in filter_size_header:
                filter_size_header = filter_size_header | {val}
                cal_active = True
                cal_desc = f"baseline [{bstatus}] {_fmt_size(val)} — auto-filtering by header size"
        elif fld == "fbs":
            if val not in filter_size_bytes:
                filter_size_bytes = filter_size_bytes | {val}
                cal_active = True
                cal_desc = f"baseline [{bstatus}] ~{_fmt_size(val)} — auto-filtering by body size"
    elif cal and cal.get("status") is not None:
        cal_desc = f"baseline [{cal['status']}], sizes vary — no auto-filter (use -fs/-fbs/-fc manually)"
    else:
        cal_desc = "inconclusive — no auto-filter"

    # ── Determine what data the scan needs ────────────────────────────
    if word_source_type == "iter":
        word_batches = read_iter_in_batches(generated_iter, _INTERNAL_BATCH_SIZE)  # type: ignore
    else:
        word_batches = read_wordlist_in_batches(wordlist_path, _INTERNAL_BATCH_SIZE)  # type: ignore

    verbose_local = bool(verbose)
    words_filter_active = bool(filter_words)

    need_word_count = verbose_local and words_filter_active
    need_body_size = bool(filter_size_bytes)   # includes auto-cal additions
    need_snippet = verbose_local

    # ── Config summary ────────────────────────────────────────────────
    tls_on = bool(getattr(session, "verify", True))
    print(f"\n{'─' * 80}")
    print(f"  Target    : {url_template}")
    print(f"  Threads   : {max_workers}   Timeout: {timeout}s   Redirects: {'follow' if follow_redirects else 'show'}")
    print(f"  TLS verify: {'on' if tls_on else 'OFF (insecure)'}")
    print(f"  Match     : {_fmt_status_set(status_codes)}")
    any_filter = filter_status or filter_size_header or filter_size_bytes or filter_words
    if any_filter:
        if filter_status:
            print(f"  Filter -fc: {_fmt_status_set(filter_status)}")
        if filter_size_header:
            cal_note = " (incl. auto-cal)" if cal_active and cal.get("filter_field") == "fs" else ""
            print(f"  Filter -fs: {_fmt_int_set(filter_size_header)}{cal_note}")
        if filter_size_bytes:
            cal_note = " (incl. auto-cal)" if cal_active and cal.get("filter_field") == "fbs" else ""
            print(f"  Filter -fbs: {_fmt_int_set(filter_size_bytes)}{cal_note}")
        if filter_words:
            print(f"  Filter -fw: {_fmt_int_set(filter_words)}")
    print(f"  Auto-cal  : {cal_desc}")
    print(f"{'─' * 80}\n")

    total_hits = 0
    total_processed = 0
    error_count = 0
    error_warned = False
    status_counter: Counter = Counter()
    run_start = time.monotonic()
    pbar = tqdm(
        total=total_words if total_words is not None else None,
        desc="Fuzzing",
        unit="req",
        disable=not sys.stderr.isatty(),
    )

    store_hits = bool(output_file)
    hits_buf = []
    wrote_header = False

    executor = ThreadPoolExecutor(max_workers=max_workers)
    try:
        for batch in word_batches:
            if STOP_EVENT.is_set():
                break

            future_to_word = {}
            for word in batch:
                if STOP_EVENT.is_set():
                    break
                f = executor.submit(
                    check_url,
                    session=session,
                    word=word,
                    url_template=url_template,
                    follow_redirects=follow_redirects,
                    timeout=timeout,
                    need_word_count=need_word_count,
                    need_snippet=need_snippet,
                    need_body_size=need_body_size,
                    stop_event=STOP_EVENT,
                )
                future_to_word[f] = word

            for future in as_completed(future_to_word):
                if STOP_EVENT.is_set():
                    break

                word = future_to_word[future]
                (url, status, redirect, header_cl,
                 body_size_bytes_val, word_count, response_time, snippet) = future.result()

                if status == "cancelled":
                    continue

                pbar.update(1)
                total_processed += 1
                status_counter[status] += 1

                # ── Error-rate monitoring ─────────────────────────────
                if status == "error":
                    error_count += 1
                if (not error_warned
                        and total_processed in _ERROR_CHECK_AT
                        and error_count / total_processed > _ERROR_WARN_FRACTION):
                    error_warned = True
                    pct = error_count / total_processed * 100
                    tqdm.write(
                        _dim(f"  [!] High error rate: {error_count}/{total_processed} "
                             f"({pct:.0f}%) — check target, network, or reduce --threads")
                    )

                # ── Filtering ─────────────────────────────────────────
                if should_filter_response(
                    status,
                    header_cl,
                    body_size_bytes_val,
                    word_count,
                    filter_status,
                    filter_size_header,
                    filter_size_bytes,
                    filter_words,
                    words_filter_active,
                ):
                    continue

                is_hit = _is_hit(status, status_codes)
                if not verbose_local and not is_hit:
                    continue

                # ── Format the display line ───────────────────────────
                colorized = color_status(status)
                slow_tag = ""
                if isinstance(response_time, (int, float)) and response_time >= _SLOW_THRESHOLD:
                    slow_tag = " [SLOW]" if not USE_COLOR else (
                        " " + Fore.RED + Style.BRIGHT + "[SLOW]" + Style.RESET_ALL)

                # Best available size: prefer body bytes, fall back to header CL
                disp_size = _fmt_size(body_size_bytes_val) if body_size_bytes_val is not None else _fmt_size(header_cl)
                disp_time = _fmt_time(response_time)

                if is_hit:
                    # ── HIT: prominent format with >> marker ──────────
                    redir_part = ""
                    if redirect and not follow_redirects:
                        redir_part = f"  ->  {redirect}"
                    snip_part = ""
                    if need_snippet and snippet:
                        snip_part = f"\n           Snip: {snippet}"
                    line = (
                        f" >> {colorized}  {_bold(word)}"
                        f"  {disp_size}  {disp_time}{slow_tag}"
                        f"  {_dim(url)}{redir_part}{snip_part}"
                    )
                else:
                    # ── Non-hit (verbose noise): compact, dimmed ──────
                    redir_part = ""
                    if redirect and not follow_redirects:
                        redir_part = f"  -> {redirect}"
                    line = _dim(
                        f"    {colorized}  {word}"
                        f"  {disp_size}  {disp_time}{slow_tag}{redir_part}"
                    )

                tqdm.write(line)

                if is_hit:
                    total_hits += 1
                    pbar.set_postfix(hits=total_hits, refresh=False)

                    if store_hits:
                        hits_buf.append((word, url, status, redirect))
                        if len(hits_buf) >= 2000:
                            _flush_hits(output_file, hits_buf, url_template, wrote_header)
                            wrote_header = True
                            hits_buf.clear()

            if STOP_EVENT.is_set():
                break

    except KeyboardInterrupt:
        STOP_EVENT.set()
        try:
            session.close()
        except Exception:
            pass
        try:
            executor.shutdown(wait=False, cancel_futures=True)
        except TypeError:
            executor.shutdown(wait=False)
        raise
    finally:
        try:
            executor.shutdown(wait=False, cancel_futures=True)
        except TypeError:
            executor.shutdown(wait=False)
        pbar.close()

    if store_hits and hits_buf:
        _flush_hits(output_file, hits_buf, url_template, wrote_header)

    elapsed = time.monotonic() - run_start
    return total_hits, elapsed, status_counter


# ═══════════════════════════════════════════════════════════════
#  Entry point
# ═══════════════════════════════════════════════════════════════

def main():
    if COLORAMA_AVAILABLE:
        colorama_init(autoreset=True)
    _install_sigint_handler()

    parser = argparse.ArgumentParser(
        description="Fast web fuzzer (lean): GET fuzzing with practical filters."
    )

    parser.add_argument(
        "TEMPLATE",
        help="Target URL template (must include 'fuzz'), e.g. https://site/path/fuzz"
    )

    parser.add_argument("-f", "--wordlist", help="Path to the wordlist file (optionally .gz)")
    parser.add_argument("-r", "--regex", help="Generate fuzz values from a regex pattern instead of a wordlist")
    parser.add_argument("--regex-limit", type=int, default=100000, help="Max candidates to produce from --regex")

    parser.add_argument(
        "-s", "--status-codes", default=_DEFAULT_STATUS_CODES,
        help=(
            "Status selectors for hits "
            "(e.g., 200, 3xx, 401-403, 'common', or -1/'error' for transport failures). "
            f"Default: {_DEFAULT_STATUS_CODES}"
        ),
    )
    parser.add_argument("-rdr", "--follow-redirects", action="store_true", help="Follow redirects")

    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output (non-filtered responses)")
    parser.add_argument("-o", "--output", help="Append hits to a text file")

    parser.add_argument("-t", "--threads", type=int, default=20, help="Worker threads")
    parser.add_argument("--timeout", type=float, default=5.0, help="Connect/read timeout in seconds")

    parser.add_argument("-fs", "--filter-size", help="Comma-separated list of header Content-Length values to filter out")
    parser.add_argument("-fbs", "--filter-bytes", help="Comma-separated list of actual body byte sizes to filter out")
    parser.add_argument("-fw", "--filter-words", help="Comma-separated list of word counts to filter out (requires --verbose)")
    parser.add_argument("-fc", "--filter-status", help="Status selectors to filter out (e.g., 404,5xx,429, or 'error')")

    parser.add_argument("-H", "--headers", help="Custom headers in JSON format")
    parser.add_argument("--proxy", help="HTTP(S) proxy (env proxies ignored; use --proxy)")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")

    args = parser.parse_args()

    global USE_COLOR
    USE_COLOR = COLORAMA_AVAILABLE and sys.stderr.isatty()

    if args.timeout <= 0:
        print("Error: --timeout must be > 0.")
        sys.exit(1)
    if args.threads < 1:
        print("Error: --threads must be >= 1.")
        sys.exit(1)

    parsed = urlparse(args.TEMPLATE)
    if parsed.scheme.lower() not in ("http", "https"):
        print("Error: TEMPLATE must be a full URL starting with http:// or https://")
        sys.exit(1)
    if "fuzz" not in args.TEMPLATE:
        print("Error: TEMPLATE must include 'fuzz' (e.g., https://site/path/fuzz).")
        sys.exit(1)

    if args.insecure:
        warnings.filterwarnings("ignore", category=InsecureRequestWarning)

    headers = None
    if args.headers:
        try:
            headers = json.loads(args.headers)
        except json.JSONDecodeError:
            print("Error: --headers must be valid JSON.")
            sys.exit(1)
        if headers is not None and not isinstance(headers, dict):
            print('Error: --headers must be a JSON object, e.g. \'{"Header":"Value"}\'.')
            sys.exit(1)

    try:
        sc = _expand_status_alias(args.status_codes)
        status_codes = parse_status_selector(sc)
    except Exception as e:
        print(f"Error parsing --status-codes: {e}")
        sys.exit(1)

    filter_size_header: Set[int] = set()
    if args.filter_size:
        try:
            filter_size_header = {int(x.strip()) for x in args.filter_size.split(",") if x.strip()}
        except ValueError:
            print("Error: --filter-size must be integers.")
            sys.exit(1)

    filter_size_bytes: Set[int] = set()
    if args.filter_bytes:
        try:
            filter_size_bytes = {int(x.strip()) for x in args.filter_bytes.split(",") if x.strip()}
        except ValueError:
            print("Error: --filter-bytes must be integers.")
            sys.exit(1)

    filter_words: Set[int] = set()
    if args.filter_words:
        if not args.verbose:
            print("Error: --filter-words requires --verbose (needs response text).")
            sys.exit(1)
        try:
            filter_words = {int(x.strip()) for x in args.filter_words.split(",") if x.strip()}
        except ValueError:
            print("Error: --filter-words must be integers.")
            sys.exit(1)

    filter_status: Set[int] = set()
    if args.filter_status:
        try:
            filter_status = parse_status_selector(args.filter_status)
        except Exception as e:
            print(f"Error parsing --filter-status: {e}")
            sys.exit(1)

    if not args.wordlist and not args.regex:
        print("Error: You must provide either --wordlist or --regex.")
        sys.exit(1)
    if args.wordlist and args.regex:
        print("Error: Cannot use both --wordlist and --regex at the same time.")
        sys.exit(1)

    generated_iter = None
    total_words = None
    if args.regex:
        try:
            try:
                import exrex
            except ImportError:
                print("Error: --regex requires 'exrex' (pip install exrex)")
                sys.exit(1)
            gen = exrex.generate(args.regex)
            if args.regex_limit and args.regex_limit > 0:
                gen = itertools.islice(gen, args.regex_limit)
                total_words = args.regex_limit
            generated_iter = gen
            word_source_type = "iter"
            print(f"Streaming up to {total_words if total_words else '∞'} words from regex: {args.regex}")
        except Exception as e:
            print(f"Error generating words from regex: {e}")
            sys.exit(1)
    else:
        total_words = count_lines(args.wordlist)
        if total_words == 0:
            print("Error: The wordlist is empty.")
            sys.exit(1)
        print(f"Loaded {total_words:,} words from {args.wordlist}")
        word_source_type = "file"

    def _make_adapter(threads: int, retry_total: int = 2, retry_backoff: float = 0.3):
        safe = frozenset({"GET"})
        # Do NOT retry on 5xx — server errors are *findings* for a fuzzer.
        try:
            retries = Retry(
                total=retry_total,
                backoff_factor=retry_backoff,
                status_forcelist=[429],
                allowed_methods=safe,
                respect_retry_after_header=True,
            )
        except TypeError:
            retries = Retry(
                total=retry_total,
                backoff_factor=retry_backoff,
                status_forcelist=[429],
                method_whitelist=safe,
            )
        pool = max(threads * 2, 16)
        return HTTPAdapter(
            pool_connections=pool,
            pool_maxsize=pool,
            max_retries=retries,
        )

    with requests.Session() as session:
        session.trust_env = False
        session.verify = (not args.insecure)
        if args.proxy:
            session.proxies.update({"http": args.proxy, "https": args.proxy})

        adapter = _make_adapter(args.threads)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        session.headers["User-Agent"] = _DEFAULT_USER_AGENT
        if headers:
            session.headers.update(headers)

        hits, elapsed, status_counter = fuzz_target(
            url_template=args.TEMPLATE,
            word_source_type=word_source_type,
            wordlist_path=args.wordlist,
            generated_iter=generated_iter,
            session=session,
            follow_redirects=args.follow_redirects,
            verbose=args.verbose,
            status_codes=status_codes,
            filter_size_header=filter_size_header,
            filter_size_bytes=filter_size_bytes,
            filter_words=filter_words,
            filter_status=filter_status,
            output_file=args.output,
            max_workers=args.threads,
            timeout=args.timeout,
            total_words=total_words,
        )

    # ── Summary ───────────────────────────────────────────────────────
    mins, secs = divmod(elapsed, 60)
    if mins:
        elapsed_str = f"{int(mins)}m {secs:.1f}s"
    else:
        elapsed_str = f"{secs:.1f}s"

    reqs_done = sum(status_counter.values()) or total_words or 0
    rps = reqs_done / elapsed if elapsed > 0 else 0

    print(f"\n{'─' * 80}")
    print(f"  Done in {elapsed_str}  ({reqs_done:,} requests, ~{rps:.0f} req/s)")
    print(f"  Hits: {hits}")
    if status_counter:
        print(f"  Status distribution: {_fmt_counter(status_counter)}")
    if args.output:
        print(f"  Output: {args.output}")

    # Actionable guidance when nothing was found
    if hits == 0 and not STOP_EVENT.is_set():
        hints = []
        if not args.verbose:
            hints.append("try -v to see all responses")
        if args.status_codes == _DEFAULT_STATUS_CODES:
            hints.append("try -s '2xx,3xx,4xx,5xx' for wider matching")
        if not args.filter_status and not args.filter_size and not args.filter_bytes:
            hints.append("check if auto-calibration filtered too aggressively")
        if hints:
            print(f"  Tip: {'; '.join(hints)}")

    print(f"{'─' * 80}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        STOP_EVENT.set()
        print("\nFuzzing interrupted by user.")
        sys.exit(130)
