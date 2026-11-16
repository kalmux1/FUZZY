#!/usr/bin/env python3
"""
FUZZY - multi-domain subdomain reconnaissance pipeline.

Stage 1: puredns bruteforce  (mass DNS, wildcard-filtered)
Stage 2: ffuf host probing    (HTTP/HTTPS liveness on resolved hosts)

Author : Kalmux
Repo   : https://github.com/kalmux/fuzzy
License: MIT
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import select
import shutil
import signal
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

VERSION = "1.0.1"
AUTHOR  = "Kalmux"
REPO    = "https://github.com/kalmux/fuzzy"

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)
RESOLVER_URL = (
    "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
)
PUREDNS_BATCH = 100


# ---------------------------------------------------------------- unicode

def _unicode_terminal() -> bool:
    if os.environ.get("FUZZY_ASCII") == "1":
        return False
    if os.environ.get("FUZZY_UNICODE") == "1":
        return True
    for var in ("LC_ALL", "LC_CTYPE", "LANG"):
        val = os.environ.get(var, "")
        if val:
            low = val.lower()
            return "utf-8" in low or "utf8" in low
    return False


UNICODE_OK = _unicode_terminal()


# ---------------------------------------------------------------- colour

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _tty() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


class C:
    enabled = _tty()

    @classmethod
    def _w(cls, code: str, s: str) -> str:
        return f"\033[{code}m{s}\033[0m" if cls.enabled else s

    @classmethod
    def bold(cls, s):     return cls._w("1", s)
    @classmethod
    def dim(cls, s):      return cls._w("2", s)
    @classmethod
    def red(cls, s):      return cls._w("31", s)
    @classmethod
    def green(cls, s):    return cls._w("32", s)
    @classmethod
    def yellow(cls, s):   return cls._w("33", s)
    @classmethod
    def blue(cls, s):     return cls._w("34", s)
    @classmethod
    def magenta(cls, s):  return cls._w("35", s)
    @classmethod
    def cyan(cls, s):     return cls._w("36", s)
    @classmethod
    def grey(cls, s):     return cls._w("90", s)

    @classmethod
    def c256(cls, n: int, s: str) -> str:
        return f"\033[38;5;{n}m{s}\033[0m" if cls.enabled else s


def status_colour(code) -> str:
    if code is None or code == "":
        return C.grey("---")
    try:
        code = int(code)
    except (TypeError, ValueError):
        return C.grey("---")
    text = str(code)
    if 200 <= code < 300: return C.green(text)
    if 300 <= code < 400: return C.cyan(text)
    if 400 <= code < 500: return C.yellow(text)
    if 500 <= code < 600: return C.red(text)
    return C.grey(text)


# ---------------------------------------------------------------- helpers

def fmt_dur(seconds: float) -> str:
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h:d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"


def fmt_int(n) -> str:
    try:
        return f"{int(n):,}"
    except (TypeError, ValueError):
        return "0"


def fmt_bytes(n) -> str:
    if n is None or n == "":
        return "-"
    try:
        n = int(n)
    except (TypeError, ValueError):
        return "-"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n}B"


def progress_bar(pct: float, width: int = 26) -> str:
    pct = max(0.0, min(1.0, pct))
    filled = int(width * pct)
    if UNICODE_OK:
        return "\u2588" * filled + "\u2591" * (width - filled)
    return "#" * filled + "." * (width - filled)


SPIN_U = "\u280b\u2819\u2839\u2838\u283c\u2834\u2826\u2827\u2807\u280f"
SPIN_A = "|/-\\"


def spinner_frame(t: float) -> str:
    pool = SPIN_U if UNICODE_OK else SPIN_A
    return pool[int(t * 8) % len(pool)]


def sanitize_csv_cell(v) -> str:
    if v is None:
        return ""
    s = str(v)
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + s
    return s


def count_lines(path: Path) -> int:
    n = 0
    try:
        with open(path, "rb") as f:
            for _ in f:
                n += 1
    except OSError:
        pass
    return n


def stage_fingerprint(*files) -> str:
    h = hashlib.sha256()
    for f in files:
        if f is None:
            h.update(b"<none>")
            continue
        try:
            with open(f, "rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    h.update(chunk)
        except (OSError, TypeError):
            h.update(b"<missing>")
    return h.hexdigest()


def atomic_write(path: Path, data: str):
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(data, encoding="utf-8")
    os.replace(tmp, path)


def read_marker(path: Path):
    try:
        parts = path.read_text(encoding="utf-8").splitlines()
        return parts[0] if parts else None
    except OSError:
        return None


# ---------------------------------------------------------------- display

class LiveDisplay:
    def __init__(self, enabled: bool = True):
        self.enabled = enabled and sys.stdout.isatty()
        self.lock = threading.Lock()
        self.last_len = 0

    def _clear_locked(self):
        if self.last_len:
            sys.stdout.write("\r" + " " * self.last_len + "\r")
            self.last_len = 0

    def update(self, text: str):
        if not self.enabled:
            return
        with self.lock:
            self._clear_locked()
            sys.stdout.write(text)
            sys.stdout.flush()
            self.last_len = len(ANSI_RE.sub("", text))

    def line(self, text: str = ""):
        with self.lock:
            if self.enabled:
                self._clear_locked()
            sys.stdout.write(text + "\n")
            sys.stdout.flush()
            self.last_len = 0

    def finish(self):
        with self.lock:
            self._clear_locked()
            sys.stdout.flush()


class Ticker(threading.Thread):
    def __init__(self, display: LiveDisplay, render, interval: float = 0.12):
        super().__init__(daemon=True)
        self.display = display
        self.render = render
        self.interval = interval
        self.stop_event = threading.Event()

    def run(self):
        start = time.time()
        while not self.stop_event.wait(self.interval):
            elapsed = time.time() - start
            self.display.update(self.render(elapsed, spinner_frame(elapsed)))

    def __enter__(self):
        if self.display.enabled:
            self.start()
        return self

    def __exit__(self, *exc):
        self.stop_event.set()
        if self.is_alive():
            self.join(timeout=2)
        self.display.finish()


# ---------------------------------------------------------------- procs

ACTIVE_PROCS: set = set()
ACTIVE_LOCK = threading.Lock()


def _register(proc):
    with ACTIVE_LOCK:
        ACTIVE_PROCS.add(proc)


def _unregister(proc):
    with ACTIVE_LOCK:
        ACTIVE_PROCS.discard(proc)


def _kill_proc_tree(proc):
    try:
        if proc.poll() is not None:
            return
    except Exception:
        return
    try:
        pgid = os.getpgid(proc.pid)
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def stream_process(cmd, on_segment=None, timeout=None, log=None):
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
        start_new_session=True,
    )
    _register(proc)
    start = time.time()
    buf = b""
    timed_out = False
    try:
        while True:
            if timeout and (time.time() - start) > timeout:
                log and log("timeout reached, killing process group")
                timed_out = True
                _kill_proc_tree(proc)
                break
            try:
                ready, _, _ = select.select([proc.stdout], [], [], 0.5)
            except (OSError, ValueError):
                break
            if not ready:
                if proc.poll() is not None:
                    break
                continue
            chunk = proc.stdout.read(4096)
            if not chunk:
                break
            buf += chunk
            segments = re.split(rb"[\r\n]", buf)
            buf = segments.pop()
            for seg in segments:
                text = seg.decode("utf-8", "replace").strip()
                if text and on_segment:
                    on_segment(text)
        if buf.strip() and on_segment:
            on_segment(buf.decode("utf-8", "replace").strip())
    finally:
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _kill_proc_tree(proc)
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
        _unregister(proc)
    return 124 if timed_out else proc.returncode


# ---------------------------------------------------------------- ffuf parse

PROG_RE = re.compile(
    r":: Progress: \[(\d+)/(\d+)\] :: Job \[\d+/\d+\] :: "
    r"(\d+) req/sec :: Duration: \[([\d:]+)\] :: Errors: (\d+) ::"
)

RESULT_RE = re.compile(
    r"^(?P<url>\S+)\s+\[Status:\s*(?P<status>\d+),\s*Size:\s*(?P<size>\d+),"
    r"\s*Words:\s*(?P<words>\d+),\s*Lines:\s*(?P<lines>\d+)"
    r"(?:,\s*Duration:\s*[\d.]+\s*(?:ms|s))?\]"
)

# puredns progress line (after ANSI stripping), e.g.:
# [ETA 05:33:19] |█░░░░░░| 150/3000001 rate: 150 qps (time: 00:00:00)
PUREDNS_PROG_RE = re.compile(
    r"\[ETA\s+([\d:]+)\].*?(\d+)/(\d+)\s+rate:\s+(\d+)\s+qps"
)


def parse_ffuf_json(path: Path):
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    out = []
    for r in data.get("results", []):
        url = r.get("url") or ""
        title = ""
        scraper = r.get("scraper") or {}
        if isinstance(scraper.get("title"), list) and scraper["title"]:
            title = scraper["title"][0]
        out.append({
            "url": url,
            "status": r.get("status", r.get("status_code")),
            "length": r.get("length", r.get("content_length")),
            "words": r.get("words", r.get("content_words")),
            "lines": r.get("lines", r.get("content_lines")),
            "content_type": r.get("content-type", r.get("content_type", "")),
            "title": title,
        })
    return out


# ---------------------------------------------------------------- input

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def normalise_domain(raw: str):
    d = raw.strip()
    if not d or d.startswith("#"):
        return None
    d = re.sub(r"^[a-zA-Z]+://", "", d)
    d = d.split("/")[0].split("?")[0]
    d = d.strip().strip(".").lower()
    if not d or not DOMAIN_RE.match(d):
        return None
    return d


def load_domains(path: Path):
    seen, out = set(), []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        d = normalise_domain(line)
        if d and d not in seen:
            seen.add(d)
            out.append(d)
    return out


def load_lines(path: Path):
    if not path.exists():
        return []
    return [l.strip() for l in
            path.read_text(encoding="utf-8", errors="replace").splitlines()
            if l.strip() and not l.startswith("#")]


def root_of(host: str, roots_set: set) -> str:
    parts = host.split(".")
    for i in range(len(parts)):
        candidate = ".".join(parts[i:])
        if candidate in roots_set:
            return candidate
    return ""


# ---------------------------------------------------------------- stages

def build_puredns_cmd(args, batch, out: Path):
    cmd = [args.puredns_bin, "bruteforce", str(args.wordlist)]
    cmd += [str(d) for d in batch]
    cmd += ["-r", str(args.resolvers), "-w", str(out)]
    if args.massdns_bin:
        cmd += ["--bin", args.massdns_bin]
    if args.wildcard_tests:
        cmd += ["--wildcard-tests", str(args.wildcard_tests)]
    if args.skip_wildcard:
        cmd.append("--skip-wildcard-filter")
    if args.skip_validation:
        cmd.append("--skip-validation")
    if args.rate_limit_trusted:
        cmd += ["--rate-limit-trusted", str(args.rate_limit_trusted)]
    # v1.0.1: use --dns-rate (default 0 = unlimited) instead of --rate
    if args.dns_rate:
        cmd += ["--rate-limit", str(args.dns_rate)]
    return cmd


def run_puredns(args, paths, domains, display, log):
    stage1: Path = paths["stage1"]
    batches = [domains[i:i + PUREDNS_BATCH]
               for i in range(0, len(domains), PUREDNS_BATCH)]
    if not batches:
        return 0

    if args.dry_run:
        for idx, batch in enumerate(batches):
            out = paths["work"] / f"resolved-{idx}.txt"
            cmd = build_puredns_cmd(args, batch, out)
            display.line(C.bold("[dry-run] ") + " ".join(cmd))
        return 0

    if stage1.exists():
        stage1.unlink()

    workers = max(1, args.workers)
    done = [0]
    total_resolved = [0]
    progress = {}                       # batch_idx -> (cur, total, qps, eta)
    last_line = [""]
    last_line_time = [0.0]
    lock = threading.Lock()

    def run_batch(idx, batch):
        out = paths["work"] / f"resolved-{idx}.txt"
        if out.exists():
            out.unlink()
        cmd = build_puredns_cmd(args, batch, out)

        def on_line(line):
            clean = ANSI_RE.sub("", line).strip()
            if clean:
                with lock:
                    last_line[0] = clean
                    last_line_time[0] = time.time()
            m = PUREDNS_PROG_RE.search(clean)
            if m:
                eta, cur, tot, qps = m.groups()
                with lock:
                    progress[idx] = (int(cur), int(tot), int(qps), eta)
            log(f"puredns: {line}")

        rc = stream_process(cmd, on_line,
                            timeout=args.max_runtime, log=log)
        n = 0
        if out.exists():
            n = sum(1 for l in out.read_text(
                encoding="utf-8", errors="replace").splitlines() if l.strip())
        with lock:
            done[0] += 1
            total_resolved[0] += n
        return out, rc

    def render(elapsed, frame):
        with lock:
            d = done[0]
            tr = total_resolved[0]
            prog = dict(progress)
            ll = last_line[0]
            ll_age = time.time() - last_line_time[0]

        # Aggregate across all in-flight batches
        cur_total = sum(p[0] for p in prog.values())
        grand_total = sum(p[1] for p in prog.values())
        qps = sum(p[2] for p in prog.values())
        eta = ""
        if prog:
            etas = [p[3] for p in prog.values() if p[3]]
            if etas:
                # show the slowest ETA
                def _key(s):
                    parts = s.split(":")
                    if len(parts) == 3:
                        h, m, sec = (int(x) for x in parts)
                    else:
                        h, m, sec = 0, int(parts[0]), int(parts[1])
                    return h * 3600 + m * 60 + sec
                eta = max(etas, key=_key)

        base = (f"{C.magenta(frame)} {C.bold('puredns')} ")
        if grand_total > 0:
            pct = cur_total / grand_total
            return (base
                    + f"{progress_bar(pct, 18)} {pct*100:5.1f}%  "
                    + f"{fmt_int(cur_total)}/{fmt_int(grand_total)}  "
                    + f"{qps} qps  ETA {eta or '--:--:--'}  "
                    + f"{C.cyan(fmt_int(tr))} resolved  "
                    + f"batch {min(d+1, len(batches))}/{len(batches)}")

        # No progress line yet (startup) — show what we know
        suffix = ""
        if ll and ll_age < 4:
            suffix = f" {C.grey('| ' + ll[:50])}"
        return (base
                + f"batch {min(d+1, len(batches))}/{len(batches)} "
                + f"| {fmt_dur(elapsed)} | "
                + f"{C.cyan(fmt_int(tr))} resolved" + suffix)

    all_rc = 0
    stage_files = []
    with Ticker(display, render):
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(run_batch, i, b)
                       for i, b in enumerate(batches)]
            for fut in as_completed(futures):
                try:
                    out, rc = fut.result()
                except Exception as exc:
                    log(f"puredns batch error: {exc}")
                    all_rc = 1
                    continue
                if rc != 0:
                    all_rc = rc
                stage_files.append(out)
    display.finish()

    seen = set()
    with open(stage1, "w", encoding="utf-8") as f:
        for sf in stage_files:
            if sf.exists():
                for line in sf.read_text(
                        encoding="utf-8", errors="replace").splitlines():
                    line = line.strip()
                    if line and line not in seen:
                        seen.add(line)
                        f.write(line + "\n")
    return all_rc


def build_host_probe_cmd(args, urls_file: Path, out_json: Path):
    cmd = [args.ffuf_bin, "-w", str(urls_file), "-u", "FUZZ",
           "-mc", args.mc,
           "-t", str(args.threads),
           "-timeout", str(args.timeout),
           "-H", f"User-Agent: {args.ua}",
           "-o", str(out_json), "-of", "json"]
    if args.rate:                       # --rate applies to ffuf only now
        cmd += ["-rate", str(args.rate)]
    if args.ac:
        cmd.append("-ac")
    if args.insecure:
        cmd.append("-k")
    if args.proxy:
        cmd += ["-x", args.proxy]
    return cmd


def run_ffuf_host_probe(hosts, args, paths, display, log):
    urls = []
    for h in hosts:
        urls.append(f"https://{h}")
        if not args.https_only:
            urls.append(f"http://{h}")

    urls_file: Path = paths["urls"]
    out_json: Path = paths["stage2"]
    cmd = build_host_probe_cmd(args, urls_file, out_json)

    if args.dry_run:
        display.line(C.bold("[dry-run] ") + " ".join(cmd)
                     + "  (URLs generated from stage-1 output)")
        return 0

    urls_file.write_text("\n".join(urls) + "\n", encoding="utf-8")
    if out_json.exists():
        out_json.unlink()

    state = {"done": 0, "total": len(urls), "rate": 0,
             "errors": 0, "hits": 0, "start": time.time()}
    lock = threading.Lock()

    def on_segment(seg: str):
        m = PROG_RE.search(seg)
        if m:
            with lock:
                state["done"] = int(m.group(1))
                state["total"] = max(1, int(m.group(2)))
                state["rate"] = int(m.group(3))
                state["errors"] = int(m.group(5))
            elapsed = time.time() - state["start"]
            pct = state["done"] / state["total"]
            remaining = state["total"] - state["done"]
            eta = (remaining / state["rate"]) if state["rate"] else 0
            frame = spinner_frame(elapsed)
            display.update(
                f"{C.blue(frame)} {C.bold('ffuf')} "
                f"{progress_bar(pct)} {pct*100:5.1f}%  "
                f"{fmt_int(state['done'])}/{fmt_int(state['total'])}  "
                f"{state['rate']} req/s  ETA {fmt_dur(eta)}  "
                f"err {C.yellow(str(state['errors']))}  "
                f"hits {C.green(str(state['hits']))}"
            )
            return

        m = RESULT_RE.match(seg)
        if m:
            with lock:
                state["hits"] += 1
            status = int(m.group("status"))
            display.line(
                f"  {C.green('+')} {status_colour(status)} "
                f"{fmt_bytes(int(m.group('size'))):>8}  {m.group('url')}"
            )
            return

        log(f"ffuf: {seg}")

    rc = stream_process(cmd, on_segment, timeout=args.max_runtime, log=log)
    display.finish()
    return rc


def run_ffuf_fallback(domains, args, paths, display, log):
    results = []
    done = 0
    total = max(1, len(domains))
    workers = max(1, args.workers)
    lock = threading.Lock()

    def one(domain: str):
        out_json = paths["work"] / f"fallback-{domain}.json"
        if out_json.exists():
            out_json.unlink()
        cmd = [args.ffuf_bin,
               "-w", str(args.wordlist),
               "-u", f"https://FUZZ.{domain}",
               "-mc", args.mc,
               "-t", str(args.threads),
               "-timeout", str(args.timeout),
               "-H", f"User-Agent: {args.ua}",
               "-o", str(out_json), "-of", "json", "-ac"]
        if args.rate:
            cmd += ["-rate", str(args.rate)]
        if args.insecure:
            cmd.append("-k")
        if args.proxy:
            cmd += ["-x", args.proxy]
        if args.dry_run:
            display.line(C.bold("[dry-run] ") + " ".join(cmd))
            return domain, []

        rc = stream_process(cmd, lambda s: log(f"ffuf[{domain}]: {s}"),
                            timeout=args.max_runtime, log=log)
        if rc not in (0, 1, 124):
            log(f"ffuf[{domain}] exited {rc}")
        return domain, parse_ffuf_json(out_json)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(one, d): d for d in domains}
        for fut in as_completed(futures):
            domain = futures[fut]
            try:
                _, found = fut.result()
            except Exception as exc:
                log(f"fallback error {domain}: {exc}")
                found = []
            with lock:
                done += 1
                results.extend((domain, r) for r in found)
            frame = spinner_frame(time.time())
            display.update(
                f"{C.blue(frame)} {C.bold('ffuf')} fallback "
                f"{progress_bar(done/total)} {done}/{total} domains | "
                f"{C.green(str(len(results)))} hits"
            )
            for r in found:
                display.line(
                    f"  {C.green('+')} {status_colour(r['status'])} "
                    f"{fmt_bytes(r['length']):>8}  {r['url']}"
                )
    display.finish()
    return results


# ---------------------------------------------------------------- output

def build_rows(resolved_hosts, ffuf_rows, roots_set):
    rows = {}
    for h in resolved_hosts:
        rows[h] = {
            "host": h,
            "root_domain": root_of(h, roots_set),
            "http_status": "", "content_length": "", "words": "",
            "lines": "", "url": "", "content_type": "", "title": "",
            "source": "dns",
        }
    for r in ffuf_rows:
        url = r.get("url", "") or ""
        host = urlsplit(url).hostname or ""
        if not host:
            continue
        existing = rows.get(host)
        if existing and existing.get("source") == "http":
            if not (url.startswith("https://")
                    and not (existing.get("url") or "").startswith("https://")):
                continue
        row = existing or {
            "host": host,
            "root_domain": root_of(host, roots_set),
            "http_status": "", "content_length": "", "words": "",
            "lines": "", "url": "", "content_type": "", "title": "",
            "source": "http",
        }
        row.update({
            "http_status": r.get("status", ""),
            "content_length": r.get("length", ""),
            "words": r.get("words", ""),
            "lines": r.get("lines", ""),
            "url": url,
            "content_type": r.get("content_type", "") or "",
            "title": (r.get("title") or "")[:120],
            "source": "http",
        })
        rows[host] = row
    return sorted(rows.values(), key=lambda x: (x["root_domain"], x["host"]))


FIELDS = ["host", "root_domain", "http_status", "content_length", "words",
          "lines", "url", "content_type", "title", "source"]

CSV_SANITIZE = {"host", "root_domain", "url", "content_type", "title"}


def write_output(rows, out: Path, fmt: str):
    out.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        atomic_write(out, json.dumps(rows, indent=2) + "\n")
    elif fmt == "txt":
        atomic_write(out, "\n".join(r["host"] for r in rows) + "\n")
    else:
        tmp = out.with_suffix(out.suffix + ".tmp")
        with open(tmp, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=FIELDS)
            writer.writeheader()
            for r in rows:
                safe = {k: (sanitize_csv_cell(v) if k in CSV_SANITIZE else v)
                        for k, v in r.items()}
                writer.writerow(safe)
        os.replace(tmp, out)


def print_summary(rows, args, elapsed, paths, ffuf_only=False):
    total = len(rows)
    http = [r for r in rows if r["source"] == "http"]
    dns_only = total - len(http)
    by_status = {}
    for r in http:
        try:
            s = int(r["http_status"])
        except (TypeError, ValueError):
            s = 0
        bucket = f"{s // 100}xx" if s else "???"
        by_status[bucket] = by_status.get(bucket, 0) + 1

    if UNICODE_OK:
        tl, tr, bl, br, h, v = "\u256d", "\u256e", "\u2570", "\u256f", "\u2500", "\u2502"
    else:
        tl, tr, bl, br, h, v = "+", "+", "+", "+", "-", "|"

    W = 54
    print()
    print(C.grey(tl + h * W + tr))
    print(C.grey(v) + C.bold(f"  {'SUMMARY':<{W - 2}}") + C.grey(v))
    print(C.grey("+" + h * W + "+"))

    def row(label, value, colour=str):
        left = f"  {label:<22}"
        right = f"{value:>28}"
        print(C.grey(v) + left + colour(right) + C.grey("  " + v))

    row("input domains", fmt_int(len(paths["domains"])))
    row("wordlist entries", fmt_int(paths["wordlist_lines"]))
    if ffuf_only:
        row("HTTP live", fmt_int(len(http)), C.green)
    else:
        row("DNS resolved", fmt_int(total), C.cyan)
        row("HTTP live", fmt_int(len(http)), C.green)
        row("DNS only (no HTTP)", fmt_int(dns_only), C.yellow)
    for bucket in sorted(by_status):
        row(f"  status {bucket}", fmt_int(by_status[bucket]),
            C.green if bucket == "2xx" else C.yellow)
    row("elapsed", fmt_dur(elapsed), C.magenta)
    print(C.grey(bl + h * W + br))
    arrow = "\u2192" if UNICODE_OK else "->"
    print(f"  results {arrow} {C.bold(str(args.output))}")
    if paths["work"].exists():
        print(f"  workdir {arrow} {C.grey(str(paths['work']))}")


# ---------------------------------------------------------------- banner

def show_banner(animate: bool = True):
    if not sys.stdout.isatty() and os.environ.get("FUZZY_FORCE_BANNER") != "1":
        return

    W = 44
    title = "F U Z Z Y"

    if UNICODE_OK:
        tl, tr, bl, br, h, v = "\u256d", "\u256e", "\u2570", "\u256f", "\u2500", "\u2502"
    else:
        tl, tr, bl, br, h, v = "+", "+", "+", "+", "-", "|"

    indent = "  "
    inner = W + 2

    top = tl + h * W + tr
    mid = v + title.center(W) + v
    bot = bl + h * W + br

    for line in (top, mid, bot):
        print(indent + C.cyan(line))

    l1 = "Multi-Domain Subdomain Reconnaissance"
    pad_l = max(0, (inner - len(l1)) // 2)
    pad_r = max(0, inner - len(l1) - pad_l)
    print(indent + " " * pad_l + C.cyan(l1) + " " * pad_r)

    part_a, sep, part_b = "Puredns x Ffuf", "  |  ", "By Kalmux"
    l2 = part_a + sep + part_b
    pad_l = max(0, (inner - len(l2)) // 2)
    pad_r = max(0, inner - len(l2) - pad_l)
    print(indent + " " * pad_l
          + C.magenta(part_a) + C.grey(sep) + C.yellow(part_b)
          + " " * pad_r)

    print()

    if animate and sys.stdout.isatty():
        msg = "  initialising pipeline"
        sys.stdout.write(C.cyan(msg))
        sys.stdout.flush()
        for _ in range(2):
            for dots in (".", "..", "..."):
                sys.stdout.write("\r" + C.cyan(msg + dots))
                sys.stdout.flush()
                time.sleep(0.10)
        sys.stdout.write("\r" + " " * (len(msg) + 4) + "\r")
        sys.stdout.flush()


# ---------------------------------------------------------------- CLI

def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="fuzzy",
        description=("FUZZY - enumerate subdomains across a list of domains "
                     "using puredns (DNS) + ffuf (HTTP liveness)."),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  fuzzy -i scope.txt -w n0kovo_subdomains.txt -o results.csv
  fuzzy -i scope.txt -w words.txt -o out.json --format json --https-only
  fuzzy -i scope.txt -w words.txt -o out.csv --ffuf-only --workers 8
  fuzzy -i scope.txt -w words.txt -o out.csv --resume
  fuzzy -i scope.txt -w words.txt -o out.csv --dry-run
""",
    )

    req = p.add_argument_group("required")
    req.add_argument("-i", "--input", required=True, type=Path,
                     help="file with target domains, one per line")
    req.add_argument("-w", "--wordlist", required=True, type=Path,
                     help="subdomain wordlist")
    req.add_argument("-o", "--output", required=True, type=Path,
                     help="single output file")

    eng = p.add_argument_group("engine")
    eng.add_argument("-r", "--resolvers", type=Path,
                     help="puredns resolver list (default: auto-detect)")
    eng.add_argument("--puredns-bin", default="puredns",
                     help="puredns binary name (default: puredns)")
    eng.add_argument("--ffuf-bin", default="ffuf",
                     help="ffuf binary name (default: ffuf)")
    eng.add_argument("--massdns-bin",
                     help="explicit massdns path for puredns")
    eng.add_argument("--ffuf-only", action="store_true",
                     help="skip puredns; brute-force each domain with ffuf "
                          "(slow fallback)")
    eng.add_argument("--puredns-only", action="store_true",
                     help="DNS stage only, no HTTP probing")
    eng.add_argument("--download-resolvers", action="store_true",
                     help="fetch the trickest resolver list if none is found")

    perf = p.add_argument_group("performance")
    perf.add_argument("--dns-rate", type=int, default=0,
                      help="puredns DNS rate limit in qps "
                           "(default 0 = unlimited, let massdns fly)")
    perf.add_argument("--rate", type=int, default=150,
                      help="ffuf HTTP rate limit in qps (default 150)")
    perf.add_argument("-t", "--threads", type=int, default=100,
                      help="ffuf threads per process (default 100)")
    perf.add_argument("--timeout", type=int, default=5,
                      help="ffuf per-request timeout seconds (default 5)")
    perf.add_argument("--workers", type=int, default=4,
                      help="parallel puredns batches / domains (default 4)")
    perf.add_argument("--max-runtime", type=int, default=0,
                      help="hard cap per tool invocation, seconds (0=off)")

    dns = p.add_argument_group("puredns tuning")
    dns.add_argument("--wildcard-tests", type=int, default=0,
                     help="puredns --wildcard-tests (raise for load-balanced DNS)")
    dns.add_argument("--skip-wildcard", action="store_true",
                     help="disable wildcard filtering (--skip-wildcard-filter)")
    dns.add_argument("--skip-validation", action="store_true",
                     help="skip puredns validation step")
    dns.add_argument("--rate-limit-trusted", type=int, default=0,
                     help="puredns --rate-limit-trusted (0 = puredns default 500)")

    http = p.add_argument_group("http probing")
    http.add_argument("--https-only", action="store_true",
                      help="probe only https:// (skip http:// pass)")
    http.add_argument("--mc", default="200,204,301,302,307,401,403,405",
                      help="ffuf status-code matcher")
    http.add_argument("--ua", default=DEFAULT_UA,
                      help="User-Agent header sent by ffuf")
    http.add_argument("--ac", action="store_true",
                      help="enable ffuf auto-calibration for host probing")
    http.add_argument("--proxy",
                      help="upstream proxy for ffuf (-x)")
    http.add_argument("-k", "--insecure", action="store_true",
                      help="skip TLS verification in ffuf")

    out = p.add_argument_group("output / runtime")
    out.add_argument("--format", choices=("csv", "json", "txt"), default="csv",
                     help="output format (default csv)")
    out.add_argument("--resume", action="store_true",
                     help="reuse completed stages from the work directory")
    out.add_argument("--clean", action="store_true",
                     help="remove the work directory on success")
    out.add_argument("--log", type=Path,
                     help="debug log path (default: <output>.log)")
    out.add_argument("--debug", action="store_true",
                     help="print raw subprocess output to stderr")
    out.add_argument("--quiet", action="store_true",
                     help="suppress banner and live display")
    out.add_argument("--no-banner", action="store_true",
                     help="suppress banner only (keep live display)")
    out.add_argument("--dry-run", action="store_true",
                     help="print commands that would be run, don't execute")
    out.add_argument("--version", action="version",
                     version=f"%(prog)s {VERSION}  by {AUTHOR}")
    return p.parse_args(argv)


# ---------------------------------------------------------------- main

def find_resolvers(args, display, log):
    if args.resolvers:
        if not (args.resolvers.is_file() and args.resolvers.stat().st_size > 0):
            display.line(C.red(
                f"[!] resolvers file is missing or empty: {args.resolvers}"))
            return None
        return args.resolvers
    candidates = [
        Path.home() / ".config/fuzzy/resolvers.txt",
        Path("resolvers.txt"),
        Path.home() / ".config/puredns/resolvers.txt",
    ]
    for c in candidates:
        if c and c.is_file() and c.stat().st_size > 0:
            return c
    if args.download_resolvers:
        target = Path.home() / ".config/fuzzy/resolvers.txt"
        target.parent.mkdir(parents=True, exist_ok=True)
        display.line(C.cyan(f"  [*] downloading resolvers -> {target}"))
        try:
            req = Request(RESOLVER_URL, headers={"User-Agent": DEFAULT_UA})
            with urlopen(req, timeout=30) as resp:
                data = resp.read()
            lines = [l.strip() for l in data.decode("utf-8", "replace")
                     .splitlines() if l.strip() and not l.startswith("#")]
            valid = [l for l in lines if re.match(r"^[0-9a-fA-F:.]+:\d+$", l)]
            if len(valid) < 10:
                display.line(C.red("[!] downloaded resolver file looks invalid"))
                return None
            target.write_text("\n".join(valid) + "\n", encoding="utf-8")
        except Exception as exc:
            display.line(C.red(f"[!] resolver download failed: {exc}"))
            return None
        return target
    return None


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    suppress_banner = any(a in argv for a in ("--no-banner", "--quiet"))
    if not suppress_banner:
        fast = any(a in argv for a in ("-h", "--help", "--version", "--dry-run"))
        show_banner(animate=not fast)

    args = parse_args(argv)
    args.workers = max(1, args.workers)
    args.threads = max(1, args.threads)
    start = time.time()

    log_handle = [None]

    def log(msg: str):
        if args.debug:
            print(C.grey(f"  [dbg] {msg}"), file=sys.stderr)
        if log_handle[0] is None and args.log:
            try:
                log_handle[0] = open(args.log, "a", encoding="utf-8")
            except OSError:
                return
        if log_handle[0]:
            try:
                log_handle[0].write(f"[{time.strftime('%H:%M:%S')}] {msg}\n")
                log_handle[0].flush()
            except OSError:
                pass

    display = LiveDisplay(enabled=not args.quiet)
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if args.log is None:
        args.log = output.with_suffix(output.suffix + ".log")

    if args.ffuf_only and args.puredns_only:
        display.line(C.red("[!] --ffuf-only and --puredns-only are mutually exclusive"))
        return 1
    if not args.input.is_file():
        display.line(C.red(f"[!] input file not found: {args.input}"))
        return 1
    if not args.wordlist.is_file():
        display.line(C.red(f"[!] wordlist not found: {args.wordlist}"))
        return 1

    domains = load_domains(args.input)
    if not domains:
        display.line(C.red("[!] no valid domains in the input file"))
        return 1
    wordlist_lines = count_lines(args.wordlist)
    if wordlist_lines < 1000:
        display.line(C.yellow(
            f"  [!] wordlist has only {fmt_int(wordlist_lines)} entries - "
            "n0kovo's list should be >1M. Re-download it."))

    if not args.ffuf_only and shutil.which(args.puredns_bin) is None:
        display.line(C.yellow(
            f"  [!] '{args.puredns_bin}' not found - falling back to ffuf-only"))
        args.ffuf_only = True
    if shutil.which(args.ffuf_bin) is None and not args.puredns_only:
        display.line(C.red(f"[!] '{args.ffuf_bin}' not found in PATH"))
        return 1

    if not args.ffuf_only:
        resolvers = find_resolvers(args, display, log)
        if resolvers is None:
            display.line(C.red("[!] no resolvers found. Pass -r resolvers.txt "
                               "or use --download-resolvers"))
            return 1
        args.resolvers = resolvers

    work = output.parent / f".{output.name}.work"
    work.mkdir(parents=True, exist_ok=True)
    paths = {
        "work": work,
        "stage1": work / "resolved.txt",
        "urls": work / "urls.txt",
        "stage2": work / "http.json",
        "domains": domains,
        "wordlist_lines": wordlist_lines,
    }
    args.scope_file = args.input.resolve()

    marker1 = work / "stage1.ok"
    marker2 = work / "stage2.ok"

    if args.dry_run:
        if not args.ffuf_only:
            run_puredns(args, paths, domains, display, log)
        if not args.puredns_only:
            if args.ffuf_only:
                run_ffuf_fallback(domains, args, paths, display, log)
            else:
                cmd = build_host_probe_cmd(args, paths["urls"], paths["stage2"])
                display.line(C.bold("[dry-run] ") + " ".join(cmd)
                             + "  (URLs generated from stage-1 output)")
        display.line(C.bold("[dry-run] no files written"))
        return 0

    fp = stage_fingerprint(args.input, args.wordlist, args.resolvers)
    exit_code = 0

    if not args.ffuf_only:
        reuse = (args.resume and marker1.exists()
                 and read_marker(marker1) == fp
                 and paths["stage1"].exists())
        if reuse:
            display.line(C.grey("  [=] reusing stage 1 (DNS) results"))
        else:
            display.line(C.bold("  [1/2] DNS brute-force - puredns"))
            if args.dns_rate == 0:
                display.line(C.grey(
                    "        DNS rate: unlimited (pass --dns-rate N to cap)"))
            else:
                display.line(C.grey(
                    f"        DNS rate: {args.dns_rate} qps"))
            rc = run_puredns(args, paths, domains, display, log)
            if rc != 0:
                display.line(C.yellow(f"  [!] puredns exited {rc}"))
            if (rc == 0 and paths["stage1"].exists()
                    and paths["stage1"].stat().st_size > 0):
                atomic_write(marker1, f"{fp}\n{time.time()}\n")
            elif rc != 0:
                exit_code = 2

    if args.ffuf_only:
        resolved_hosts = []
    else:
        resolved_hosts = sorted({
            d for d in (normalise_domain(l) for l in load_lines(paths["stage1"]))
            if d
        })
        display.line(C.cyan(
            f"  [*] {fmt_int(len(resolved_hosts))} subdomains resolved via DNS"))
        if not resolved_hosts:
            display.line(C.yellow("  [!] DNS stage produced no hosts"))
            if exit_code == 0:
                exit_code = 2

    ffuf_rows = []
    if not args.puredns_only and not args.ffuf_only:
        if not resolved_hosts:
            pass
        elif (args.resume and marker2.exists()
              and read_marker(marker2) == fp
              and paths["stage2"].exists()):
            display.line(C.grey("  [=] reusing stage 2 (HTTP) results"))
            ffuf_rows = parse_ffuf_json(paths["stage2"])
        else:
            display.line(C.bold("  [2/2] HTTP probe - ffuf"))
            rc = run_ffuf_host_probe(resolved_hosts, args, paths, display, log)
            if rc not in (0, 1):
                display.line(C.yellow(f"  [!] ffuf exited {rc}"))
                exit_code = exit_code or 2
            ffuf_rows = parse_ffuf_json(paths["stage2"])
            if rc in (0, 1) and paths["stage2"].exists():
                atomic_write(marker2, f"{fp}\n{time.time()}\n")
    elif args.ffuf_only:
        display.line(C.bold("  [1/1] ffuf-only per-domain bruteforce "
                            f"({fmt_int(len(domains))} domains)"))
        pairs = run_ffuf_fallback(domains, args, paths, display, log)
        ffuf_rows = [r for _, r in pairs]

    resolved_set = set(resolved_hosts or [])
    for r in ffuf_rows:
        h = urlsplit(r.get("url", "")).hostname
        if h:
            resolved_set.add(h)

    roots_set = set(domains)
    rows = build_rows(resolved_set, ffuf_rows, roots_set)

    write_output(rows, output, args.format)
    print_summary(rows, args, time.time() - start, paths,
                  ffuf_only=args.ffuf_only)

    if log_handle[0]:
        try:
            log_handle[0].close()
        except OSError:
            pass

    if args.clean:
        shutil.rmtree(work, ignore_errors=True)
        display.line(C.grey(f"  [*] removed work directory {work}"))

    return exit_code


def _sigint(_signum, _frame):
    with ACTIVE_LOCK:
        procs = list(ACTIVE_PROCS)
    for p in procs:
        _kill_proc_tree(p)
    raise KeyboardInterrupt


if __name__ == "__main__":
    signal.signal(signal.SIGINT, _sigint)
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(C.yellow("\n[!] interrupted - partial work kept in the work dir"))
        sys.exit(130)
    except BrokenPipeError:
        sys.exit(1)

