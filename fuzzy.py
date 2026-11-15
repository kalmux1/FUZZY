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
import json
import os
import re
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

VERSION = "1.0.0"
AUTHOR  = "Kalmux"
REPO    = "https://github.com/kalmux/fuzzy"

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)
RESOLVER_URL = (
    "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
)


# ---------------------------------------------------------------- unicode

def _unicode_terminal() -> bool:
    """True only when the terminal is known to render box/spinner glyphs."""
    if os.environ.get("FUZZY_ASCII") == "1":
        return False
    if os.environ.get("FUZZY_UNICODE") == "1":
        return True
    # POSIX precedence: LC_ALL > LC_CTYPE > LANG
    for var in ("LC_ALL", "LC_CTYPE", "LANG"):
        val = os.environ.get(var, "")
        if val:
            low = val.lower()
            return "utf-8" in low or "utf8" in low
    # nothing set - be safe
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
    if code is None:
        return C.grey("---")
    code = int(code)
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
    return f"{int(n):,}"


def fmt_bytes(n) -> str:
    if n is None:
        return "-"
    n = int(n)
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


class LineCounter:
    def __init__(self, path: Path):
        self.path = path
        self.offset = 0
        self.count = 0
        self.partial = b""

    def poll(self) -> int:
        try:
            with open(self.path, "rb") as f:
                f.seek(self.offset)
                chunk = f.read()
                self.offset = f.tell()
        except FileNotFoundError:
            return self.count
        if chunk:
            data = self.partial + chunk
            parts = data.split(b"\n")
            self.partial = parts.pop()
            self.count += len(parts)
        return self.count

    def total(self) -> int:
        try:
            return sum(1 for _ in open(self.path, "rb"))
        except FileNotFoundError:
            return 0


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
        self.start_time = 0.0

    def run(self):
        self.start_time = time.time()
        while not self.stop_event.wait(self.interval):
            elapsed = time.time() - self.start_time
            self.display.update(self.render(elapsed, spinner_frame(elapsed)))

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop_event.set()
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


def stream_process(cmd, on_segment=None, timeout=None, log=None):
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
        start_new_session=True,   # so we can killpg + reap massdns children
    )
    _register(proc)
    start = time.time()
    buf = b""
    try:
        while True:
            chunk = proc.stdout.read(4096)
            if not chunk:
                break
            if timeout and (time.time() - start) > timeout:
                log and log("timeout reached, killing child")
                proc.kill()
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
        rc = proc.wait()
        _unregister(proc)
    return rc


def _kill_proc_tree(proc):
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
    return [l.strip() for l in
            path.read_text(encoding="utf-8", errors="replace").splitlines()
            if l.strip() and not l.startswith("#")]


def root_of(host: str, roots):
    best = ""
    for r in roots:
        if host == r or host.endswith("." + r):
            if len(r) > len(best):
                best = r
    return best


# ---------------------------------------------------------------- stages

def run_puredns(args, paths, display: LiveDisplay, log):
    stage1: Path = paths["stage1"]
    counter = LineCounter(stage1)

    cmd = [args.puredns_bin, "bruteforce", str(args.wordlist),
           "-d", str(args.scope_file),
           "-r", str(args.resolvers),
           "-w", str(stage1), "-q"]
    if args.massdns_bin:
        cmd += ["--bin", args.massdns_bin]
    if args.wildcard_tests:
        cmd += ["--wildcard-tests", str(args.wildcard_tests)]
    if args.skip_wildcard:
        cmd.append("--skip-wildcard")
    if args.skip_validation:
        cmd.append("--skip-validation")
    if args.rate_limit_trusted:
        cmd += ["--rate-limit-trusted", str(args.rate_limit_trusted)]

    if args.dry_run:
        display.line(C.bold("[dry-run] ") + " ".join(cmd))
        return 0

    def render(elapsed, frame):
        n = counter.poll()
        return (f"{C.magenta(frame)} {C.bold('puredns')} "
                f"bruteforcing {fmt_int(len(paths['domains']))} domains "
                f"| {fmt_dur(elapsed)} | "
                f"{C.cyan(fmt_int(n))} resolved")

    with Ticker(display, render):
        rc = stream_process(cmd, lambda s: log(f"puredns: {s}"),
                            timeout=args.max_runtime)

    counter.poll()
    total = counter.total()
    if rc != 0 and total == 0:
        display.line(C.red(f"  [!] puredns exited {rc} with no results"))
    return rc


def build_host_probe_cmd(args, urls_file: Path, out_json: Path):
    cmd = [args.ffuf_bin, "-w", str(urls_file), "-u", "FUZZ",
           "-mc", args.mc,
           "-t", str(args.threads),
           "-timeout", str(args.timeout),
           "-H", f"User-Agent: {args.ua}",
           "-o", str(out_json), "-of", "json"]
    if args.rate:
        cmd += ["-rate", str(args.rate)]
    if args.ac:
        cmd.append("-ac")
    if args.insecure:
        cmd.append("-k")
    if args.proxy:
        cmd += ["-x", args.proxy]
    return cmd


def run_ffuf_host_probe(hosts, args, paths, display: LiveDisplay, log):
    urls = []
    for h in hosts:
        urls.append(f"https://{h}")
        if not args.https_only:
            urls.append(f"http://{h}")
    urls_file: Path = paths["urls"]
    urls_file.write_text("\n".join(urls) + "\n", encoding="utf-8")

    out_json: Path = paths["stage2"]
    cmd = build_host_probe_cmd(args, urls_file, out_json)

    if args.dry_run:
        display.line(C.bold("[dry-run] ") + " ".join(cmd))
        return 0

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


def run_ffuf_fallback(domains, args, paths, display: LiveDisplay, log):
    results = []
    done = 0
    total = len(domains)
    lock = threading.Lock()

    def one(domain: str):
        out_json = paths["work"] / f"fallback-{domain}.json"
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

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        _register(proc)
        try:
            try:
                proc.wait(timeout=args.max_runtime or None)
            except subprocess.TimeoutExpired:
                log(f"fallback timeout: {domain}")
                _kill_proc_tree(proc)
                proc.wait()
        finally:
            _unregister(proc)
        return domain, parse_ffuf_json(out_json)

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
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

def build_rows(domains, resolved_hosts, ffuf_rows, roots):
    rows = {}
    for h in resolved_hosts:
        rows[h] = {
            "host": h,
            "root_domain": root_of(h, roots),
            "http_status": "", "content_length": "", "words": "",
            "lines": "", "url": "", "content_type": "", "title": "",
            "source": "dns",
        }
    for r in ffuf_rows:
        url = r.get("url", "")
        host = urlsplit(url).hostname or ""
        if not host:
            continue
        row = rows.get(host) or {
            "host": host,
            "root_domain": root_of(host, roots),
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


def write_output(rows, out: Path, fmt: str):
    if fmt == "json":
        out.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    elif fmt == "txt":
        out.write_text("\n".join(r["host"] for r in rows) + "\n",
                       encoding="utf-8")
    else:
        with open(out, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows(rows)


def print_summary(rows, args, elapsed, paths):
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

    line = h * 54
    print()
    print(C.grey(tl + line + tr))
    print(C.grey(v) + C.bold("  SUMMARY").ljust(54 + 9) + C.grey(v))
    print(C.grey("+" + line + "+"))

    def row(label, value, colour=str):
        left = f"  {label:<22}"
        right = f"{value:>28}"
        print(C.grey(v) + left + colour(right) + C.grey("  " + v))

    row("input domains", fmt_int(len(paths["domains"])))
    row("wordlist entries", fmt_int(paths["wordlist_lines"]))
    row("DNS resolved", fmt_int(total), C.cyan)
    row("HTTP live", fmt_int(len(http)), C.green)
    row("DNS only (no HTTP)", fmt_int(dns_only), C.yellow)
    for bucket in sorted(by_status):
        row(f"  status {bucket}", fmt_int(by_status[bucket]),
            C.green if bucket == "2xx" else C.yellow)
    row("elapsed", fmt_dur(elapsed), C.magenta)
    print(C.grey(bl + line + br))
    arrow = "\u2192" if UNICODE_OK else "->"
    print(f"  results {arrow} {C.bold(str(args.output))}")
    if paths["work"].exists():
        print(f"  workdir {arrow} {C.grey(str(paths['work']))}")


# ---------------------------------------------------------------- banner

UNICODE_BANNER = r"""
            ███████╗██╗   ██╗███████╗███████╗██╗   ██╗
            ██╔════╝██║   ██║╚══███╔╝╚══███╔╝╚██╗ ██╔╝
            █████╗  ██║   ██║  ███╔╝   ███╔╝  ╚████╔╝ 
            ██╔══╝  ██║   ██║ ███╔╝   ███╔╝    ╚██╔╝  
            ██║     ╚██████╔╝███████╗███████╗   ██║   
            ╚═╝      ╚═════╝ ╚══════╝╚══════╝   ╚═╝   
""".strip("\n").splitlines()

ASCII_BANNER = r"""
            ______  __  __  ____  ____ __   __
            |  ___| | | | |___ \|___ \ \ \ / /
            | |_    | | | |  __) |  __) \ V / 
            |  _|   | |_| | / __/ / __/   | |  
            |_|      \___/ |_____|_____|  |_|  
""".strip("\n").splitlines()


def show_banner(animate: bool = True):
    lines = UNICODE_BANNER if UNICODE_OK else ASCII_BANNER
    palette = [51, 45, 39, 33, 27, 21]
    for i, line in enumerate(lines):
        print(C.c256(palette[i % len(palette)], line))

    tag = "multi-domain subdomain reconnaissance | puredns x ffuf"
    print(C.grey(f"  v{VERSION}  |  {tag}"))
    print(C.magenta(f"  by {AUTHOR}") + C.grey(f"  |  {REPO}"))
    print()
    if animate and sys.stdout.isatty():
        msg = "  initialising pipeline"
        sys.stdout.write(C.cyan(msg))
        for _ in range(3):
            for dots in (".", "..", "..."):
                sys.stdout.write("\r" + C.cyan(msg + dots))
                sys.stdout.flush()
                time.sleep(0.12)
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
    perf.add_argument("-t", "--threads", type=int, default=100,
                      help="ffuf threads per process (default 100)")
    perf.add_argument("--rate", type=int, default=150,
                      help="ffuf req/s cap (default 150, 0=unlimited)")
    perf.add_argument("--timeout", type=int, default=5,
                      help="ffuf per-request timeout seconds (default 5)")
    perf.add_argument("--workers", type=int, default=4,
                      help="parallel domains in --ffuf-only mode (default 4)")
    perf.add_argument("--max-runtime", type=int, default=0,
                      help="hard cap per tool invocation, seconds (0=off)")

    dns = p.add_argument_group("puredns tuning")
    dns.add_argument("--wildcard-tests", type=int, default=0,
                     help="puredns --wildcard-tests (raise for load-balanced DNS)")
    dns.add_argument("--skip-wildcard", action="store_true",
                     help="disable wildcard filtering (puredns)")
    dns.add_argument("--skip-validation", action="store_true",
                     help="skip puredns validation step")
    dns.add_argument("--rate-limit-trusted", type=int, default=0,
                     help="puredns --rate-limit-trusted value")

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
    candidates = []
    if args.resolvers:
        candidates.append(args.resolvers)
    candidates += [
        Path.home() / ".config/fuzzy/resolvers.txt",
        Path("resolvers.txt"),
        Path.home() / ".config/puredns/resolvers.txt",
    ]
    for c in candidates:
        if c and c.is_file() and c.stat().st_size > 0:
            return c
    if args.download_resolvers:
        target = args.resolvers or (Path.home() / ".config/fuzzy/resolvers.txt")
        target.parent.mkdir(parents=True, exist_ok=True)
        display.line(C.cyan(f"  [*] downloading resolvers -> {target}"))
        req = Request(RESOLVER_URL, headers={"User-Agent": DEFAULT_UA})
        with urlopen(req, timeout=30) as resp:
            target.write_bytes(resp.read())
        return target
    return None


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    # ---- banner BEFORE parse_args so -h/--version still show it ---------
    suppress_banner = any(a in argv for a in ("--no-banner", "--quiet"))
    if not suppress_banner:
        fast = any(a in argv for a in ("-h", "--help", "--version", "--dry-run"))
        show_banner(animate=not fast)

    args = parse_args(argv)
    start = time.time()

    def log(msg: str):
        if args.debug:
            print(C.grey(f"  [dbg] {msg}"), file=sys.stderr)
        if not args.log:
            return
        try:
            with open(args.log, "a", encoding="utf-8") as fh:
                fh.write(f"[{time.strftime('%H:%M:%S')}] {msg}\n")
        except OSError:
            pass

    display = LiveDisplay(enabled=not args.quiet)
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if args.log is None:
        args.log = output.with_suffix(output.suffix + ".log")

    # ---- preflight -------------------------------------------------------
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
    wordlist_lines = len(load_lines(args.wordlist))
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

    # ---- paths / state ---------------------------------------------------
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

    # ---- stage 1: DNS ----------------------------------------------------
    if not args.ffuf_only:
        if args.resume and marker1.exists() and paths["stage1"].exists():
            display.line(C.grey("  [=] reusing stage 1 (DNS) results"))
        else:
            display.line(C.bold("  [1/2] DNS brute-force - puredns"))
            rc = run_puredns(args, paths, display, log)
            if rc != 0:
                display.line(C.yellow(f"  [!] puredns exited {rc}"))
            marker1.write_text(str(time.time()))

    # ---- collect resolved hosts -----------------------------------------
    if args.ffuf_only:
        resolved_hosts = []
    else:
        resolved_hosts = sorted({
            normalise_domain(l) for l in load_lines(paths["stage1"])
        } - {None})
        display.line(C.cyan(
            f"  [*] {fmt_int(len(resolved_hosts))} subdomains resolved via DNS"))
        if not resolved_hosts:
            display.line(C.yellow("  [!] DNS stage produced no hosts"))

    # ---- stage 2: HTTP ---------------------------------------------------
    ffuf_rows = []
    if not args.puredns_only and not args.ffuf_only:
        if not resolved_hosts:
            pass
        elif args.resume and marker2.exists() and paths["stage2"].exists():
            display.line(C.grey("  [=] reusing stage 2 (HTTP) results"))
            ffuf_rows = parse_ffuf_json(paths["stage2"])
        else:
            display.line(C.bold("  [2/2] HTTP probe - ffuf"))
            rc = run_ffuf_host_probe(resolved_hosts, args, paths, display, log)
            if rc not in (0, 1):
                display.line(C.yellow(f"  [!] ffuf exited {rc}"))
            ffuf_rows = parse_ffuf_json(paths["stage2"])
            marker2.write_text(str(time.time()))
    elif args.ffuf_only:
        display.line(C.bold("  [1/1] ffuf-only per-domain bruteforce "
                            f"({fmt_int(len(domains))} domains)"))
        pairs = run_ffuf_fallback(domains, args, paths, display, log)
        ffuf_rows = [r for _, r in pairs]

    # ---- rows / output ---------------------------------------------------
    resolved_set = set(resolved_hosts or [])
    for r in ffuf_rows:
        h = urlsplit(r.get("url", "")).hostname
        if h:
            resolved_set.add(h)

    rows = build_rows(domains, resolved_set, ffuf_rows, domains)

    if args.dry_run:
        display.line(C.bold("[dry-run] no files written"))
        return 0

    write_output(rows, output, args.format)
    print_summary(rows, args, time.time() - start, paths)

    if args.clean:
        shutil.rmtree(work, ignore_errors=True)
        display.line(C.grey(f"  [*] removed work directory {work}"))

    return 0


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
