<div align="center">
  
```text
        ╭────────────────────────────────────────────╮
        │                 F U Z Z Y                  │
        ╰────────────────────────────────────────────╯
              Multi-Domain Subdomain Reconnaissance
                  Puredns x Ffuf  |  By Kalmux
```

</div>

> **Multi-domain subdomain reconnaissance pipeline** — puredns (DNS) × ffuf (HTTP).
> Author: **Kalmux** · License: **MIT** · Version: **1.0.0**

<br>

Feed FUZZY a file of domains and a wordlist. It resolves every `word.domain`
combination via mass DNS (wildcard-filtered), probes every resolved host over
HTTP/HTTPS, and writes a single merged results file with status, length, title
and source (`dns` or `http`).



---

## Table of contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
  - [One-line install](#one-line-install)
  - [massdns capabilities (Linux)](#massdns-capabilities-linux)
  - [What gets installed](#what-gets-installed)
- [Quick start](#quick-start)
- [CLI reference](#cli-reference)
  - [Required flags](#required-flags)
  - [Engine](#engine)
  - [Performance](#performance)
  - [puredns tuning](#puredns-tuning)
  - [HTTP probing](#http-probing)
  - [Output / runtime](#output--runtime)
- [Examples](#examples)
- [Environment variables](#environment-variables)
- [Output format](#output-format)
- [Work directory and `--resume`](#work-directory-and---resume)
- [Exit codes](#exit-codes)
- [How it works](#how-it-works)
- [Performance tuning](#performance-tuning)
- [Troubleshooting](#troubleshooting)
- [Security notes](#security-notes)
- [License](#license)

---

## Features

- **Multi-domain in one run** — pass a scope file with N domains; batches
  puredns into groups of 100 and runs them in parallel.
- **Wildcard-filtered DNS** — uses puredns + massdns, the fastest DNS
  brute-forcing combo available.
- **HTTP/HTTPS liveness** — ffuf probes every resolved host on both schemes
  (or `--https-only`) with a browser User-Agent.
- **Unified output** — one CSV / JSON / TXT file with `dns` and `http`
  sources merged.
- **Resumable** — fingerprint-validated stage markers; changing the input,
  wordlist or resolvers **automatically invalidates** cached stages.
- **Live display** — spinner + progress bar + per-hit line, colourised
  status codes, dims gracefully when piped or `NO_COLOR` is set.
- **Minimalist banner** — clean box, colourised info lines, UTF-8 or ASCII.
- **Real timeouts** — `--max-runtime` kills the whole process group
  (massdns children included), not just the top-level process.
- **CSV formula-injection safe** — dangerous leading characters
  (`= + - @ \t \r`) in hostnames/titles are neutralised.
- **Deterministic merge** — when both `http://` and `https://` respond,
  **https always wins**, so repeated runs produce identical output.
- **Exit codes that mean something** — non-zero on any stage failure.

---

## Requirements

| Component | Minimum | Why |
|---|---|---|
| Python | 3.8+ | Fuzzy CLI |
| ffuf | any recent build | HTTP probing |
| puredns | v2.x | DNS brute-force |
| massdns | any recent build | DNS engine used by puredns |
| **Linux or macOS** | — | Windows not supported |
| **Root or `cap_net_raw`** | — | massdns needs raw sockets |

`install.sh` installs all of the above automatically. If you prefer to install
manually, see the [Troubleshooting](#troubleshooting) section.

---

## Installation

### One-line install

```bash
git clone [https://github.com/kalmux/fuzzy.git](https://github.com/kalmux/fuzzy.git)
cd fuzzy
chmod +x install.sh fuzzy.py
./install.sh
exec $SHELL
```

### massdns capabilities (Linux)

**This is the step that trips up most users.** massdns uses raw sockets, so it
either needs **root** or the `CAP_NET_RAW` capability. The installer attempts
`setcap` automatically; if it fails, run:

```bash
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip \
     ~/.local/bin/massdns
```

Verify:

```bash
getcap ~/.local/bin/massdns
# expected:
# /home/<user>/.local/bin/massdns cap_net_admin,cap_net_bind_service,cap_net_raw=eip
```

On **macOS**, `setcap` does not exist. Run `fuzzy` as root
(`sudo fuzzy ...`) or wrap the puredns invocation in a small helper script
that uses `sudo` for massdns only.

### What gets installed

| Path | Purpose |
|---|---|
| `~/.local/share/fuzzy/fuzzy.py` | The Python CLI |
| `~/.local/bin/fuzzy` | Symlink → `fuzzy.py` |
| `~/.local/bin/ffuf` | HTTP fuzzer |
| `~/.local/bin/puredns` | DNS brute-forcer |
| `~/.local/bin/massdns` | puredns DNS engine |
| `~/.local/go/` | Go toolchain (if not already installed) |
| `~/.config/fuzzy/resolvers.txt` | Public resolver list (trickest) |
| Shell rc | Adds `~/.local/bin` to `PATH` and a `fuzzy` alias |

The installer is **idempotent** — safe to re-run. It pins:

| Tool | Default version | Override |
|---|---|---|
| Go | `1.22.5` | `GO_VERSION=1.23.0 ./install.sh` |
| ffuf | `v2.1.0` | `FFUF_VERSION=v2.1.0 ./install.sh` |
| puredns | `v2.1.6` | `PUREDNS_VERSION=v2.1.6 ./install.sh` |
| massdns | `master` (no tags upstream) | `MASSDNS_REF=<branch-or-tag> ./install.sh` |

Go downloads are **SHA-256 verified** against `go.dev/dl/...sha256`.

---

## Quick start

```bash
# 1. write a scope file
cat > scope.txt <<'EOF'
example.com
example.org
target.net
EOF

# 2. download a wordlist (n0kovo is excellent)
#    [https://github.com/n0kovo/n0kovo_subdomains](https://github.com/n0kovo/n0kovo_subdomains)

# 3. dry run first — this only prints commands, writes nothing
fuzzy -i scope.txt -w n0kovo.txt -o results.csv --dry-run

# 4. run it
fuzzy -i scope.txt -w n0kovo.txt -o results.csv

# 5. inspect results
column -s, -t < results.csv | head
```

---

## CLI reference

```
fuzzy -i INPUT -w WORDLIST -o OUTPUT [options]
```

### Required flags

| Flag | Type | Description |
|---|---|---|
| `-i, --input` | file | Target domains, one per line. `http://`, trailing `/`, and `#comments` are stripped. |
| `-w, --wordlist` | file | Subdomain wordlist (`n0kovo_subdomains.txt` recommended). |
| `-o, --output` | file | Destination results file. Parent directories are created. |

### Engine

| Flag | Default | Description |
|---|---|---|
| `-r, --resolvers` | auto | Resolver list for puredns. Auto-detected from `~/.config/fuzzy/resolvers.txt`, `./resolvers.txt`, or `~/.config/puredns/resolvers.txt`. |
| `--puredns-bin` | `puredns` | Override the puredns binary name/path. |
| `--ffuf-bin` | `ffuf` | Override the ffuf binary name/path. |
| `--massdns-bin` | auto | Explicit massdns path passed to puredns via `--bin`. |
| `--ffuf-only` | off | Skip puredns entirely; brute-force each domain with ffuf (`https://FUZZ.<domain>`). Very slow — fallback only. |
| `--puredns-only` | off | Run DNS stage only; no HTTP probing. |
| `--download-resolvers` | off | Download trickest resolvers if none are found. Output is **validated** (≥ 10 `IP:port` lines) before use. |

`--ffuf-only` and `--puredns-only` are mutually exclusive.

### Performance

| Flag | Default | Description |
|---|---|---|
| `-t, --threads` | `100` | ffuf threads per process. |
| `--rate` | `150` | Rate cap — applies to **both** ffuf (`-rate`) and puredns (`--rate-limit`). `0` = unlimited. |
| `--timeout` | `5` | ffuf per-request timeout, seconds. |
| `--workers` | `4` | Parallelism — puredns batches per stage-1 run, or parallel domains in `--ffuf-only`. |
| `--max-runtime` | `0` | **Hard wall-clock cap** for any single tool invocation. `0` = off. Uses process-group kill so massdns children die too. |

### puredns tuning

| Flag | Default | Description |
|---|---|---|
| `--wildcard-tests` | `0` | Increase (e.g. `3`) for load-balanced DNS with multiple wildcard IPs. |
| `--skip-wildcard` | off | Disable wildcard filtering (`--skip-wildcard-filter`). Only do this if you're sure. |
| `--skip-validation` | off | Skip puredns' own validation pass. Faster, noisier. |
| `--rate-limit-trusted` | `0` | `--rate-limit-trusted` for known-good resolvers. |

### HTTP probing

| Flag | Default | Description |
|---|---|---|
| `--https-only` | off | Skip the `http://` probe pass. Halves requests. |
| `--mc` | `200,204,301,302,307,401,403,405` | ffuf status-code matcher. |
| `--ua` | browser UA | User-Agent header. |
| `--ac` | off | Enable ffuf **auto-calibration** for host probing. Useful against wildcard HTTP responses. |
| `--proxy` | — | Upstream proxy (`-x` in ffuf). |
| `-k, --insecure` | off | Skip TLS verification in ffuf. |

### Output / runtime

| Flag | Default | Description |
|---|---|---|
| `--format` | `csv` | `csv`, `json`, or `txt`. |
| `--resume` | off | Reuse completed stages **when the fingerprint matches**. |
| `--clean` | off | Delete the work directory on success. |
| `--log` | `<output>.log` | Debug log path. A persistent handle is used (not reopened per line). |
| `--debug` | off | Also print raw subprocess output to stderr. |
| `--quiet` | off | Suppress banner **and** live display. |
| `--no-banner` | off | Suppress banner only; keep live display. |
| `--dry-run` | off | Print exact tool commands; **write no files**. |
| `--version` | — | Print version + author and exit. |

---

## Examples

```bash
# Standard run
fuzzy -i scope.txt -w n0kovo.txt -o results.csv

# JSON output, HTTPS only
fuzzy -i scope.txt -w n0kovo.txt -o out.json --format json --https-only

# Fallback when puredns is broken
fuzzy -i scope.txt -w n0kovo.txt -o out.csv --ffuf-only --workers 8

# DNS only — fast inventory
fuzzy -i scope.txt -w n0kovo.txt -o hosts.txt --format txt --puredns-only

# Resume after an interruption
fuzzy -i scope.txt -w n0kovo.txt -o out.csv --resume

# Hard 20-minute cap per tool invocation
fuzzy -i scope.txt -w n0kovo.txt -o out.csv --max-runtime 1200

# Through Burp
fuzzy -i scope.txt -w n0kovo.txt -o out.csv --proxy [http://127.0.0.1:8080](http://127.0.0.1:8080) -k

# Dry run — inspect exact commands before any work
fuzzy -i scope.txt -w n0kovo.txt -o out.csv --dry-run
```

---

## Environment variables

| Variable | Effect |
|---|---|
| `FUZZY_ASCII=1` | Force ASCII banner/spinner/progress bar. |
| `FUZZY_UNICODE=1` | Force Unicode regardless of locale. |
| `FUZZY_FORCE_BANNER=1` | Print the banner even when stdout is not a TTY (useful in scripts). |
| `NO_COLOR=1` | Disable all ANSI colour. |
| `FUZZY_HOME` | Override `~/.local/share/fuzzy`. |
| `FUZZY_BIN` | Override `~/.local/bin`. |
| `FUZZY_CONFIG` | Override `~/.config/fuzzy`. |
| `GO_VERSION`, `FFUF_VERSION`, `PUREDNS_VERSION`, `MASSDNS_REF` | Pin installer versions. |

---

## Output format

### CSV columns

```
host, root_domain, http_status, content_length, words, lines,
url, content_type, title, source
```

| Column | Description |
|---|---|
| `host` | The fully-qualified subdomain (`api.example.com`). |
| `root_domain` | Longest matching entry from your scope file. |
| `http_status` | HTTP status code, or empty for DNS-only. |
| `content_length` | Response body size in bytes. |
| `words` | Word count from ffuf. |
| `lines` | Line count from ffuf. |
| `url` | Full URL probed (prefers `https://`). |
| `content_type` | `Content-Type` header. |
| `title` | HTML `<title>` (truncated to 120 chars). |
| `source` | `dns` (resolved, no HTTP answer) or `http` (live). |

### JSON

An array of objects with the same keys as the CSV columns, plus native
typing (`content_length` is numeric, etc.).

### TXT

One host per line — convenient for downstream tools.

### CSV safety

Leading characters `= + - @ \t \r` in `host`, `root_domain`, `url`,
`content_type` and `title` are **prefixed with `'`** to prevent
formula injection when opened in Excel / LibreOffice / Google Sheets.

### Deterministic merging

If both `http://host` and `https://host` respond, **https wins** — so
repeated runs against the same target produce identical output regardless
of ffuf completion order.

---

## Work directory and `--resume`

Every run creates a work directory next to the output file:

```
.<output-name>.work/
├── resolved.txt          # stage 1 output (deduplicated)
├── resolved-0.txt        # per-batch raw output
├── resolved-1.txt        # …
├── urls.txt              # stage 2 input
├── http.json             # stage 2 raw ffuf output
├── stage1.ok             # marker (fingerprint + timestamp)
└── stage2.ok             # marker (fingerprint + timestamp)
```

### Fingerprint

Each marker stores a **SHA-256 fingerprint** of:

- `--input` file
- `--wordlist` file
- `--resolvers` file (if applicable)

If any of the three changes, `--resume` **automatically invalidates** the
corresponding stage and re-runs it — no more silently stale results.

### `--clean`

`--clean` removes the entire work directory **on success only**. On failure
or interrupt, it is preserved so `--resume` can pick up.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Everything ran to completion and rows were produced. |
| `1` | Preflight error — missing input/wordlist, conflicting flags, missing tool. |
| `2` | A stage failed (puredns exited non-zero, or DNS produced zero hosts). |
| `124` | `--max-runtime` triggered on some tool. |
| `130` | Interrupted (Ctrl-C); work directory preserved. |

`2` is returned even if some hosts were found — it just signals that you
shouldn't trust the results were exhaustive.

---

## How it works

### Stage 1 — DNS

```
for batch in domains[0:100], domains[100:200], …
    puredns bruteforce wordlist d1 d2 … -r resolvers -w resolved-N.txt
```

- Batched 100 domains per puredns call
- Batches run in parallel (`--workers`)
- Domains passed **positionally** — does not depend on any
  puredns `--domains-file` flag
- Results are deduplicated into `resolved.txt`

### Stage 2 — HTTP

```
for host in resolved:
    urls += https://host        (always)
    urls += http://host         (unless --https-only)

ffuf -w urls.txt -u FUZZ -mc … -t … -timeout … -o http.json -of json
```

- Live progress parsed from ffuf's `:: Progress:` lines
- Individual hits parsed from result lines (colourised by status bucket)
- Results merged into the final table with https preference

### Merge and output

1. Load stage-1 output → seed `{host: {source: "dns"}}`
2. Overlay stage-2 rows (https wins)
3. Sort by `(root_domain, host)`
4. Write CSV / JSON / TXT atomically (`.tmp` + `os.replace`)

---

## Performance tuning

| Situation | Recommendation |
|---|---|
| **n0kovo wordlist (1M+)** | Leave defaults. Run overnight for big scopes. |
| **Small scope, tiny wordlist** | `--rate 0 -t 200` |
| **Rate-limited by a WAF** | `--rate 50 -t 20 --timeout 10` |
| **Load-balanced wildcard DNS** | `--wildcard-tests 3` |
| **puredns is slow or flaky** | Lower `--workers` to `2`, raise `--max-runtime` |
| **DNS only, no HTTP** | `--puredns-only --format txt` — fast inventory |
| **`--ffuf-only` mode** | `--workers 4 --rate 200` (each ffuf worker already has `-t` threads) |
| **Massive scope (10k+ domains)** | Increase `--workers` but keep an eye on file-descriptor limits (`ulimit -n`) |

**Bottleneck order**, typically:

1. Resolvers (public DNS throttling)
2. puredns validation (well, massdns under the hood)
3. ffuf HTTP probing

Real numbers on a laptop, 1 domain × 1M-word wordlist:

- Stage 1: **3–8 min** with good resolvers
- Stage 2: **30–90 s** per 100 live hosts at `--rate 150`

---

## Troubleshooting

### `puredns exited 2 with no results`

Almost always means **massdns has no raw-socket capability**:

```bash
getcap ~/.local/bin/massdns
# fix:
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip ~/.local/bin/massdns
```

### `no resolvers found`

```bash
fuzzy -i scope.txt -w words.txt -o out.csv --download-resolvers
# or supply your own:
fuzzy -i scope.txt -w words.txt -o out.csv -r /path/to/resolvers.txt
```

### `[!] wordlist has only N entries`

Your wordlist is suspiciously small — n0kovo's is >1M. Download the full
list from https://github.com/n0kovo/n0kovo_subdomains.

### `fuzzy: command not found` after install

```bash
exec $SHELL
# or:
export PATH="$HOME/.local/bin:$PATH"
```

The installer added `~/.local/bin` to your shell rc but the current shell
doesn't see it until you reload.

### Banner shows as boxes / question marks

Your locale is not UTF-8. Either:

```bash
export LANG=en_US.UTF-8
```

or force ASCII:

```bash
export FUZZY_ASCII=1
```

### `--resume` re-runs Stage 1 even though I didn't change anything

Check that `--resolvers` points to the same file — changing resolvers
invalidates the fingerprint by design. If you want to reuse results across
resolver changes, delete the `.stage1.ok` marker or copy `resolved.txt`
first.

### `ffuf` immediately errors with `output file already exists`

Fixed in v1.0.0 (the work-directory file is unlinked before each run).
If you're on an older version, delete `.<output>.work/http.json`.

### Ctrl-C leaves massdns running

Also fixed in v1.0.0 (`SIGINT` handler kills the process group). If you
still see it, upgrade — the fix relies on `start_new_session=True` +
`os.killpg`.

---

## Security notes

- **massdns requires `cap_net_raw`.** The installer attempts `setcap`
  automatically. Review the capability before deploying in a shared
  environment — `cap_net_raw` allows the process to craft raw packets.
- **`--proxy`** forwards ffuf traffic through the URL you supply. Verify the
  proxy's TLS stripping if you care about the target's HTTPS validity.
- **`--insecure`** disables TLS verification in ffuf. Do not use against
  production systems you don't own.
- **Results file** contains full recon data. Default permissions honour
  your umask — consider `umask 077` before running on multi-user hosts.
- **Work directory** contains raw puredns + ffuf output including all
  discovered hosts and every HTTP response body's first bytes. Same
  caveat.
- **CSV output** is formula-injection hardened but not XML-injection
  hardened — opening a hostile CSV in an old viewer may still be unsafe.
- **Installer downloads** are SHA-256 verified for Go; ffuf and puredns
  are fetched via Go modules (Go verifies sums); massdns is compiled from
  source at the configured ref.

---

## Uninstall

```bash
# shell rc cleanup
sed -i.bak '/# Added by FUZZY installer/d; /# FUZZY alias/,+1d' ~/.bashrc ~/.zshrc 2>/dev/null

# binaries and data
rm -f  ~/.local/bin/fuzzy ~/.local/bin/ffuf ~/.local/bin/puredns ~/.local/bin/massdns
rm -rf ~/.local/share/fuzzy ~/.config/fuzzy
```

`~/.local/go` is shared with other Go tooling — the installer does not
touch it on uninstall.

---

## License

MIT — see [LICENSE](LICENSE).

```text
Copyright (c) 2026 Kalmux
```

---

## Author

**Kalmux** — https://github.com/kalmux/fuzzy

Contributions, issues and pull requests welcome.
