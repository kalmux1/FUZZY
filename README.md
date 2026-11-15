# FUZZY

> Multi-domain subdomain reconnaissance — puredns × ffuf.
> Author: **Kalmux** · License: MIT

Feed a domain list and a wordlist; get every discovered subdomain in one
file, with HTTP status/length/title where the host answers.

## Install

```bash
git clone https://github.com/kalmux/fuzzy.git
cd fuzzy
./install.sh
exec $SHELL
```

`install.sh` installs:

- **ffuf** — HTTP fuzzing / host probing
- **puredns** — mass DNS brute-force with wildcard filtering
- **massdns** — DNS resolver engine used by puredns
- **resolvers list** — public resolvers at `~/.config/fuzzy/resolvers.txt`
- **`fuzzy` command** — symlinked at `~/.local/bin/fuzzy`
- **shell alias** — `alias fuzzy="~/.local/share/fuzzy/fuzzy.py"`

Requires: a Debian/Fedora/Arch/macOS host with `curl`, `git`, `make`, and `gcc`
(the installer adds missing packages automatically via your package manager).

## Usage

```bash
fuzzy -i scope.txt -w ~/wordlists/n0kovo_subdomains.txt -o results.csv
fuzzy -i scope.txt -w words.txt -o out.json --format json --https-only
fuzzy -i scope.txt -w words.txt -o out.csv --resume
fuzzy --help
```

### Required

| Flag | Meaning |
|---|---|
| `-i, --input` | file of domains, one per line |
| `-w, --wordlist` | subdomain wordlist |
| `-o, --output` | single output file |

### Useful optional

| Flag | Purpose |
|---|---|
| `-r, --resolvers` | override resolver list |
| `--format csv\|json\|txt` | output format (default `csv`) |
| `--https-only` | skip the `http://` probe pass |
| `--ffuf-only` | skip puredns (slow ffuf fallback) |
| `--puredns-only` | DNS stage only, no HTTP probing |
| `--resume` | reuse already-completed stages |
| `--rate N` | ffuf req/s cap (default 150) |
| `-t N` | ffuf threads (default 100) |
| `--timeout N` | ffuf per-request timeout (default 5s) |
| `--workers N` | parallel domains in `--ffuf-only` (default 4) |
| `-k, --insecure` | skip TLS verification |
| `--dry-run` | print the exact tool commands, don't run |
| `--download-resolvers` | fetch trickest resolvers if none found |
| `--clean` | delete the work directory on success |
| `--quiet` | suppress banner and live display |

## How it works

1. **DNS stage** — `puredns bruteforce <wordlist> -d <scope.txt>` runs every
   word against every domain, resolves via `massdns`, strips wildcards, and
   validates against trusted resolvers. This is the only stage that can
   realistically chew through a multi-million-word list.
2. **HTTP stage** — `ffuf -w urls.txt -u FUZZ` probes every resolved host
   on both `https://` and `http://` to confirm liveness and capture
   status/size/title.

The output file joins both stages, so DNS-only discoveries (no HTTP
response) are still recorded.

## Output

CSV columns:

```
host, root_domain, http_status, content_length, words, lines,
url, content_type, title, source
```

`source` is `dns` for hosts that only resolved (no HTTP response) and
`http` for live hosts.

## Work directory

Intermediate files live in `.<output-name>.work/` next to the output file:

- `resolved.txt` — puredns output
- `urls.txt` — URL list fed to ffuf
- `http.json` — ffuf raw results
- `stage1.ok` / `stage2.ok` — resume markers

Use `--resume` to reuse them, or `--clean` to remove them on success.

## License

MIT — see [LICENSE](LICENSE).