# FUZZY

> Multi-domain subdomain reconnaissance - puredns x ffuf.
> Author: **Kalmux** - License: MIT

Feed a domain list and a wordlist; get every discovered subdomain in one
file, with HTTP status/length/title where the host answers.

## Install

```bash
git clone https://github.com/kalmux/fuzzy.git
cd fuzzy
chmod +x install.sh fuzzy.py
./install.sh
exec $SHELL
```

`install.sh` installs:

- **python3** (required runtime)
- **ffuf** - HTTP fuzzing / host probing
- **puredns** - mass DNS brute-force with wildcard filtering
- **massdns** - DNS resolver engine used by puredns
- **resolvers list** - public resolvers at `~/.config/fuzzy/resolvers.txt`
- **`fuzzy` command** - symlinked at `~/.local/bin/fuzzy`
- **shell alias** - `alias fuzzy="~/.local/share/fuzzy/fuzzy.py"`

> If your terminal locale is not UTF-8, FUZZY automatically falls back to
> ASCII art. To enable the Unicode banner: `export LANG=en_US.UTF-8`.

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
| `--debug` | dump raw subprocess output to stderr |
| `--quiet` | suppress banner and live display |
| `--no-banner` | suppress banner only |

### Environment variables

| Variable | Effect |
|---|---|
| `FUZZY_UNICODE=1` | force Unicode banner/spinner even if locale isn't UTF-8 |
| `FUZZY_ASCII=1` | force ASCII banner/spinner |
| `NO_COLOR=1` | disable ANSI colour |

## Output

CSV columns:

```
host, root_domain, http_status, content_length, words, lines,
url, content_type, title, source
```

`source` is `dns` for hosts that only resolved (no HTTP response) and
`http` for live hosts.

## License

MIT - see [LICENSE](LICENSE).

