# SQLi Tester

**Auto‑calibrated, scope‑aware SQL injection tester** with a same‑origin crawler, header/cookie probes, optional username enumeration, and live **[hit]** streaming.  
Designed for **education, CTFs, and authorized testing**. Supports reusing enumerated usernames across all form probes to surface auth‑bypass SQLi more reliably.

<p align="left">
  <a href="https://www.python.org/downloads/"><img alt="Python" src="https://img.shields.io/badge/python-3.9%2B-blue.svg"></a>
  <a href="./LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-green.svg"></a>
</p>

**Highlights**
> - *Auto‑calibration of timeouts, concurrency, and thresholds*
> - *Same‑origin crawler to discover pages & GET parameters*
> - *Header & cookie probing for non‑traditional sinks*
> - *Optional **username enumeration** + reuse of found usernames in **all** form probes*
> - *Real‑time ticker and live **[hit]** lines with copy‑pastable payloads*
> - *Concise confirmation stage to reduce false positives*
> - *Optional second‑order marker planting & polling*
> - *Hydra command **hint** generation for login forms*

## Table of Contents

- [Concept](#concept)
- [How It Works](#how-it-works)
- [Install](#install)
- [Quick Start](#quick-start)
- [Command Reference](#command-reference)
- [Output Guide](#output-guide)
- [Examples](#examples)
- [Performance Tips](#performance-tips)
- [Troubleshooting](#troubleshooting)
- [Known Limitations](#known-limitations)
- [Legal / Responsible Use](#legal--responsible-use)
- [Licensing](#licensing)
- [Attribution & Notes](#attribution--notes)
- [Contributing](#contributing)

## Concept

Many SQLi testers fire noisy payloads without context. This script:

1. **Calibrates** to the target (threading, timeouts, length/timing thresholds).
2. **Maps** forms and GET parameters via a small, same‑origin crawl.
3. **Probes** *fields, headers, and cookies* using tampered variants.
4. Optionally **enumerates usernames** (from SecLists, etc.) and **restarts** all form probes using those usernames.  
   Many login SQLi bypasses are username‑anchored (e.g., `user' AND '1'='1'--`), so this dramatically increases signal.
5. Streams **live hits** (with evidence & sample payload) and finally **confirms** candidates with a true/false check.

The result: concise, actionable signals with minimal false positives, optimized runtime, and human‑friendly output.

## How It Works

- **Calibration**
  - p95 latency ⇒ thread count (normal/time lanes) & timeouts
  - Content‑length median ⇒ length‑delta threshold tightened on small pages
  - Time‑based threshold (e.g., `SLEEP(5)`) detection cutoff

- **Discovery**
  - Parses **forms** from pages discovered by a **same‑origin** crawl (depth auto‑set by risk)
  - Extracts **GET param candidates** from discovered links

- **Payloads**
  - Risk‑tiered Boolean, UNION/ORDER BY, error‑based, and time‑based payloads
  - Optional OR/logic‑bypass (only with `--allow-or`)
  - Randomized **tamper/obfuscation** variants (comments, URL‑encoding, case shuffles)

- **User‑context mode** (optional)
  - If `--user-enum` finds usernames (e.g., via SecLists), the script **runs all form probes with those usernames**  
    (default: first found username; change with `--use-users N`).

- **Evidence & confirmation**
  - Signals are driven by **status flip, DB error, auth marker flip, Δlen, or delay**.
  - Confirmation replays a **true vs. false** variant to downrank false positives.

- **Second‑order option**
  - Plants a marker into a likely sink (e.g., username field), then **polls** common pages for appearance.

## Install

### Requirements

- Python **3.9+** (3.10+ recommended)
- `aiohttp`
- *(optional, recommended)* `beautifulsoup4` - improves HTML form parsing; if absent, a regex fallback is used.

### Setup

```bash
# Clone your repo
git clone https://github.com/<you>/sqli-tester.git
cd sqli-tester

# (optional) create a virtualenv
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# Install Python deps (minimal)
pip install aiohttp

# Optional, recommended (better form parsing):
pip install beautifulsoup4
````

If you prefer, you can use a `requirements.txt` with:

```
aiohttp>=3.9
# Optional but recommended:
beautifulsoup4>=4.12
```

> ***Optional tools / wordlists***
> * ***Hydra**: only used if you copy/run the suggested command (Kali: `apt install hydra`).*
> * ***SecLists**: for username enumeration (Kali: `apt install seclists`).*

## Quick Start

**Basic (risk 3, defaults)**

```bash
python3 sqli_test.py -u http://<TARGET_IP> -r 3
```

**With username enumeration (uses SecLists if present)**

```bash
python3 sqli_test.py -u http://<TARGET_IP> -r 3 --user-enum
```

**Use more enumerated users and show a Hydra hint**

```bash
python3 sqli_test.py -u http://<TARGET_IP> -r 3 --user-enum --use-users 5 --hydra-hint
```

**More tamper variants (noisier & slower)**

```bash
python3 sqli_test.py -u http://<TARGET_IP> -r 3 --variants 6
```
## Command Reference

```
-u, --url                 Target base URL (required)
-R, -r, --risk            Risk level 1..4 (default 2)
-c, --confirm             Confirm replays (default 2, range 1..5)
--rounds                  Probe rounds (default 3, max 6)
--variants                Tamper variants per payload per round (default: 1, or 2 if risk>=3)
--crawl                   Crawl depth (default auto: 2 if risk>=2 else 0)
--max-cands               Max GET param candidates (default 15)

--no-probe-headers        Disable header probing
--no-probe-cookies        Disable cookie probing
--force-threads           Override auto threads (normal lane)
--force-timeout           Override auto timeout seconds (normal lane)
--allow-or                Include OR/logic-bypass payloads (noisier)

--user-enum               Enable username enumeration before probing
--userlist                Path to username wordlist (default: auto-pick common SecLists)
--user-max                Max usernames to test during enumeration (default 500)
--use-users               How many found usernames to use across probes (default 1)

--second-order            Seconds to poll for second-order sinks (default 0=off)
--second-paths            Comma-separated paths to poll (default set includes /, /home, /logs, ...)

--hydra-hint              Print a Hydra command template for the detected login form
--debug                   Print debug calibration details
```

## Output Guide

**Setup summary** - risk, threads, timeouts, thresholds, discovered forms/params.

**Status ticker** - single line, updated every \~0.5s:

```
[~] elapsed 37.4s | total requests sent 892 | live hits 3
```

**Live hits** - streaming & copy‑pastable payloads:

```
[hit] POST / field=username user=example | Δlen | payload: example' AND '1'='1'-- -
```

Each line shows method, path, field, (optional) user, **evidence**, and a **sample payload**.

**Round summary** - per round counters & elapsed:

```
[run] 9880 req (hits:24, err:0)   [time] 2080 req (hits:0, err:0) | elapsed 148.3s | total requests sent 12499
```

**Findings (concise)** - after confirmation pass:

```
=== Findings (concise) ===
- boolean-blind at POST http://<TARGET_IP>/ field 'username' [user:example]: Δlen 1234->2143 – payload: example' AND '1'='1'-- -
==========================
```

**Interrupt** - `Ctrl+C`:

```
[!] Interrupted by user. Elapsed: 62.4s
```

## Examples

**1) Default scan**

```bash
python3 sqli_test.py -u http://<TARGET_IP> -r 3
```

**2) Enum + use top 5 users in all form probes + Hydra hint**

```bash
python3 sqli_test.py -u http://<TARGET_IP> -r 3 \
  --user-enum --use-users 5 --hydra-hint
```

**3) Aggressive obfuscation variants**

```bash
python3 sqli_test.py -u http://<TARGET_IP> -r 4 --allow-or --variants 10
```

**4) Second‑order polling (30s)**

```bash
python3 sqli_test.py -u http://<TARGET_IP> --second-order 30 --second-paths "/,/logs,/reports"
```
## Performance Tips

* **Variants** (`--variants`) multiplies requests linearly. Keep modest unless needed.
* **Risk 3** is a good default. **Risk 4 + `--allow-or`** is noisier and should be used with care.
* **Crawl depth** affects discovery cost. On large targets, cap it (e.g., `--crawl 1`).
* **Timeouts/threads** are auto‑calibrated; override only if you know the environment.

## Troubleshooting

**SSL issues with self‑signed targets**
The script uses `aiohttp.TCPConnector(ssl=False)` to avoid handshake problems. If you need strict TLS, provide a custom SSL context.

**No hits but target is known vulnerable**
Try `--allow-or` (with caution), increase `--variants`, enable `--user-enum` and raise `--use-users`.
Confirm form field naming (the parser autodetects common ones; custom names may require manual checks).

## Known Limitations

* **CSRF/anti‑bot**: Pages with CSRF tokens, nonces, or bot challenges may block probes. Token handling is not automated.
* **Multi‑step / JS‑only flows**: Complex SPA logins or multi‑step forms aren’t modeled; the script sends direct HTTP requests.
* **Strict WAFs / rate limits**: Aggressive WAFs or throttling may require tuning threads/timeouts or a lower risk level.
* **Non‑standard field names**: The parser guesses username/password fields; unusual naming may require manual confirmation.

---
---

## Legal / Responsible Use

This project is intended for **educational use, CTFs, and lawful security testing** with **explicit authorization**.
You are solely responsible for compliance with applicable laws and regulations. Respect rate limits and do not disrupt production systems.

* Do **not** use against systems you do not own or control, without written permission.
* The authors and contributors provide this software **as‑is**, **without warranty of any kind** (see MIT License disclaimer).
* This tool **does not** bundle Hydra or SecLists. It only prints command **hints** referencing common install paths.
  If you install or redistribute third‑party tools/wordlists, comply with their licenses.

## Licensing

This project is released under the **MIT License**.
See the [`LICENSE`](./LICENSE) file for full text.

## Attribution & Notes

* **Hydra**: Project by THC; licensed under GPL. This script only **prints** a Hydra command template. If you install/run Hydra, comply with its license.
* **SecLists**: MIT‑licensed wordlists. This script references common install paths; install SecLists separately.
* Thanks to the broader security community for popularizing safe Boolean/time/union examples that inform practical testing strategies.

## Contributing

Issues and PRs are welcome. **Inclusion is not guaranteed** - contributions may be reworked or declined to maintain scope, safety, or readability.

Guidelines:

* Keep PRs focused and small.
* Provide before/after examples and reasoning.
* Avoid heavy dependencies or breaking the output format.
