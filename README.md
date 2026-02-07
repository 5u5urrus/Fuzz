# fuzz

Fast and very effective HTTP GET fuzzer 

<p align="center">
  <img src="fuzz.jpg" width="100%" alt="fuzz Banner">
</p>

## Features

* **Path + parameter fuzzing** via a simple template: replace `fuzz` with each payload (URL-encoded)
* **Wordlist mode** (`-f`) and **regex-generated mode** (`-r`) (streamed; no big pre-gen)
* **Auto-calibration**: sends a few random canary requests to detect baseline “not found” and auto-filter it
* **Smart matching**: show only “hits” by default using a pentest-friendly status set (customizable)
* **Practical filters**: filter by status (`-fc`), header Content-Length (`-fs`), actual body bytes (`-fbs`), and word count (`-fw`, needs `-v`)
* **Redirect handling**: show redirect targets by default, or follow them (`-rdr`)
* **Proxy + headers**: JSON headers, explicit proxy, realistic default User-Agent

## Requirements

* Python 3.8+
* `requests`
* `tqdm`

Optional:
* `colorama` (colored output)
* `exrex` (required for `--regex` mode)

```bash
pip install requests tqdm
pip install colorama exrex
````

## Installation

```bash
git clone https://github.com/5u5urrus/fuzz.git
cd <repo>
chmod +x fuzz.py
```

## Basic usage

Template must be a full URL and **must include `fuzz`**:

```bash
python fuzz.py "https://example.com/fuzz" -f wordlist.txt
```

Fuzz a query parameter:

```bash
python fuzz.py "https://example.com/search?q=fuzz" -f wordlist.txt
```

Fuzz multiple `fuzz` tokens (every `fuzz` gets replaced):

```bash
python fuzz.py "https://example.com/fuzz/api?x=fuzz" -f wordlist.txt
```

Use a gzip wordlist (auto-detected by `.gz`):

```bash
python fuzz.py "https://example.com/fuzz" -f paths.txt.gz
```

## Output control

Show only hits (default behavior):

```bash
python fuzz.py "https://example.com/fuzz" -f wordlist.txt
```

Verbose mode (shows non-hit responses too, useful for tuning filters):

```bash
python fuzz.py "https://example.com/fuzz" -f wordlist.txt -v
```

Append hits to a file:

```bash
python fuzz.py "https://example.com/fuzz" -f wordlist.txt -o hits.txt
```

Pipe hits to another tool:

```bash
python fuzz.py "https://example.com/fuzz" -f wordlist.txt | httpx -silent
```

## Threads / timeouts

Increase speed (more threads):

```bash
python fuzz.py "https://example.com/fuzz" -f wordlist.txt -t 50
```

Tune timeout (connect/read):

```bash
python fuzz.py "https://example.com/fuzz" -f wordlist.txt --timeout 10
```

## Redirects

Default: **don’t follow**, but show `Location` targets:

```bash
python fuzz.py "https://example.com/fuzz" -f wordlist.txt
```

Follow redirects:

```bash
python fuzz.py "https://example.com/fuzz" -f wordlist.txt -rdr
```

## Status matching (what counts as a “hit”)

By default it matches a pentest-friendly set:
`200,204,301-303,307,308,401,403,405,500`

Match only 200:

```bash
python fuzz.py "https://example.com/fuzz" -f wordlist.txt -s 200
```

Match all 2xx:

```bash
python fuzz.py "https://example.com/fuzz" -f wordlist.txt -s 2xx
```

Match 2xx + 3xx:

```bash
python fuzz.py "https://example.com/fuzz" -f wordlist.txt -s "2xx,3xx"
```

Match a range:

```bash
python fuzz.py "https://example.com/fuzz" -f wordlist.txt -s "200-399"
```

Match *everything* (useful in verbose tuning):

```bash
python fuzz.py "https://example.com/fuzz" -f wordlist.txt -s "2xx,3xx,4xx,5xx"
```

Include transport failures (DNS/TLS/proxy issues) as hits:

```bash
python fuzz.py "https://example.com/fuzz" -f wordlist.txt -s "200,3xx,error"
# (same as using -1)
python fuzz.py "https://example.com/fuzz" -f wordlist.txt -s "200,3xx,-1"
```

Use the built-in alias:

```bash
python fuzz.py "https://example.com/fuzz" -f wordlist.txt -s common
```

## Filters (remove noise)

Filter by status codes (remove 404s, rate limits, etc.):

```bash
python fuzz.py "https://example.com/fuzz" -f wordlist.txt -fc 404
python fuzz.py "https://example.com/fuzz" -f wordlist.txt -fc "404,429"
python fuzz.py "https://example.com/fuzz" -f wordlist.txt -fc "4xx"
python fuzz.py "https://example.com/fuzz" -f wordlist.txt -fc "error"
```

Filter by **header** Content-Length values (fast; doesn’t require reading body):

```bash
python fuzz.py "https://example.com/fuzz" -f wordlist.txt -fs 0
python fuzz.py "https://example.com/fuzz" -f wordlist.txt -fs "1234,5678"
```

Filter by **actual body byte size** (reads bytes; more accurate when Content-Length lies):

```bash
python fuzz.py "https://example.com/fuzz" -f wordlist.txt -fbs 1530
python fuzz.py "https://example.com/fuzz" -f wordlist.txt -fbs "1530,1531,1532"
```

Filter by **word count** (requires `-v` because it needs decoded text):

```bash
python fuzz.py "https://example.com/fuzz" -f wordlist.txt -v -fw 0
python fuzz.py "https://example.com/fuzz" -f wordlist.txt -v -fw "12,13,14"
```

Combine filters (typical workflow: match broadly, filter baseline):

```bash
python fuzz.py "https://example.com/fuzz" -f wordlist.txt -s "2xx,3xx,4xx" -fc 404 -fs 1530
```

### Auto-calibration note

The tool automatically sends a few random canary requests like `fzcal_<random>` and tries to detect a stable baseline response.
If it successfully detects a baseline size, it may auto-add a filter (header size or body size) to reduce false positives.
If you think it filtered too aggressively, run `-v` and/or clear your manual filters, then set `-fs/-fbs/-fc` explicitly.

## Headers / proxy / TLS

Add custom headers (JSON):

```bash
python fuzz.py "https://example.com/fuzz" -f wordlist.txt -H '{"X-Forwarded-For":"127.0.0.1"}'
```

Override User-Agent:

```bash
python fuzz.py "https://example.com/fuzz" -f wordlist.txt -H '{"User-Agent":"Mozilla/5.0 ..."}'
```

Use an HTTP(S) proxy (environment proxies are ignored; `--proxy` is explicit):

```bash
python fuzz.py "https://example.com/fuzz" -f wordlist.txt --proxy http://127.0.0.1:8080
```

Disable TLS verification (testing only):

```bash
python fuzz.py "https://example.com/fuzz" -f wordlist.txt --insecure
```

## Regex mode (generate payloads without a wordlist)

Regex mode generates candidate strings using `exrex` and streams them into the fuzzer.

Install the dependency:

```bash
pip install exrex
```

### Notes / rules

* Use `-r/--regex` for the pattern.
* Use `--regex-limit` to cap how many generated candidates you’ll try (default: 100000).
* Generated values are **URL-encoded** when injected (spaces → `%20`, `/` → `%2F`, etc.).
* Regex mode is perfect for **numeric IDs**, **known token formats**, **date-like paths**, **short controlled alphabets**, and **parameter edge exploration**.

---

### 1) Numeric IDs (classic object enumeration)

```bash
python fuzz.py "https://example.com/item/fuzz" -r "[0-9]{1,4}" --regex-limit 2000
```

Example output:

```
Streaming up to 2000 words from regex: [0-9]{1,4}
 >> [200]  1  4.2kB  91ms  https://example.com/item/1
 >> [200]  2  4.2kB  88ms  https://example.com/item/2
 >> [403]  1337  1.1kB  120ms  https://example.com/item/1337
```

Tip: If you see a ton of fake-200s, run one pass with `-v` and then filter the baseline size using `-fs` or `-fbs`.

---

### 2) Fixed-width IDs (leading zeros)

```bash
python fuzz.py "https://example.com/invoice/fuzz" -r "[0-9]{6}" --regex-limit 5000
```

Example output:

```
Streaming up to 5000 words from regex: [0-9]{6}
 >> [302]  000123  0B  34ms  https://example.com/invoice/000123  ->  https://example.com/login
 >> [200]  001947  9.8kB  62ms  https://example.com/invoice/001947
```

---

### 3) Small controlled dictionary (no wordlist file needed)

```bash
python fuzz.py "https://example.com/fuzz" -r "(admin|adminpanel|dashboard|internal|debug|test)"
```

Example output:

```
Streaming up to 100000 words from regex: (admin|adminpanel|dashboard|internal|debug|test)
 >> [401]  admin  0B  55ms  https://example.com/admin
 >> [403]  internal  1.3kB  61ms  https://example.com/internal
 >> [200]  test  6.0kB  43ms  https://example.com/test
```

---

### 4) Environment / stage discovery (subpaths)

```bash
python fuzz.py "https://example.com/fuzz" -r "(dev|stage|staging|preprod|qa|uat)(/api)?"
```

Example output:

```
Streaming up to 100000 words from regex: (dev|stage|staging|preprod|qa|uat)(/api)?
 >> [200]  staging  3.1kB  77ms  https://example.com/staging
 >> [403]  qa/api  0B  69ms  https://example.com/qa%2Fapi
```

Note: `/` is URL-encoded, so `qa/api` becomes `qa%2Fapi`. If you want literal slashes as path separators, regex mode isn’t the right tool (use a wordlist with full paths like `qa/api`), because this fuzzer intentionally URL-encodes injected values.

---

### 5) Short “token” brute (controlled alphabet)

Try 1–3 lowercase letters:

```bash
python fuzz.py "https://example.com/r/fuzz" -r "[a-z]{1,3}" --regex-limit 20000
```

Example output:

```
Streaming up to 20000 words from regex: [a-z]{1,3}
 >> [302]  a  0B  40ms  https://example.com/r/a  ->  https://example.com/r/a/
 >> [200]  abc  1.8kB  51ms  https://example.com/r/abc
```

Use this for **short invite codes**, **short link resolvers**, or **feature flags**.

---

### 6) Date-like patterns (archives / backups / logs)

```bash
python fuzz.py "https://example.com/backup/fuzz.zip" -r "20(2[0-6])-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])" --regex-limit 5000
```

Example output:

```
Streaming up to 5000 words from regex: 20(2[0-6])-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])
 >> [200]  2026-01-03  2.4MB  1.92s [SLOW]  https://example.com/backup/2026-01-03.zip
 >> [403]  2025-12-31  0B  83ms  https://example.com/backup/2025-12-31.zip
```

---

### 7) Extension probing (find a real file type quickly)

```bash
python fuzz.py "https://example.com/download/fuzz" -r "(report|backup|db|dump)\\.(zip|tar|gz|sql|bak)"
```

Example output:

```
Streaming up to 100000 words from regex: (report|backup|db|dump)\.(zip|tar|gz|sql|bak)
 >> [200]  backup.sql  7.6MB  2.31s [SLOW]  https://example.com/download/backup.sql
 >> [403]  dump.zip  0B  74ms  https://example.com/download/dump.zip
```

---

### 8) Parameter edge-cases (non-alphanumeric)

```bash
python fuzz.py "https://example.com/search?q=fuzz" -r "(%00|%0a|%0d|%2e%2e%2f|\\.|\\.%2f|%2f)" --regex-limit 200
```

Example output:

```
Streaming up to 200 words from regex: (%00|%0a|%0d|%2e%2e%2f|\.|\.%2f|%2f)
 >> [400]  %0d  0B  29ms  https://example.com/search?q=%250d
 >> [500]  %2e%2e%2f  1.2kB  210ms  https://example.com/search?q=%252e%252e%252f
```

Important: because the tool URL-encodes the injected value, anything that already looks like `%xx` will get encoded again (`%` → `%25`), which is *exactly* what you want when testing “double-encoding” behaviors.

---

### 9) Generate the fuzzer-placeholder itself (to test normalization quirks)

```bash
python fuzz.py "https://example.com/fuzz" -r "(fuzz|FUZZ|FuZz|f%75zz)" --regex-limit 50
```

Example output:

```
Streaming up to 50 words from regex: (fuzz|FUZZ|FuZz|f%75zz)
 >> [200]  FUZZ  4.2kB  61ms  https://example.com/FUZZ
 >> [404]  FuZz  1.1kB  58ms  https://example.com/FuZz
```

---

### 10) Regex + filters (real workflow)

Broad match, then filter noise:

```bash
python fuzz.py "https://example.com/item/fuzz" -r "[0-9]{1,6}" --regex-limit 20000 -s "2xx,3xx,4xx,5xx" -v
```

After you identify a baseline size (or see auto-cal mention it), tighten:

```bash
python fuzz.py "https://example.com/item/fuzz" -r "[0-9]{1,6}" --regex-limit 20000 -s "2xx,3xx,4xx,5xx" -fc 404 -fs 1530
```

Example output (tightened):

```
Streaming up to 20000 words from regex: [0-9]{1,6}
 >> [200]  12  4.2kB  57ms  https://example.com/item/12
 >> [403]  9999  0B  64ms  https://example.com/item/9999
```

## License

MIT

## Author

Vahe Demirkhanyan

```
