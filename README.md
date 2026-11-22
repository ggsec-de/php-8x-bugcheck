# php-8x-bugcheck

**Does this PHP build still behave the way it should?**

One file, nine checks, one line each, read-only. It answers a narrow question about a specific
host: which of the behaviours in the 0-day bug reports that appeared for PHP in November 2026 are
present here. It contains no exploit payloads and no crash inputs.

## Why this exists

In November 2026, reports of 0-day bugs in PHP appeared online. They named 8.4.28, 8.5.13 and
8.6.0 among the affected builds and described a large number of engine and extension defects.
Reading them tells you that some piece of code does something unpleasant to a process. It does not
tell you what *your* host does, and it is not something you hand to a hosting provider or a client.

The smaller question is answerable in one request: does this build accept the input, return the
wrong length, or silently wrap the value? That is what this script reports. It deliberately stops
at the behaviour and does not describe what could be built on top of it - that part stays with the
person who needs it and has the authority to test for it.

## What it checks

| line | question | what a fixed build does |
| --- | --- | --- |
| `url_numeric_hosts` | does `FILTER_VALIDATE_URL` accept decimal, octal, hex and shortened spellings of an IPv4 host? | rejects all six |
| `date_out_of_range` | does `date_create('+999999')` return a date instead of failing? | fails |
| `numeric_nul` | does `bcadd("1\0 2", "0")` stop at the NUL and return `1`? | keeps or rejects the value |
| `sqlite_nul_text` | after storing a three-byte TEXT value with an inner NUL, do you read three bytes back? | three bytes |
| `dom_template` | does `cloneNode(true)` on a `<template>` element keep its children? | keeps them |
| `mb_replacement` | can a replacement string expand a one-byte subject to more bytes than the replacement itself? | no |
| `idn_at_sign` | is a fullwidth `＠` mapped to ASCII `@` and accepted as a host label? | rejected |
| `gd2_support` | does `imagegd2()` produce a file that `imagecreatefromgd2()` accepts? | both agree |
| `path_nul` | does `proc_open()` accept an embedded NUL in the working directory and start the child? | rejected |

Each line prints `ok`, `BUG`, or `NA`. `NA` means the extension the check needs is not loaded - it
is not a pass.

## What it does not do

- No exploit payloads, no crash inputs, no memory-corruption reproducers, no `/proc` access.
- No network connections. Nothing is fetched, nothing is sent.
- No writes outside one temporary file, created and removed by the `gd2_support` check.
- One process is started in total: `/bin/true` inside the `path_nul` check.
- It does not prove exploitability, and it is not a scanner. A run with no `BUG` lines says
  nothing about the nine behaviours' siblings that are not in this list.

If you find `BUG` lines on a host you do not own, tell its operator. Do not use this as a probe
against third parties.

## Requirements

PHP 8.4 or newer for the full set - `Dom\HTMLDocument` exists from 8.4, so on 8.3 that one line
reads `NA`. CLI or a web SAPI. Optional extensions, each check degrades to `NA` without them:
bcmath, sqlite3, mbstring, intl, gd. `proc_open` is used if it is not disabled.

## Run it

Shell:

```bash
php php-8x-bugcheck.php
echo "exit=$?"
```

Web, one upload, delete it afterwards:

```bash
cp php-8x-bugcheck.php /var/www/html/check.php   # or any web root
chmod 644 /var/www/html/check.php
curl -s https://example.org/check.php
rm /var/www/html/check.php
```

On CLI the exit code is `1` when at least one area reports `BUG`, `0` otherwise, so it can be used
in a cron job or a post-deploy hook.

## Reading the output

```
php                    8.4.28-nmm1
sapi                   fpm-fcgi
arch                   x86_64
opcache                1
open_basedir           unset
disable_functions      unset
memory_limit           768M

url_numeric_hosts      6/6 BUG
date_out_of_range      BUG
numeric_nul            BUG
sqlite_nul_text        BUG
dom_template           BUG
mb_replacement         BUG
idn_at_sign            BUG
gd2_support            unavailable
path_nul               BUG

result                 detection only, no exploit payloads included
summary                BUG=8 NA=0 checks=9
```

- The header block is context, not a verdict. `open_basedir unset` and
  `disable_functions unset` are common on shared hosting and worth knowing about, but they are
  configuration choices, not bugs in this list.
- `gd2_support unavailable` means GD2 is compiled out of the host's libgd (Debian and its
  derivatives do this). The writer then returns success while producing nothing. That is an
  inconsistency, but it is a packaging decision rather than something to report as a defect, so
  it is not counted in `BUG`.
- `NA` on `dom_template` usually means PHP older than 8.4; `NA` on `mb_replacement` or
  `idn_at_sign` means mbstring or intl is missing.

## Tested on

| build | SAPI | result |
| --- | --- | --- |
| 8.4.28-nmm1 (Debian, x86_64) | `fpm-fcgi` | 8 `BUG`, `gd2_support unavailable` |
| 8.3.33 (Windows, x86_64) | `cli` | 5 `BUG`, 3 `NA` (`dom_template`, `idn_at_sign`, `path_nul`) |

The behaviours behind these lines were reproduced individually on 8.4.28, 8.5.13 and 8.6.0 with
targeted reproducers before this detector was extracted. The detector itself has been run on the
two builds above, which is the reason the table has two rows and not four.

## Limitations

- One request, one process, cold state. Pool-wide effects - cross-worker state, opcache
  inheritance, per-pool `disable_functions` - are not covered by this script.
- The lines report behaviour, not CVE identifiers. Several of these behaviours have existed for
  years; none of them is new because a report says so.
- Fix status changes. The newest release at the time of writing was 8.6.0; re-run after upgrading
  rather than trusting this table.

## Licence

MIT, see `LICENSE`.
