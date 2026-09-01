# net-checker

Watches your internet connection with a continuously flowing ping stream and
reports how long it was actually down — not how many samples happened to miss.

## Setup

```bash
uv venv --python 3.14
uv sync
```

## Run

```bash
uv run net-checker --calibrate      # find the fastest ping rate this link tolerates
uv run net-checker                  # watch google.com at 20 pings/s, forever
uv run net-checker --duration 24    # stop after 24 hours
uv run net-checker --summarize      # analyse an existing log and exit
```

## No domain escapes ICMP rate limiting — a different probe does

Every internet destination tested loses the same ~25% at 100 pings/s, because
the limiter is on the path, not at the far end:

| target at 100 pings/s | loss |
| --- | --- |
| LAN gateway | 0.0% |
| first ISP hop | 20.1% |
| second ISP hop | 21.7% |
| 1.1.1.1 / 1.0.0.1 | 27.3% / 28.9% |
| 8.8.8.8 | 27.4% |
| 9.9.9.9 | 25.3% |
| 208.67.222.222 | 25.1% |
| google.com | 20.9% |
| 4.2.2.2 | 89.5% |

The LAN is clean and the loss appears at the first ISP hop, identically for
unrelated destinations — that is per-source ICMP policing upstream. Changing
the domain cannot fix it.

`--probe dns` sidesteps it: a cached DNS query over UDP is the same
one-packet-out, one-packet-back shape as an echo request, but it is ordinary
service traffic that nothing polices. Measured here:

| probe | rate | loss |
| --- | --- | --- |
| ICMP to 1.1.1.1 | 100/s | 27.3% |
| DNS to 1.1.1.1:53 | 200/s | 0.00% |
| DNS to 1.1.1.1:53 | 1000/s | 0.01% |
| DNS to 8.8.8.8:53 | 1000/s | 0.04% |
| DNS to 9.9.9.9:53 | 500/s | 75.7% |

So Cloudflare and Google DNS take 1,000 probes/s cleanly — 1 ms resolution,
5,000x finer than a 5-second ping. Quad9 rate-limits DNS, so stick to
`--resolver 1.1.1.1` (default) or `8.8.8.8`.

```bash
uv run net-checker --probe dns                      # 100/s, 10ms resolution
uv run net-checker --probe dns --interval 0.001     # 1000/s, 1ms resolution
uv run net-checker --probe dns --calibrate          # verify on your link
```

At 1,000/s that is ~86M queries and ~9 GB/day, so it suits a validation run
more than a permanent watch; the default 100/s costs ~0.9 GB/day.

## Why not one ping every 5 seconds

A 5-second cadence sends 2,880 probes in 4 hours and can only resolve an outage
to ±5s — a 3-second drop is a coin flip to notice at all. The default here is
one ping every 50 ms (20/s, ~288,000 in 4 hours), and outage edges come from the
`ping -D` timestamps, so durations are measured to the microsecond.

Faster is not automatically better: past ~50 pings/s the network rate-limits ICMP
and the loss is caused by the probing, not by the internet. Measured against
google.com from this machine:

| interval | pings/s | loss |
| --- | --- | --- |
| 0.01 | 73 | 28.7% |
| 0.02 | 48 | 2.6% |
| **0.05** | **19** | **0.0%** |
| 0.1 | 10 | 0.0% |
| 1.0 | 1 | 0.0% |

`--calibrate` re-runs that sweep on your link and recommends an interval, and
says so if the link polices ICMP. `--interval 0` uses `ping -A` (one packet per
round trip, ~70/s) if you want it fully free-flowing and accept the rate-limit
noise. To measure without any ICMP limit at all, use `--probe dns` above.

## What it refuses to call an outage

Two invariants keep measurement artifacts out of the numbers.

**All intervals are measured on the monotonic clock.** Wall-clock time is used
only for printing. This matters more than it sounds: on a WSL2 VM this tool
recorded 1,740 "outages" over 16 hours that were really the host stepping the
guest clock — 47 of those steps ran the clock *backwards* by about 14 minutes
each, erasing 11.7 hours from a 16-hour run and producing negative round-trip
times. A monotonic clock cannot be stepped, so none of that can reach a report.

**A silence with nothing lost is not an outage.** A real outage swallows
probes: at 100/s, a 1.7-second outage has to lose about 170 of them. When the
stream goes quiet but every probe sent during the quiet period is eventually
answered, the process or the clock stalled — the link did not go down. Those
are logged as `SKEW`, kept out of the downtime total, and reported separately:

```
    ignored 1738 timing anomalies totalling 49.53 minutes - silence with no probe
    lost, so the clock stepped or the process stalled, the link did not go down
```

`--summarize` applies the same test retroactively to logs written before the
`GAP` record carried its unanswered count.

## What it reports

A single dropped packet is not an outage. Every lost packet is logged with its
own timestamp, and a run with no reply for longer than `--gap` (default 1s) is
recorded as an outage with an exact duration. Reports separate the two:

```
Internet was down for 1.43 minutes.
    window 3 (4h): 287,411 probes, 1,904 lost (0.662%) = 1,712 inside outages + 192 isolated drops
    3 outages, longest 47.221083s, shortest 4.006512s
      down 09:14:07.418 -> 09:14:11.425 PDT  (4.007s)
      down 10:02:55.310 -> 10:03:42.531 PDT  (47.221s)
      down 11:48:30.902 -> 11:49:12.114 PDT  (41.212s)
    a 5s cadence would have sent 2,880 probes (100x fewer) and expected to catch 1.24 of these 3 outages
```

Each outage is listed with the wall-clock time it started and ended, to the
millisecond, in your machine's timezone — `--timezone America/Los_Angeles` (or
any IANA name) reports in another. The date is shown when an outage did not
start today, and again on the end when it crossed midnight. Long lists stop at
ten with a `... and N more` line.

The `Internet was down for …` line only appears when there was a real outage.
A window with nothing but isolated drops prints the stats line alone; a fully
clean window prints nothing at all. Every 24 hours the same roll-up is printed
in hours.

Between reports the trace fills the screen, one coloured dot per `--slice`
seconds:

| dot | meaning |
| --- | --- |
| 🟢 green | clean, nothing lost |
| 🟡 light yellow | <1% lost |
| 🟠 orange | <10% lost |
| 🔴 red | 10% or more lost |
| ⚪ grey | no probes at all (the prober itself was down) |

While a slice fills, the seconds count up in place — `1`, `2`, `3`, `4`, `5` —
in the cell the dot is about to land in, so the line never grows until the dot
replaces the digit. `--no-progress` turns the counter off; `--color never`
falls back to `. , : x #` (as does any non-tty, or `NO_COLOR`).

## How it works

Two threads:

1. **pinger** — runs the chosen probe and reconciles every packet it sends
   against the replies that come back (a late reply still counts as a reply; a
   probe unanswered after `--timeout` is a loss), appending microsecond-stamped
   records to the log: `LOSS`, `GAP` (a recovered outage and its exact length),
   `SLICE` (per-slice counters), `RESTART`. `--log-mode all` also logs every
   individual reply, and a silence that lost nothing is logged as `SKEW` rather
   than `GAP`. Each lost probe is classified as it is retired: inside an
   outage if the silence it fell into — from the last reply before it to the
   first reply after it — lasted at least `--gap`, otherwise an isolated drop.
   `--probe icmp` keeps one `ping -D -O -n` process alive and
   tracks `icmp_seq`; `--probe dns` sends DNS queries on a non-blocking UDP
   socket and tracks the transaction id.
2. **reader** — tails that log file, prints the trace character per slice, and
   at each 4-hour and 24-hour boundary prints the downtime summary.

If the ping process dies (DNS failure when the link is fully down, for example)
it is respawned, and the time it was gone still lands in the next `GAP`.

## Options

| flag | default | meaning |
| --- | --- | --- |
| `--probe` | `icmp` | `icmp` (ping) or `dns` (UDP DNS, not rate limited) |
| `--host` | `google.com` | host to ping (`--probe icmp`) |
| `--resolver` | `1.1.1.1` | resolver to query (`--probe dns`) |
| `--resolver-port` | `53` | resolver port |
| `--query-name` | `example.com` | name asked for; answered from cache |
| `--interval` | `0.05` icmp / `0.01` dns | seconds between probes; `0` = adaptive (`ping -A`) |
| `--timeout` | `2` | seconds before an unanswered packet counts as lost |
| `--gap` | `1` | seconds without a reply that counts as an outage |
| `--slice` | `5` | seconds summarised by one trace character |
| `--log` | `net-checker.log` | log file path |
| `--log-mode` | `events` | `events` or `all` (also log every reply) |
| `--report-every` | `14400` (4h) | seconds between summaries |
| `--daily` | `86400` (24h) | seconds between roll-ups |
| `--window-unit` | `minutes` | `auto`, `seconds`, `minutes`, `hours` |
| `--timezone` | system | IANA zone for reported outage times, e.g. `America/Los_Angeles` |
| `--color` | `auto` | `auto`, `always`, `never` (never = ascii trace) |
| `--no-progress` | | do not count seconds in place while a slice fills |
| `--baseline` | `5` | cadence to compare against in reports |
| `--duration` | `0` | stop after N hours (0 = forever) |
| `--calibrate` | | measure loss at several rates and exit |
| `--summarize` | | analyse the log file and exit |

At the default rate the log grows by roughly 1.7M pings/day, but only losses,
outages and one slice line per 5s are written — about 1 MB/day on a clean link.
