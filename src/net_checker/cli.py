"""Long-running internet uptime checker.

Two worker threads:
  * pinger - keeps a single `ping` process alive and lets it flow as fast as
             the round trips allow (adaptive mode), reconciling every icmp_seq
             it sends against the replies that come back, and appending
             microsecond-stamped events to the log file.
  * reader - tails that log file, prints one character per slice of wall time,
             and prints a downtime summary every reporting window.
"""

from __future__ import annotations

import argparse
import bisect
import os
import re
import selectors
import socket
import shutil
import struct
import signal
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, tzinfo
from zoneinfo import ZoneInfo

# ping -D -O -n output we care about.
REPLY_RE = re.compile(r"^\[(\d+\.\d+)\].*icmp_seq=(\d+).*\btime[=<]\s*([\d.]+)\s*ms")
PENDING_RE = re.compile(r"^\[(\d+\.\d+)\] no answer yet for icmp_seq=(\d+)")
ERROR_RE = re.compile(r"^\[(\d+\.\d+)\] From .*icmp_seq=(\d+)\s+(\S.*)$")

# Log record types.
PING = "PING"      # ts, seq, rtt_ms                 (only with --log-mode all)
LOSS = "LOSS"      # ts, seq, lost_inside_an_outage
SLICE = "SLICE"    # ts, sent, lost, lost_inside, span, min_rtt, avg_rtt, max_rtt
GAP = "GAP"        # ts (recovery), duration, probes left unanswered
SKEW = "SKEW"      # ts, duration, 0 - silence with nothing lost: a clock step or
                   #     a stalled process, never an outage
RESTART = "RESTART"  # ts, reason
KINDS = {PING, LOSS, SLICE, GAP, SKEW, RESTART}

# Every record is written as: ts <TAB> lane <TAB> kind <TAB> fields...
WAN = "wan"        # the internet probe
LAN = "lan"        # the gateway probe, the control that says who is at fault


def default_gateway() -> str | None:
    """The next hop out of this machine, so we can tell the LAN from the ISP."""
    try:
        out = subprocess.run(["ip", "route", "show", "default"],
                             capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(r"default via (\S+)", out)
    return match[1] if match else None


# --------------------------------------------------------------------------- #
# formatting helpers
# --------------------------------------------------------------------------- #
def humanize(seconds: float, unit: str) -> str:
    if unit == "auto":
        unit = "seconds" if seconds < 90 else "minutes" if seconds < 5400 else "hours"
    if unit == "seconds":
        return f"{seconds:.3f} seconds"
    if unit == "minutes":
        return f"{seconds / 60:.2f} minutes"
    return f"{seconds / 3600:.3f} hours"


def zone(name: str | None) -> tzinfo:
    """The reporting timezone: --timezone if given, otherwise the system's."""
    if not name:
        return datetime.now().astimezone().tzinfo
    try:
        return ZoneInfo(name)
    except Exception as exc:                      # noqa: BLE001 - argparse-level error
        raise SystemExit(f"unknown timezone {name!r}: {exc}")


def clock(ts: float, tz: tzinfo, with_date: bool) -> str:
    """A wall-clock stamp to the millisecond, e.g. 08-31 14:35:02.123."""
    moment = datetime.fromtimestamp(ts, tz)
    return moment.strftime("%m-%d %H:%M:%S.%f" if with_date else "%H:%M:%S.%f")[:-3]


def blame(start: float, end: float, lan_gaps: list[tuple[float, float]] | None) -> str:
    """Was the gateway reachable while the internet was not?"""
    if lan_gaps is None:
        return ""
    if any(ls < end and le > start for ls, le in lan_gaps):
        return "  [gateway unreachable too -> your LAN or this machine, not the ISP]"
    return "  [gateway stayed up -> the fault is upstream of your router]"


def outage_lines(gaps: list[tuple[float, float]], tz: tzinfo, limit: int = 10,
                 lan_gaps: list[tuple[float, float]] | None = None) -> list[str]:
    """When each outage actually started and ended, in wall-clock time."""
    today = datetime.now(tz).date()
    lines = []
    for start, end in sorted(gaps)[:limit]:
        starts, ends = datetime.fromtimestamp(start, tz), datetime.fromtimestamp(end, tz)
        lines.append(
            f"      down {clock(start, tz, starts.date() != today)} -> "
            f"{clock(end, tz, ends.date() != starts.date())} {ends.strftime('%Z')}"
            f"  ({end - start:.3f}s){blame(start, end, lan_gaps)}"
        )
    if len(gaps) > limit:
        lines.append(f"      ... and {len(gaps) - limit} more")
    return lines


def term_width() -> int:
    return max(shutil.get_terminal_size((80, 24)).columns - 1, 20)


# (upper bound on the loss ratio, label, ascii char, xterm-256 colour)
TRACE_LEVELS = (
    (0.0000, "clean", ".", 46),      # green
    (0.0100, "<1% lost", ",", 227),  # light yellow
    (0.1000, "<10%", ":", 208),      # orange
    (1.0001, ">=10%", "x", 196),     # red
)
NO_DATA = ("no probes", "#", 244)    # grey
DOT = "\u25cf"
DIAMOND = "\u25c6"


def paint(text: str, colour: int | None, bold: bool = False) -> str:
    if colour is None:
        return text
    return f"\033[{'1;' if bold else ''}38;5;{colour}m{text}\033[0m"


def use_colour(mode: str) -> bool:
    if mode == "never" or os.environ.get("NO_COLOR"):
        return False
    return mode == "always" or sys.stdout.isatty()


def render_slice(sent: int, lost: int, colour: bool, lan_lost: bool = False) -> str:
    """One character summarising a slice of wall time."""
    if sent <= 0:
        _label, char, code = NO_DATA
    else:
        ratio = lost / sent
        for bound, _label, char, code in TRACE_LEVELS:
            if ratio <= bound:
                break
    if lan_lost:
        # Shape says the gateway lost probes too; the colour still reports the
        # internet lane, so one glyph carries both facts.
        return paint(DIAMOND, code) if colour else "L"
    return paint(DOT, code) if colour else char


def legend(colour: bool) -> str:
    parts = [
        (paint(DOT, code) if colour else char) + " " + label
        for _bound, label, char, code in TRACE_LEVELS
    ]
    label, char, code = NO_DATA
    parts.append((paint(DOT, code) if colour else char) + " " + label)
    parts.append((paint(DIAMOND, 244) if colour else "L")
                 + " gateway lost too (colour still shows the internet)")
    return "   ".join(parts)


# --------------------------------------------------------------------------- #
# thread 1: keep a ping stream running and log what it did
# --------------------------------------------------------------------------- #
class Prober:
    """Shared accounting: every probe is reconciled, losses and outages logged."""

    def __init__(self, args: argparse.Namespace, stop: threading.Event, journal,
                 lane: str = WAN, host: str | None = None) -> None:
        self.args = args
        self.stop = stop
        self.journal = journal
        self.lane = lane
        self.host = host or args.host
        # probe id -> [monotonic ts unanswered, wall ts, last reply before it,
        #              first reply after it]  - intervals are monotonic so that a
        #              wall-clock step cannot invent an outage
        self.pending: dict[int, list[float | None]] = {}
        self.unstamped: deque[list[float | None]] = deque()
        self.last_success: float | None = None          # monotonic
        self.last_success_wall: float | None = None
        self.slice_start: float | None = None           # monotonic
        self.sent = self.lost = self.lost_in_outage = 0
        self.rtts: list[float] = []

    # -- log writing ------------------------------------------------------- #
    def write(self, ts: float, kind: str, *fields: object) -> None:
        self.journal.write(
            f"{ts:.6f}\t{self.lane}\t{kind}\t" + "\t".join(str(f) for f in fields) + "\n"
        )

    def on_success(self, mono: float, wall: float, ident: int, rtt: float | None) -> None:
        self.pending.pop(ident, None)             # a late reply is still a reply
        while self.unstamped:                     # this is the first reply after them
            self.unstamped.popleft()[3] = mono
        if rtt is not None:
            self.rtts.append(rtt)
            if self.args.log_mode == "all":
                self.write(wall, PING, ident, f"{rtt:.3f}")
        if self.last_success is not None:
            gap = mono - self.last_success
            if gap >= self.args.gap:
                # A real outage swallows probes. If every probe sent during the
                # silence was answered, nothing was down - the process or the
                # clock stalled - so record it as skew and keep it out of the
                # downtime total.
                unanswered = sum(
                    1 for entry in self.pending.values()
                    if entry[0] is not None and entry[0] > self.last_success
                )
                self.write(wall, GAP if unanswered else SKEW, f"{gap:.6f}", unanswered)
        self.last_success = mono
        self.last_success_wall = wall

    def mark_pending(self, ident: int, mono: float, wall: float) -> None:
        if ident in self.pending:
            return
        entry: list[float | None] = [mono, wall, self.last_success, None]
        self.pending[ident] = entry
        self.unstamped.append(entry)

    def declare_lost(self, ident: int, wall: float, base: float | None,
                     after: float | None, now: float) -> None:
        """Lost inside an outage if the silence around it lasted at least --gap.

        `base` is the last reply before this probe was sent and `after` the first
        reply following it, so the silence it fell into is exactly `after - base`
        - still running, and measured against now, if no reply has come back yet.
        """
        in_outage = base is not None and (after or now) - base >= self.args.gap
        self.lost += 1
        self.lost_in_outage += in_outage
        self.write(wall, LOSS, ident, int(in_outage))

    def tick(self, now: float, wall: float) -> None:
        """Retire timed-out probes and flush the current slice. `now` is monotonic."""
        if self.slice_start is None:
            self.slice_start = now
        for ident, (mono, sent_wall, base, after) in list(self.pending.items()):
            if now - mono < self.args.timeout:
                continue
            if after is None and base is not None and now - base < self.args.gap:
                continue                          # too early to tell; decide next tick
            del self.pending[ident]
            self.declare_lost(ident, sent_wall, base, after, now)
        if now - self.slice_start >= self.args.slice:
            span, rtts = now - self.slice_start, self.rtts
            self.write(
                wall,
                SLICE,
                self.sent,
                self.lost,
                self.lost_in_outage,
                f"{span:.6f}",
                f"{min(rtts):.3f}" if rtts else "",
                f"{sum(rtts) / len(rtts):.3f}" if rtts else "",
                f"{max(rtts):.3f}" if rtts else "",
            )
            self.slice_start, self.sent, self.lost, self.rtts = now, 0, 0, []
            self.lost_in_outage = 0


class IcmpProber(Prober):
    """Keeps one `ping` process alive and reconciles every icmp_seq it issues."""

    def __init__(self, *posargs) -> None:
        super().__init__(*posargs)
        self.last_seq = 0                         # highest seq issued this run

    def command(self) -> list[str]:
        cmd = ["ping", "-D", "-O", "-n"]
        interval = self.args.gateway_interval if self.lane == LAN else self.args.interval
        if interval:
            cmd += ["-i", str(interval)]
        else:
            cmd += ["-A"]                         # flow as fast as the RTT allows
        cmd += ["-W", str(self.args.timeout), self.host]
        return cmd

    def run(self) -> None:
        backoff = 1.0
        while not self.stop.is_set():
            try:
                proc = subprocess.Popen(
                    self.command(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0
                )
            except OSError as exc:
                self.write(time.time(), RESTART, f"spawn failed: {exc}")
                self.stop.wait(backoff)
                backoff = min(backoff * 2, 30.0)
                continue
            backoff = 1.0
            reason = self.consume(proc)
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
            if self.stop.is_set():
                break
            self.last_seq = 0
            self.pending.clear()
            self.write(time.time(), RESTART, reason)
            self.stop.wait(1.0)

    def consume(self, proc: subprocess.Popen) -> str:
        """Read the ping stream until it ends or we are asked to stop."""
        sel = selectors.DefaultSelector()
        sel.register(proc.stdout, selectors.EVENT_READ)
        buf = b""
        try:
            while not self.stop.is_set():
                for _key, _mask in sel.select(timeout=0.2):
                    chunk = os.read(proc.stdout.fileno(), 65536)
                    if not chunk:
                        self.tick(time.monotonic(), time.time())
                        return "ping stream ended"
                    buf += chunk
                    *lines, buf = buf.split(b"\n")
                    for raw in lines:
                        self.handle(raw.decode("utf-8", "replace"))
                self.tick(time.monotonic(), time.time())
                if proc.poll() is not None:
                    return f"ping exited with code {proc.returncode}"
            return "stopped"
        finally:
            sel.close()

    def count_seq(self, seq: int) -> None:
        """Every icmp_seq the process issues is counted exactly once."""
        if seq > self.last_seq:
            self.sent += seq - self.last_seq
            self.last_seq = seq

    @staticmethod
    def monotonic_of(wall_ts: float) -> float:
        """ping stamps its lines with the wall clock; anchor them to monotonic now."""
        return time.monotonic() - (time.time() - wall_ts)

    def handle(self, line: str) -> None:
        match = REPLY_RE.match(line)
        if match:
            ts, seq, rtt = float(match[1]), int(match[2]), float(match[3])
            self.count_seq(seq)
            self.on_success(self.monotonic_of(ts), ts, seq, rtt)
            return

        match = PENDING_RE.match(line)
        if match:
            ts, seq = float(match[1]), int(match[2])
            self.count_seq(seq)
            self.mark_pending(seq, self.monotonic_of(ts), ts)
            return

        match = ERROR_RE.match(line)
        if match:                                 # host/net unreachable: lost now
            ts, seq = float(match[1]), int(match[2])
            mono = self.monotonic_of(ts)
            self.count_seq(seq)
            _m, _w, base, after = self.pending.pop(seq, [mono, ts, self.last_success, None])
            self.declare_lost(seq, ts, base, after, mono)


class DnsProber(Prober):
    """Sends cached DNS queries over UDP - no ICMP, so no ICMP rate limiting.

    One small packet out, one back, exactly the shape of an echo request, but
    carried as ordinary service traffic that the network does not police.
    """

    def __init__(self, *posargs) -> None:
        super().__init__(*posargs)
        self.txid = 0

    def query(self, name: str) -> bytes:
        body = b""
        for label in name.split("."):
            body += bytes([len(label)]) + label.encode()
        return body + b"\x00" + struct.pack(">HH", 1, 1)   # A, IN

    def run(self) -> None:
        backoff = 1.0
        question = self.query(self.args.query_name)
        interval = self.args.interval or 0.001
        while not self.stop.is_set():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setblocking(False)
                sock.connect((self.args.resolver, self.args.resolver_port))
            except OSError as exc:
                self.write(time.time(), RESTART, f"socket failed: {exc}")
                self.stop.wait(backoff)
                backoff = min(backoff * 2, 30.0)
                continue
            backoff = 1.0
            reason = self.pump(sock, question, interval)
            sock.close()
            if self.stop.is_set():
                break
            self.pending.clear()
            self.write(time.time(), RESTART, reason)
            self.stop.wait(1.0)

    def pump(self, sock: socket.socket, question: bytes, interval: float) -> str:
        sel = selectors.DefaultSelector()
        sel.register(sock, selectors.EVENT_READ)
        next_send = time.monotonic()
        try:
            while not self.stop.is_set():
                now = time.monotonic()
                if now >= next_send:
                    self.txid = (self.txid + 1) & 0xFFFF
                    packet = struct.pack(">HHHHHH", self.txid, 0x0100, 1, 0, 0, 0) + question
                    try:
                        sock.send(packet)
                        self.sent += 1
                        self.mark_pending(self.txid, now, time.time())
                    except BlockingIOError:
                        pass
                    except OSError as exc:        # network unreachable, etc.
                        self.sent += 1
                        self.declare_lost(self.txid, time.time(), self.last_success, None, now)
                        # ENETUNREACH / ECONNREFUSED / EHOSTUNREACH / EINVAL all mean
                        # "not right now", which is a lost probe, not a broken socket.
                        if exc.errno not in (101, 111, 113, 22):
                            return f"send failed: {exc}"
                    next_send += interval
                    if next_send < now - 1:       # fell far behind; resynchronise
                        next_send = now + interval

                if sel.select(timeout=max(0.0, min(next_send - time.monotonic(), 0.05))):
                    while True:
                        try:
                            data = sock.recv(2048)
                        except OSError:      # incl. ECONNREFUSED from the last send
                            break
                        if len(data) < 4 or not data[2] & 0x80:   # not a response
                            continue
                        now = time.monotonic()
                        txid = struct.unpack(">H", data[:2])[0]
                        entry = self.pending.get(txid)
                        rtt = (now - entry[0]) * 1000 if entry else None
                        self.on_success(now, time.time(), txid, rtt)
                self.tick(time.monotonic(), time.time())
            return "stopped"
        finally:
            sel.close()


PROBERS = {"icmp": IcmpProber, "dns": DnsProber}


class Journal:
    """One log file, written by every lane."""

    def __init__(self, path: str) -> None:
        self.fh = open(path, "a", buffering=1, encoding="utf-8")
        self.lock = threading.Lock()

    def write(self, line: str) -> None:
        with self.lock:
            self.fh.write(line)

    def close(self) -> None:
        self.fh.close()


def pinger(args: argparse.Namespace, stop: threading.Event, journal: Journal,
           lane: str = WAN, host: str | None = None) -> None:
    prober = IcmpProber if lane == LAN else PROBERS[args.probe]
    prober(args, stop, journal, lane, host).run()


# --------------------------------------------------------------------------- #
# thread 2: read the log, draw the trace, report downtime
# --------------------------------------------------------------------------- #
class Screen:
    """Keeps track of where we are on the current trace line."""

    def __init__(self, colour: bool = False) -> None:
        self.column = 0
        self.colour = colour
        self.preview = ""          # transient countdown sitting in the next cell

    def show(self, text: str) -> None:
        """Draw a transient character in place, to be overwritten by the dot."""
        if text == self.preview:
            return
        self.clear()
        sys.stdout.write((paint(text, 244) if self.colour else text) + "\b")
        sys.stdout.flush()
        self.preview = text

    def clear(self) -> None:
        if self.preview:
            sys.stdout.write(" \b")
            self.preview = ""

    def mark(self, char: str) -> None:
        self.clear()
        if self.column >= term_width():
            sys.stdout.write("\n")
            self.column = 0
        sys.stdout.write(char)
        sys.stdout.flush()
        self.column += 1

    def message(self, text: str, colour: int | None = None, bold: bool = False) -> None:
        self.clear()
        if self.column:
            sys.stdout.write("\n")
            self.column = 0
        sys.stdout.write((paint(text, colour, bold) if self.colour else text) + "\n")
        sys.stdout.flush()


@dataclass
class Bucket:
    """Everything observed inside one reporting window."""

    sent: int = 0
    lost: int = 0
    inside: int = 0                                        # lost while an outage was running
    span: float = 0.0
    gaps: list[tuple[float, float]] = field(default_factory=list)  # (start, end) of each outage
    skews: list[float] = field(default_factory=list)   # silences with nothing lost
    restarts: int = 0

    @property
    def outages(self) -> list[float]:
        return [end - start for start, end in self.gaps]

    @property
    def downtime(self) -> float:
        return sum(self.outages)

    def split_losses(self) -> tuple[int, int]:
        """(drops inside an outage, isolated drops)."""
        inside = min(self.inside, self.lost)
        return inside, self.lost - inside

    def report(self, label: str, unit: str, baseline: float, tz: tzinfo,
               lan: "Bucket | None" = None) -> list[str]:
        inside, isolated = self.split_losses()
        lost = self.lost
        loss_pct = 100 * lost / self.sent if self.sent else 0.0
        outages = self.outages
        lines: list[str] = []
        if self.downtime > 0:
            lines.append(f"Internet was down for {humanize(self.downtime, unit)}.")
        lines.append(
            f"    {label}: {self.sent:,} probes, {lost:,} lost ({loss_pct:.3f}%) "
            f"= {inside:,} inside outages + {isolated:,} isolated drops"
        )
        if outages:
            lines.append(
                f"    {len(outages)} outage{'' if len(outages) == 1 else 's'}, "
                f"longest {max(outages):.6f}s, shortest {min(outages):.6f}s"
            )
            lines.extend(outage_lines(self.gaps, tz, lan_gaps=lan.gaps if lan else None))
            if lan is not None:
                upstream = [g for g in self.gaps if not blame(*g, lan.gaps).startswith("  [gateway un")]
                lines.append(
                    f"    gateway control lane: {lan.sent:,} probes, {lan.lost:,} lost "
                    f"({100 * lan.lost / lan.sent if lan.sent else 0:.3f}%), "
                    f"{len(lan.gaps)} gateway outage{'' if len(lan.gaps) == 1 else 's'}"
                    f"  -> {len(upstream)} of {len(self.gaps)} outages were upstream of your router"
                )
        if outages and baseline and self.sent and self.span > baseline:
            probes = self.span / baseline
            caught = sum(min(1.0, out / baseline) for out in outages)
            lines.append(
                f"    a {baseline:g}s cadence would have sent {probes:,.0f} probes "
                f"({self.sent / probes:.0f}x fewer) and expected to catch "
                f"{caught:.2f} of these {len(outages)} outages"
            )
        if self.skews:
            lines.append(
                f"    ignored {len(self.skews)} timing anomal"
                f"{'y' if len(self.skews) == 1 else 'ies'} totalling "
                f"{humanize(sum(self.skews), 'auto')} - silence with no probe lost, so the"
                " clock stepped or the process stalled, the link did not go down"
            )
        if self.restarts:
            lines.append(f"    ping restarted {self.restarts} time(s)")
        return lines


def style(text: str) -> tuple[int, bool]:
    """Headlines in red, the detail lines under them in grey."""
    return (196, True) if text.startswith("Internet was down") else (244, False)


def parse_line(line: str) -> tuple[float, str, str, list[str]] | None:
    """(ts, lane, kind, fields). Records written before lanes existed are wan."""
    parts = line.rstrip("\n").split("\t")
    if len(parts) < 2:
        return None
    try:
        ts = float(parts[0])
    except ValueError:
        return None
    if parts[1] in KINDS:
        return ts, WAN, parts[1], parts[2:]
    if len(parts) > 2 and parts[2] in KINDS:
        return ts, parts[1], parts[2], parts[3:]
    return None


def reader(args: argparse.Namespace, stop: threading.Event, start: float) -> None:
    colour = use_colour(args.color)
    screen = Screen(colour)
    tz = zone(args.timezone)
    progress = args.progress and sys.stdout.isatty()
    countdown_max = max(1, min(9, int(args.slice)))   # 1..5 for the default 5s slice
    slice_started = time.monotonic()
    lanes = (WAN, LAN)
    window = {lane: Bucket() for lane in lanes}
    day = {lane: Bucket() for lane in lanes}
    lan_trouble = [False]                   # gateway lost probes since the last dot
    next_window = start + args.report_every
    next_day = start + args.daily
    windows = days = 0

    nonlocal_slice = [slice_started]        # last slice boundary, for the countdown

    def apply(record: tuple[float, str, str, list[str]]) -> None:
        _ts, lane, kind, rest = record
        if lane not in window:
            return
        buckets = (window[lane], day[lane])
        if kind == SLICE:
            sent, lost = int(rest[0]), int(rest[1])
            inside = int(rest[2]) if len(rest) > 2 and rest[2].isdigit() else 0
            for bucket in buckets:
                bucket.sent += sent
                bucket.lost += lost
                bucket.inside += inside
            if lane == LAN:
                lan_trouble[0] = lan_trouble[0] or lost > 0
            else:                            # the trace follows the internet lane
                screen.mark(render_slice(sent, lost, colour, lan_trouble[0]))
                lan_trouble[0] = False
                nonlocal_slice[0] = time.monotonic()
        elif kind == GAP:
            duration = float(rest[0])
            for bucket in buckets:
                bucket.gaps.append((_ts - duration, _ts))
        elif kind == SKEW:
            for bucket in buckets:
                bucket.skews.append(float(rest[0]))
        elif kind == RESTART:
            for bucket in buckets:
                bucket.restarts += 1

    with open(args.log, "r", encoding="utf-8") as fh:
        fh.seek(0, os.SEEK_END)
        while not stop.is_set():
            now = time.monotonic()
            if now >= next_window:
                windows += 1
                wan, lan = window[WAN], window[LAN]
                wan.span = lan.span = args.report_every
                if wan.lost or wan.restarts or wan.skews or lan.lost:
                    for text in wan.report(
                        f"window {windows} ({args.report_every / 3600:g}h)",
                        args.window_unit,
                        args.baseline,
                        tz,
                        lan if lan.sent else None,
                    ):
                        screen.message(text, *style(text))
                window = {lane: Bucket() for lane in lanes}
                next_window += args.report_every
            if now >= next_day:
                days += 1
                wan, lan = day[WAN], day[LAN]
                wan.span = lan.span = args.daily
                header = f"day {days} ({args.daily / 3600:g}h)"
                if wan.lost or wan.restarts or wan.skews or lan.lost:
                    for text in wan.report(header, "hours", args.baseline, tz,
                                           lan if lan.sent else None):
                        screen.message(text, *style(text))
                    if not wan.gaps:
                        screen.message(
                            "    the internet never went down, only single packets dropped", 244
                        )
                else:
                    screen.message(
                        f"Internet was up for the whole {header}: {wan.sent:,} probes, 0 lost.", 46
                    )
                day = {lane: Bucket() for lane in lanes}
                next_day += args.daily

            if progress:                        # count the seconds until the next dot
                elapsed = int(now - nonlocal_slice[0]) + 1
                screen.show(str(min(elapsed, countdown_max)))

            line = fh.readline()
            if line:
                if not line.endswith("\n"):      # partial write; rewind and retry
                    fh.seek(-len(line.encode("utf-8")), os.SEEK_CUR)
                    stop.wait(0.05)
                    continue
                record = parse_line(line)
                if record:
                    apply(record)
                continue
            stop.wait(0.05)


# --------------------------------------------------------------------------- #
# offline analysis of an existing log
# --------------------------------------------------------------------------- #
def summarize(args: argparse.Namespace) -> int:
    totals = {WAN: Bucket(), LAN: Bucket()}
    first = last = None
    loss_ts: list[float] = []
    unverified: list[tuple[float, float]] = []      # logs written before GAP carried a count
    try:
        with open(args.log, "r", encoding="utf-8") as fh:
            for line in fh:
                record = parse_line(line)
                if not record:
                    continue
                ts, lane, kind, rest = record
                if lane not in totals:
                    continue
                total = totals[lane]
                first = ts if first is None else first
                last = ts
                if kind == SLICE:
                    total.sent += int(rest[0])
                    total.lost += int(rest[1])
                    if len(rest) > 2 and rest[2].isdigit():
                        total.inside += int(rest[2])
                elif kind == LOSS:
                    if lane == WAN:
                        loss_ts.append(ts)
                elif kind == GAP:
                    duration = float(rest[0])
                    if len(rest) < 2:
                        unverified.append((ts - duration, ts))
                    elif int(rest[1]):
                        total.gaps.append((ts - duration, ts))
                    else:
                        total.skews.append(duration)
                elif kind == SKEW:
                    total.skews.append(float(rest[0]))
                elif kind == RESTART:
                    total.restarts += 1
    except FileNotFoundError:
        print(f"No log file at {args.log}", file=sys.stderr)
        return 1
    if first is None:
        print("Log is empty.")
        return 0

    # Older logs recorded a silence without saying whether any probe was lost in
    # it. Check them the same way: a real outage has to swallow probes.
    total, lan = totals[WAN], totals[LAN]
    if unverified:
        loss_ts.sort()
        for start, end in unverified:
            if bisect.bisect_right(loss_ts, end) - bisect.bisect_left(loss_ts, start):
                total.gaps.append((start, end))
            else:
                total.skews.append(end - start)

    tz = zone(args.timezone)
    total.span = last - first
    fmt = "%Y-%m-%d %H:%M:%S.%f"
    print(f"Window:  {datetime.fromtimestamp(first, tz).strftime(fmt)[:-3]} -> "
          f"{datetime.fromtimestamp(last, tz).strftime(fmt)[:-3]} "
          f"{datetime.fromtimestamp(last, tz).strftime('%Z')}")
    print(f"Span:    {humanize(total.span, 'auto')}")
    inside, isolated = total.split_losses()
    if total.sent:
        rate = total.sent / total.span if total.span else 0
        print(f"Probes:  {total.sent:,} ({rate:.1f}/s), {total.lost:,} lost "
              f"({100 * total.lost / total.sent:.3f}%) = {inside:,} inside outages "
              f"+ {isolated:,} isolated drops")
    if lan.sent:
        print(f"Gateway: {lan.sent:,} probes, {lan.lost:,} lost "
              f"({100 * lan.lost / lan.sent:.3f}%), {len(lan.gaps)} gateway outages")
    if total.gaps:
        for text in total.report("total", "auto", args.baseline, tz, lan if lan.sent else None):
            print(text)
        print("Longest outages:")
        for i, (start, end) in enumerate(
            sorted(total.gaps, key=lambda g: g[1] - g[0], reverse=True)[:10], 1
        ):
            print(f"  {i:2}. {outage_lines([(start, end)], tz, lan_gaps=lan.gaps if lan.sent else None)[0].strip()}")
    elif total.lost:
        print(f"Drops:   {total.lost:,} isolated packets, no run longer than {args.gap:g}s")
        print("The internet never went down.")
    else:
        print("Internet was never down.")
    if total.skews:
        print(f"\nIgnored: {len(total.skews):,} timing anomalies totalling "
              f"{humanize(sum(total.skews), 'auto')} - stretches with no reply where no probe "
              f"was lost either.\n         The clock stepped or the process stalled; the link "
              f"did not go down.")
    return 0


# --------------------------------------------------------------------------- #
# rate calibration
# --------------------------------------------------------------------------- #
CALIBRATION_RATES = {
    "icmp": (0.01, 0.02, 0.05, 0.1, 0.2, 1.0),
    "dns": (0.001, 0.002, 0.005, 0.01, 0.02, 0.05),
}


def measure_icmp(args: argparse.Namespace, interval: float, seconds: float) -> tuple[int, int]:
    proc = subprocess.run(
        ["ping", "-q", "-n", "-i", str(interval), "-w", str(int(seconds)), args.host],
        capture_output=True, text=True, timeout=seconds + 15,
    )
    match = re.search(r"(\d+) packets transmitted, (\d+) received", proc.stdout)
    return (int(match[1]), int(match[2])) if match else (0, 0)


def measure_dns(args: argparse.Namespace, interval: float, seconds: float) -> tuple[int, int]:
    """Send cached DNS queries at a fixed rate and count the answers."""
    prober = DnsProber(args, threading.Event(), Journal(os.devnull))
    question = prober.query(args.query_name)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    sock.connect((args.resolver, args.resolver_port))
    sel = selectors.DefaultSelector()
    sel.register(sock, selectors.EVENT_READ)
    inflight: set[int] = set()
    sent = received = txid = 0
    end = time.monotonic() + seconds
    next_send = time.monotonic()
    try:
        while time.monotonic() < end + args.timeout:
            now = time.monotonic()
            if now >= next_send and now < end:
                txid = (txid + 1) & 0xFFFF
                try:
                    sock.send(struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0) + question)
                    sent += 1
                    inflight.add(txid)
                except OSError:
                    sent += 1
                next_send += interval
                if next_send < now - 1:
                    next_send = now + interval
            if sel.select(timeout=max(0.0, min(next_send - time.monotonic(), 0.02))):
                while True:
                    try:
                        data = sock.recv(2048)
                    except OSError:
                        break
                    if len(data) >= 4 and data[2] & 0x80:
                        if struct.unpack(">H", data[:2])[0] in inflight:
                            inflight.discard(struct.unpack(">H", data[:2])[0])
                            received += 1
    finally:
        sel.close()
        sock.close()
    return sent, received


def calibrate(args: argparse.Namespace) -> int:
    """Find how fast this link can be pinged before the network rate-limits us.

    Loss measured here is the floor: anything at or below it is the cost of the
    probing rate itself, not the internet being down.
    """
    seconds = args.calibrate
    target = args.host if args.probe == "icmp" else f"{args.resolver}:{args.resolver_port}"
    print(f"Calibrating {args.probe.upper()} against {target}, {seconds:g}s per rate. "
          "Pick the fastest rate whose loss stays near the slow rates.\n")
    print(f"{'interval':>9} {'pings/s':>8} {'sent':>7} {'lost':>6} {'loss':>8}")
    results: list[tuple[float, float, int]] = []
    measure = measure_icmp if args.probe == "icmp" else measure_dns
    for interval in CALIBRATION_RATES[args.probe]:
        sent, received = measure(args, interval, seconds)
        if not sent:
            print(f"{interval:>9g} {'-':>8} {'-':>7} {'-':>6} {'failed':>8}")
            continue
        lost = sent - received
        loss = 100 * lost / sent if sent else 100.0
        results.append((interval, loss, sent))
        print(f"{interval:>9g} {sent / seconds:>8.1f} {sent:>7,} {lost:>6,} {loss:>7.2f}%")

    if not results:
        return 1
    floor = min(loss for _i, loss, _s in results)
    good = [i for i, loss, _s in results if loss <= floor + args.calibrate_tolerance]
    best = min(good) if good else min(i for i, _l, _s in results)
    print(f"\nBaseline loss on this link: {floor:.2f}%.")
    print(f"Suggested: --probe {args.probe} --interval {best:g}  ({1 / best:.0f} probes/s, "
          f"{best * 1000:.0f}ms resolution, {5 / best:.0f}x finer than a 5s cadence)")
    if args.probe == "icmp" and floor > 0.5:
        print("This link polices ICMP. Try --probe dns, which is not rate limited the same way.")
    return 0


# --------------------------------------------------------------------------- #
# entry point
# --------------------------------------------------------------------------- #
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="net-checker",
        description="Ping a host as fast as it answers and report how long the internet was down.",
    )
    parser.add_argument("--probe", choices=("icmp", "dns"), default="icmp",
                        help="icmp = ping (often rate limited), dns = UDP DNS queries (not)")
    parser.add_argument("--host", default="google.com", help="host to ping (default: google.com)")
    parser.add_argument("--resolver", default="1.1.1.1",
                        help="resolver for --probe dns (default: 1.1.1.1; 8.8.8.8 also unpoliced)")
    parser.add_argument("--resolver-port", type=int, default=53, help="resolver port (default: 53)")
    parser.add_argument("--query-name", default="example.com",
                        help="name asked for in --probe dns; answered from cache (default: example.com)")
    parser.add_argument(
        "--interval",
        type=float,
        default=None,
        help="seconds between probes (default: 0.05 for icmp, 0.01 for dns); 0 uses ping -A, "
             "one packet per round trip, which most networks rate-limit -- run --calibrate first",
    )
    parser.add_argument("--timeout", type=float, default=2.0,
                        help="seconds before an unanswered packet counts as lost (default: 2)")
    parser.add_argument("--gap", type=float, default=1.0,
                        help="seconds without a reply that counts as an outage (default: 1)")
    parser.add_argument("--slice", type=float, default=5.0,
                        help="seconds of pings summarised by one trace character (default: 5)")
    parser.add_argument("--gateway", default="auto", metavar="IP",
                        help="also probe this address as a control lane, so an outage can be "
                             "blamed on the LAN or on the ISP; 'auto' finds the default route, "
                             "'off' disables it (default: auto)")
    parser.add_argument("--gateway-interval", type=float, default=0.05,
                        help="seconds between gateway probes (default: 0.05 = 20/s)")
    parser.add_argument("--log", default="net-checker.log", help="log file path")
    parser.add_argument("--log-mode", choices=("events", "all"), default="events",
                        help="'events' logs losses/outages/slices, 'all' also logs every reply")
    parser.add_argument("--report-every", type=float, default=4 * 3600,
                        help="seconds between summaries (default: 4h)")
    parser.add_argument("--daily", type=float, default=24 * 3600,
                        help="seconds between daily roll-ups (default: 24h)")
    parser.add_argument("--window-unit", choices=("auto", "seconds", "minutes", "hours"),
                        default="minutes", help="unit for the periodic summary (default: minutes)")
    parser.add_argument("--no-progress", dest="progress", action="store_false",
                        help="do not count seconds in place while a slice fills")
    parser.add_argument("--timezone", default=None, metavar="ZONE",
                        help="timezone for reported outage times, e.g. America/Los_Angeles "
                             "(default: this machine's)")
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto",
                        help="coloured unicode trace; 'never' falls back to . , : x (default: auto)")
    parser.add_argument("--baseline", type=float, default=5.0,
                        help="cadence to compare against in reports (default: 5s)")
    parser.add_argument("--duration", type=float, default=0,
                        help="stop after N hours (0 = run forever)")
    parser.add_argument("--summarize", action="store_true",
                        help="analyse an existing log and exit")
    parser.add_argument("--calibrate", type=float, nargs="?", const=15.0, default=0,
                        metavar="SECONDS",
                        help="measure loss at several ping rates (default 15s each) and exit")
    parser.add_argument("--calibrate-tolerance", type=float, default=1.0,
                        help="extra loss %% over the floor still considered clean (default: 1)")
    args = parser.parse_args(argv)
    if args.gateway == "auto":
        args.gateway = default_gateway()
    elif args.gateway == "off":
        args.gateway = None
    if args.interval is None:
        args.interval = 0.05 if args.probe == "icmp" else 0.01
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.calibrate:
        return calibrate(args)
    if args.summarize:
        return summarize(args)

    journal = Journal(args.log)
    start = time.monotonic()
    stop = threading.Event()
    cadence = (f"every {args.interval:g}s ({1 / args.interval:.0f}/s)" if args.interval
               else "adaptive (one packet per round trip)")
    target = args.host if args.probe == "icmp" else f"DNS {args.query_name} @ {args.resolver}"
    control = (f"Gateway control lane: {args.gateway} every {args.gateway_interval:g}s\n"
               if args.gateway else
               "No gateway lane: an outage cannot be blamed on the ISP rather than your LAN\n")
    print(
        f"Watching {target} with {args.probe} probes, {cadence} -> {args.log}\n"
        f"{control}"
        f"One character per {args.slice:g}s:  {legend(use_colour(args.color))}\n"
        f"Summary every {args.report_every / 3600:g}h, roll-up every {args.daily / 3600:g}h. Ctrl-C to stop."
    )

    threads = [
        threading.Thread(target=pinger, args=(args, stop, journal), name="wan", daemon=True),
        threading.Thread(target=reader, args=(args, stop, start), name="reader", daemon=True),
    ]
    if args.gateway:
        threads.insert(1, threading.Thread(
            target=pinger, args=(args, stop, journal, LAN, args.gateway), name="lan", daemon=True
        ))
    for thread in threads:
        thread.start()

    deadline = start + args.duration * 3600 if args.duration else None
    try:
        while True:
            if deadline and time.monotonic() >= deadline:
                break
            time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        for thread in threads:
            thread.join(timeout=5)
        journal.close()

    print()
    return summarize(args)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal.default_int_handler)
    raise SystemExit(main())
