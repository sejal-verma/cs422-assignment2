"""CS 422 Assignment 2 -- Parts 1 & 2: iPerf Throughput & TCP Statistics Tracing.

See README.md for usage, the iperf3 protocol flow, and output files.

Everything that touches the network uses only Python's standard library:
  socket   plain TCP sockets, getsockopt() for TCP statistics
  struct   packing/unpacking protocol bytes
  json     the iperf3 JSON messages
  ctypes   decoding the kernel's struct tcp_info returned by getsockopt()
  urllib   downloading the public server list
No iperf3 binary, no iperf3 library, and no custom receiver are used.
The only third-party package is matplotlib, used just to draw the plot.

Layout of this file (search for the banners below)
  Configuration
  PART 1(a)  iperf3 client written from scratch with plain sockets
  PART 1(b)  destination selection, failure logging, bounded replacement
  PART 1(c)  goodput from TCP_INFO, summary table, plot
  PART 2(a)  TCP statistics tracing
  Launcher   optional Docker hand-off, then the entry point
"""

from __future__ import annotations

import argparse
import csv
import ctypes
import json
import os
import random
import socket
import statistics
import string
import struct
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional


# ##############################################################################
# CONFIGURATION
# Defaults used when no command-line option is given (see main() for the flags).
# ##############################################################################

N_DESTINATIONS = 10
DURATION = 10.0
MAX_REPLACEMENT_ATTEMPTS = 30
SAMPLE_INTERVAL = 0.2

SERVER_LIST_URL = (
    "https://export.iperf3serverlist.net/listed_iperf3_servers.json"
)

RESULTS_DIR = Path(".")


# ##############################################################################
# PART 1(a) | iPerf3 client
# ##############################################################################

COOKIE_SIZE = 37

TEST_START = 1
TEST_RUNNING = 2
TEST_END = 4
PARAM_EXCHANGE = 9
CREATE_STREAMS = 10
EXCHANGE_RESULTS = 13
DISPLAY_RESULTS = 14
IPERF_DONE = 16
ACCESS_DENIED = -1
SERVER_ERROR = -2

DEFAULT_BLKSIZE = 128 * 1024
CONNECT_TIMEOUT = 5.0
IO_TIMEOUT = 10.0


# ==============================================================================
# Part 1(c) & Part 2(a): reading TCP statistics from the data socket
# ==============================================================================

class _TCPInfoPrefix(ctypes.Structure):
    """Leading and extended fields of Linux's struct tcp_info."""

    _fields_ = [
        ("tcpi_state", ctypes.c_uint8),
        ("tcpi_ca_state", ctypes.c_uint8),
        ("tcpi_retransmits", ctypes.c_uint8),
        ("tcpi_probes", ctypes.c_uint8),
        ("tcpi_backoff", ctypes.c_uint8),
        ("tcpi_options", ctypes.c_uint8),
        ("tcpi_wscale_byte", ctypes.c_uint8),
        ("tcpi_flags_byte", ctypes.c_uint8),
        ("tcpi_rto", ctypes.c_uint32),
        ("tcpi_ato", ctypes.c_uint32),
        ("tcpi_snd_mss", ctypes.c_uint32),
        ("tcpi_rcv_mss", ctypes.c_uint32),
        ("tcpi_unacked", ctypes.c_uint32),
        ("tcpi_sacked", ctypes.c_uint32),
        ("tcpi_lost", ctypes.c_uint32),
        ("tcpi_retrans", ctypes.c_uint32),
        ("tcpi_fackets", ctypes.c_uint32),
        ("tcpi_last_data_sent", ctypes.c_uint32),
        ("tcpi_last_ack_sent", ctypes.c_uint32),
        ("tcpi_last_data_recv", ctypes.c_uint32),
        ("tcpi_last_ack_recv", ctypes.c_uint32),
        ("tcpi_pmtu", ctypes.c_uint32),
        ("tcpi_rcv_ssthresh", ctypes.c_uint32),
        ("tcpi_rtt", ctypes.c_uint32),
        ("tcpi_rttvar", ctypes.c_uint32),
        ("tcpi_snd_ssthresh", ctypes.c_uint32),
        ("tcpi_snd_cwnd", ctypes.c_uint32),
        ("tcpi_advmss", ctypes.c_uint32),
        ("tcpi_reordering", ctypes.c_uint32),
        ("tcpi_rcv_rtt", ctypes.c_uint32),
        ("tcpi_rcv_space", ctypes.c_uint32),
        ("tcpi_total_retrans", ctypes.c_uint32),
        ("tcpi_pacing_rate", ctypes.c_uint64),
        ("tcpi_max_pacing_rate", ctypes.c_uint64),
        ("tcpi_bytes_acked", ctypes.c_uint64),
    ]


_TCP_INFO_OPT = getattr(socket, "TCP_INFO", 11)


def get_bytes_acked(data_sock: socket.socket) -> Optional[int]:
    """Return cumulative bytes ACKed on this TCP socket."""

    try:
        raw = data_sock.getsockopt(
            socket.IPPROTO_TCP,
            _TCP_INFO_OPT,
            ctypes.sizeof(_TCPInfoPrefix),
        )

        if len(raw) < ctypes.sizeof(_TCPInfoPrefix):
            return None

        return _TCPInfoPrefix.from_buffer_copy(raw).tcpi_bytes_acked

    except (OSError, AttributeError):
        return None


def get_congestion_algorithm(sock: socket.socket) -> str:
    """Return the congestion-control algorithm used by this socket."""

    try:
        opt = getattr(socket, "TCP_CONGESTION", 13)
        raw = sock.getsockopt(socket.IPPROTO_TCP, opt, 16)

        return (
            raw.split(b"\x00", 1)[0].decode("ascii")
            or "unknown"
        )

    except (OSError, AttributeError, UnicodeDecodeError):
        return "unknown"


# ==============================================================================
# Part 1(a): low-level protocol helpers
# ==============================================================================

def make_cookie() -> bytes:
    """Build a random 37-byte iperf3 cookie."""

    body = "".join(
        random.choices(
            string.ascii_letters + string.digits,
            k=COOKIE_SIZE - 1,
        )
    )

    return (body + "\x00").encode("ascii")


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes from a TCP byte stream."""

    chunks = []
    remaining = n

    while remaining > 0:
        chunk = sock.recv(remaining)

        if not chunk:
            raise ConnectionError(
                f"peer closed while expecting {n} bytes "
                f"({remaining} left)"
            )

        chunks.append(chunk)
        remaining -= len(chunk)

    return b"".join(chunks)


def send_json(sock: socket.socket, obj: dict) -> None:
    """Send an iperf3 length-prefixed JSON message."""

    payload = json.dumps(obj).encode("utf-8")

    sock.sendall(
        struct.pack("!I", len(payload)) + payload
    )


def recv_json(sock: socket.socket) -> dict:
    """Receive an iperf3 length-prefixed JSON message."""

    (length,) = struct.unpack(
        "!I",
        recv_exact(sock, 4),
    )

    if length > 1_000_000:
        raise ConnectionError(
            f"implausible JSON length {length}"
        )

    return json.loads(
        recv_exact(sock, length).decode("utf-8")
    )


# ==============================================================================
# Data containers
# ==============================================================================

@dataclass
class GoodputSample:
    elapsed_s: float
    bytes_acked: int
    goodput_bps: float

    destination: str = ""
    algorithm: str = "unknown"
    run_id: str = ""

    snd_cwnd: int = 0

    rtt_us: float = 0.0
    rtt_ms: float = 0.0
    rttvar_us: int = 0

    total_retrans: int = 0
    lost: int = 0

    pacing_rate_bps: int = 0


@dataclass
class TestResult:
    host: str
    port: int

    success: bool = False
    error: Optional[str] = None

    bytes_sent: int = 0
    duration_actual: float = 0.0

    algorithm: str = "unknown"

    server_results: Optional[dict] = None
    samples: list = field(default_factory=list)


# ==============================================================================
# Part 1(a): iperf3 client
# ==============================================================================

class Iperf3Client:

    def __init__(
        self,
        host: str,
        port: int,
        duration: float = 10.0,
        blksize: int = DEFAULT_BLKSIZE,
        on_sample: Optional[
            Callable[[socket.socket, float, int], None]
        ] = None,
    ):
        self.host = host
        self.port = port
        self.duration = duration
        self.blksize = blksize
        self.on_sample = on_sample

        self.cookie = make_cookie()

        self.ctrl_sock: Optional[socket.socket] = None
        self.data_sock: Optional[socket.socket] = None

        self._peer_ip: Optional[str] = None

    def _open_control(self) -> None:
        """Step (i): open the control connection."""

        sock = socket.create_connection(
            (self.host, self.port),
            timeout=CONNECT_TIMEOUT,
        )

        sock.settimeout(IO_TIMEOUT)
        sock.sendall(self.cookie)

        self.ctrl_sock = sock

        self._peer_ip = sock.getpeername()[0]

    def _open_data_stream(self) -> None:
        """Step (iii): open the data connection."""

        sock = socket.create_connection(
            (self._peer_ip, self.port),
            timeout=CONNECT_TIMEOUT,
        )

        sock.settimeout(IO_TIMEOUT)
        sock.sendall(self.cookie)

        self.data_sock = sock

    def _send_test_params(self) -> None:
        """Step (ii): send JSON test parameters."""

        send_json(
            self.ctrl_sock,
            {
                "tcp": True,
                "omit": 0,
                "time": int(self.duration),
                "parallel": 1,
                "len": self.blksize,
                "client_version": "3.9",
            },
        )

    def _run_send_loop(
        self,
        result: TestResult,
    ) -> None:
        """Step (iv): continuously send TCP data."""

        result.algorithm = get_congestion_algorithm(
            self.data_sock
        )

        sampler = getattr(
            self.on_sample,
            "__self__",
            None,
        )

        if (
            sampler is not None
            and hasattr(sampler, "set_algorithm")
        ):
            sampler.set_algorithm(result.algorithm)

        buf = bytes(self.blksize)

        start = time.monotonic()
        deadline = start + self.duration

        last_sample = start

        self.data_sock.settimeout(
            SAMPLE_INTERVAL / 4
        )

        # Baseline TCP_INFO sample.
        if self.on_sample:
            self.on_sample(
                self.data_sock,
                0.0,
                0,
            )

        while True:
            now = time.monotonic()

            if now >= deadline:
                break

            if (
                self.on_sample
                and (now - last_sample) >= SAMPLE_INTERVAL
            ):
                self.on_sample(
                    self.data_sock,
                    now - start,
                    result.bytes_sent,
                )

                last_sample = now

            try:
                result.bytes_sent += (
                    self.data_sock.send(buf)
                )

            except socket.timeout:
                continue

            except (
                BrokenPipeError,
                ConnectionResetError,
            ) as e:
                raise ConnectionError(
                    "data connection dropped "
                    f"mid-transfer: {e}"
                )

        result.duration_actual = (
            time.monotonic() - start
        )

        if self.on_sample:
            self.on_sample(
                self.data_sock,
                result.duration_actual,
                result.bytes_sent,
            )

    def _send_results(
        self,
        result: TestResult,
    ) -> None:

        send_json(
            self.ctrl_sock,
            {
                "cpu_util_total": 0.0,
                "cpu_util_user": 0.0,
                "cpu_util_system": 0.0,

                "sender_has_retransmits": -1,

                "streams": [
                    {
                        "id": 1,
                        "bytes": result.bytes_sent,
                        "retransmits": -1,
                        "jitter": 0,
                        "errors": 0,
                        "packets": 0,
                        "start_time": 0,
                        "end_time":
                            result.duration_actual,
                    }
                ],
            },
        )

    def run(self) -> TestResult:
        """Run one complete iperf3 test."""

        result = TestResult(
            host=self.host,
            port=self.port,
        )

        try:
            self._open_control()

            while True:

                state = struct.unpack(
                    "b",
                    recv_exact(
                        self.ctrl_sock,
                        1,
                    ),
                )[0]

                if state == PARAM_EXCHANGE:
                    self._send_test_params()

                elif state == CREATE_STREAMS:
                    self._open_data_stream()

                elif state == TEST_START:
                    pass

                elif state == TEST_RUNNING:

                    self._run_send_loop(result)

                    self.ctrl_sock.sendall(
                        struct.pack(
                            "b",
                            TEST_END,
                        )
                    )

                elif state == EXCHANGE_RESULTS:

                    self._send_results(result)

                    result.server_results = (
                        recv_json(
                            self.ctrl_sock
                        )
                    )

                elif state == DISPLAY_RESULTS:

                    self.ctrl_sock.sendall(
                        struct.pack(
                            "b",
                            IPERF_DONE,
                        )
                    )

                    result.success = True
                    break

                elif state == ACCESS_DENIED:

                    raise ConnectionError(
                        "server sent ACCESS_DENIED "
                        "(busy or rejected params)"
                    )

                elif state == SERVER_ERROR:

                    i_errno, _errno = (
                        struct.unpack(
                            "!ii",
                            recv_exact(
                                self.ctrl_sock,
                                8,
                            ),
                        )
                    )

                    raise ConnectionError(
                        "server reported SERVER_ERROR "
                        f"(i_errno {i_errno})"
                    )

                else:

                    raise ConnectionError(
                        "unrecognized state byte "
                        f"{state} -- verify with Wireshark"
                    )

        except socket.timeout:
            result.error = (
                "timeout (server non-responsive)"
            )

        except ConnectionRefusedError:
            result.error = "connection refused"

        except (
            ConnectionResetError,
            BrokenPipeError,
        ) as e:

            result.error = (
                "connection reset/broken pipe: "
                f"{e}"
            )

        except (
            ConnectionError,
            OSError,
        ) as e:

            result.error = str(e)

        except (
            json.JSONDecodeError,
            UnicodeDecodeError,
        ) as e:

            result.error = (
                "malformed JSON from server: "
                f"{e}"
            )

        finally:

            for s in (
                self.data_sock,
                self.ctrl_sock,
            ):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass

        return result


# ##############################################################################
# PART 1(b) | Destination selection
# ##############################################################################

class _Redirect308(
    urllib.request.HTTPRedirectHandler
):

    def http_error_308(
        self,
        req,
        fp,
        code,
        msg,
        headers,
    ):
        return self.http_error_302(
            req,
            fp,
            301,
            msg,
            headers,
        )


def fetch_server_pool() -> list[
    tuple[str, int]
]:
    """Download and parse the public iperf3 server list."""

    opener = urllib.request.build_opener(
        _Redirect308
    )

    req = urllib.request.Request(
        SERVER_LIST_URL,
        headers={
            "User-Agent":
                "cs422-iperf-client/1.0"
        },
    )

    with opener.open(
        req,
        timeout=10,
    ) as resp:

        entries = json.loads(
            resp.read().decode("utf-8")
        )

    pool = []

    for entry in entries:

        host = (
            entry.get("IP/HOST")
            or ""
        ).strip()

        port_field = (
            entry.get("PORT")
            or ""
        ).strip()

        if not host:
            continue

        if not port_field:

            port = 5201

        elif "-" in port_field:

            try:
                lo, hi = (
                    int(x)
                    for x in port_field.split(
                        "-",
                        1,
                    )
                )

                port = random.randint(
                    lo,
                    hi,
                )

            except ValueError:
                port = 5201

        else:

            try:
                port = int(port_field)

            except ValueError:
                port = 5201

        pool.append(
            (host, port)
        )

    return pool


def select_destinations(
    n: int,
    duration: float,
    max_extra_attempts: int,
):
    """Try random destinations until n tests succeed."""

    print(
        "Fetching server pool from "
        f"{SERVER_LIST_URL} ..."
    )

    pool = fetch_server_pool()

    print(
        f"  {len(pool)} candidate servers available"
    )

    random.shuffle(pool)

    candidates = iter(pool)

    results: list[TestResult] = []
    log_lines: list[str] = []

    attempts_used = 0

    max_total_attempts = (
        n + max_extra_attempts
    )

    while (
        len(results) < n
        and attempts_used < max_total_attempts
    ):

        try:
            host, port = next(candidates)

        except StopIteration:

            log_lines.append(
                "Ran out of candidate servers "
                "before reaching n."
            )

            break

        attempts_used += 1

        print(
            f"[{attempts_used}/"
            f"{max_total_attempts}] "
            f"Testing {host}:{port} ..."
        )

        destination_str = (
            f"{host}:{port}"
        )

        sampler = TCPStatsSampler(
            destination=destination_str,
            algorithm="unknown",
            run_id=f"run_{attempts_used}",
        )

        client = Iperf3Client(
            host,
            port,
            duration=duration,
            on_sample=sampler.on_sample,
        )

        result = client.run()

        result.samples = sampler.samples

        min_samples = max(
            3,
            int(
                0.5
                * duration
                / SAMPLE_INTERVAL
            ),
        )

        if (
            result.success
            and len(result.samples)
            < min_samples
        ):

            result.success = False

            result.error = (
                "too few samples "
                f"({len(result.samples)} "
                f"< {min_samples}); "
                "connection stalled"
            )

        if result.success:

            print(
                "  OK  "
                f"({result.bytes_sent} "
                "bytes sent)"
            )

            log_lines.append(
                f"OK    {host}:{port}"
            )

            results.append(result)

        else:

            print(
                f"  FAIL: {result.error} "
                "-- trying a replacement"
            )

            log_lines.append(
                f"FAIL  {host}:{port}  "
                f"error={result.error}"
            )

    shortfall = (
        n - len(results)
    )

    if shortfall > 0:

        log_lines.append(
            "SHORTFALL: requested "
            f"{n}, got {len(results)} "
            f"(tried {attempts_used}/"
            f"{max_total_attempts} attempts)"
        )

        print(
            "\nShortfall: requested "
            f"{n} destinations, only "
            f"{len(results)} succeeded "
            f"after {attempts_used} attempts."
        )

    else:

        print(
            "\nReached target of "
            f"{n} successful destinations."
        )

    return results, log_lines


# ==============================================================================
# Part 1(c) & Part 2(a): TCP statistics sampling
# ==============================================================================

class TCPStatsSampler:
    """Capture TCP_INFO and calculate interval goodput."""

    def __init__(
        self,
        destination: str,
        algorithm: str = "unknown",
        run_id: str = "run_1",
    ):
        self.destination = destination
        self.algorithm = algorithm
        self.run_id = run_id

        self.samples: list[
            GoodputSample
        ] = []

        self._last_time: Optional[
            float
        ] = None

        self._last_bytes: Optional[
            int
        ] = None

    def set_algorithm(
        self,
        algorithm: str,
    ) -> None:

        self.algorithm = algorithm

    def on_sample(
        self,
        data_sock: socket.socket,
        elapsed_s: float,
        _bytes_sent: int,
    ) -> None:

        try:
            raw = data_sock.getsockopt(
                socket.IPPROTO_TCP,
                _TCP_INFO_OPT,
                ctypes.sizeof(
                    _TCPInfoPrefix
                ),
            )

            if (
                len(raw)
                < ctypes.sizeof(
                    _TCPInfoPrefix
                )
            ):
                return

            info = (
                _TCPInfoPrefix
                .from_buffer_copy(raw)
            )

        except (
            OSError,
            AttributeError,
        ):
            return

        acked = (
            info.tcpi_bytes_acked
        )

        goodput_bps = 0.0

        if (
            self._last_time
            is not None
        ):

            dt = (
                elapsed_s
                - self._last_time
            )

            if (
                dt
                < SAMPLE_INTERVAL / 2
            ):
                return

            dbytes = (
                acked
                - self._last_bytes
            )

            if dt > 0:
                goodput_bps = (
                    dbytes * 8 / dt
                )

        self.samples.append(
            GoodputSample(
                elapsed_s=round(
                    elapsed_s,
                    3,
                ),
                bytes_acked=acked,
                goodput_bps=round(
                    goodput_bps,
                    2,
                ),
                destination=(
                    self.destination
                ),
                algorithm=(
                    self.algorithm
                ),
                run_id=self.run_id,
                snd_cwnd=(
                    info.tcpi_snd_cwnd
                ),
                rtt_us=float(
                    info.tcpi_rtt
                ),
                rtt_ms=round(
                    info.tcpi_rtt
                    / 1000.0,
                    3,
                ),
                rttvar_us=(
                    info.tcpi_rttvar
                ),
                total_retrans=(
                    info.tcpi_total_retrans
                ),
                lost=info.tcpi_lost,
                pacing_rate_bps=(
                    info.tcpi_pacing_rate
                ),
            )
        )

        self._last_time = elapsed_s
        self._last_bytes = acked


# ==============================================================================
# Part 2(a): detailed TCP statistics export
# ==============================================================================

def save_tcp_stats_export(
    results: list[TestResult],
    csv_path: Path,
    json_metadata_path: Path,
) -> None:

    with open(
        csv_path,
        "w",
        encoding="utf-8",
    ) as f:

        f.write(
            "destination,run_id,algorithm,"
            "elapsed_s,goodput_bps,snd_cwnd,"
            "rtt_us,rtt_ms,rttvar_us,"
            "total_retrans,lost,"
            "pacing_rate_bps,bytes_acked\n"
        )

        for result in results:

            for sample in result.samples:

                f.write(
                    f"{sample.destination},"
                    f"{sample.run_id},"
                    f"{sample.algorithm},"
                    f"{sample.elapsed_s:.3f},"
                    f"{sample.goodput_bps:.1f},"
                    f"{sample.snd_cwnd},"
                    f"{sample.rtt_us:.1f},"
                    f"{sample.rtt_ms:.3f},"
                    f"{sample.rttvar_us},"
                    f"{sample.total_retrans},"
                    f"{sample.lost},"
                    f"{sample.pacing_rate_bps},"
                    f"{sample.bytes_acked}\n"
                )

    print(
        "Detailed TCP stats CSV "
        f"written to {csv_path}"
    )

    metadata = {
        "description":
            "Part 2(a) TCP Statistics "
            "& Goodput Export",

        "kernel_decoding": (
            "Extracted via getsockopt"
            "(IPPROTO_TCP, TCP_INFO, "
            "struct tcp_info) using a "
            "ctypes prefix mapping."
        ),

        "metrics": {

            "elapsed_s": {
                "unit": "seconds",
                "description":
                    "Time elapsed since "
                    "send loop start via "
                    "monotonic clock.",
            },

            "goodput_bps": {
                "unit": "bits/second",
                "formula":
                    "(delta bytes_acked * 8) "
                    "/ delta time",
            },

            "snd_cwnd": {
                "unit":
                    "segments/packets",
                "field":
                    "tcpi_snd_cwnd",
            },

            "rtt_us": {
                "unit": "microseconds",
                "field": "tcpi_rtt",
            },

            "rtt_ms": {
                "unit": "milliseconds",
                "formula":
                    "rtt_us / 1000.0",
            },

            "rttvar_us": {
                "unit": "microseconds",
                "field": "tcpi_rttvar",
            },

            "total_retrans": {
                "unit": "packet count",
                "field":
                    "tcpi_total_retrans "
                    "(Loss Signal)",
            },

            "lost": {
                "unit": "packet count",
                "field":
                    "tcpi_lost "
                    "(Loss Proxy)",
            },

            "pacing_rate_bps": {
                "unit": "bytes/second",
                "field":
                    "tcpi_pacing_rate",
            },

            "bytes_acked": {
                "unit": "bytes",
                "field":
                    "tcpi_bytes_acked",
            },
        },
    }

    json_metadata_path.write_text(
        json.dumps(
            metadata,
            indent=4,
        ),
        encoding="utf-8",
    )

    print(
        "TCP stats metadata "
        "documentation written to "
        f"{json_metadata_path}"
    )


# ==============================================================================
# Part 1(c): goodput summary
# ==============================================================================

SUMMARY_COLUMNS = [
    "destination",
    "algorithm",
    "min_Mbps",
    "median_Mbps",
    "mean_Mbps",
    "p95_Mbps",
]


def _percentile(
    values: list[float],
    pct: float,
) -> float:
    """Calculate a percentile using linear interpolation."""

    ordered = sorted(values)

    if len(ordered) == 1:
        return ordered[0]

    pos = (
        pct / 100
    ) * (
        len(ordered) - 1
    )

    lo = int(pos)

    hi = min(
        lo + 1,
        len(ordered) - 1,
    )

    return (
        ordered[lo]
        + (
            ordered[hi]
            - ordered[lo]
        )
        * (pos - lo)
    )


def build_summary_table(
    results: list[TestResult],
) -> list[dict]:

    rows = []

    for r in results:

        if not r.samples:
            continue

        vals = [
            s.goodput_bps / 1e6
            for s in r.samples
        ]

        rows.append(
            {
                "destination":
                    f"{r.host}:{r.port}",

                "algorithm":
                    r.algorithm,

                "min_Mbps":
                    min(vals),

                "median_Mbps":
                    statistics.median(
                        vals
                    ),

                "mean_Mbps":
                    statistics.mean(
                        vals
                    ),

                "p95_Mbps":
                    _percentile(
                        vals,
                        95,
                    ),
            }
        )

    return rows


def print_summary_table(
    rows: list[dict],
) -> None:

    if not rows:
        print(
            "(no samples to summarize)"
        )
        return

    def fmt(v):
        if isinstance(v, float):
            return f"{v:.6f}"

        return str(v)

    table = [
        [
            fmt(row[c])
            for c in SUMMARY_COLUMNS
        ]
        for row in rows
    ]

    widths = [
        max(
            [len(h)]
            + [
                len(line[i])
                for line in table
            ]
        )
        for i, h in enumerate(
            SUMMARY_COLUMNS
        )
    ]

    print(
        "  ".join(
            h.rjust(w)
            for h, w in zip(
                SUMMARY_COLUMNS,
                widths,
            )
        )
    )

    for line in table:

        print(
            "  ".join(
                cell.rjust(w)
                for cell, w in zip(
                    line,
                    widths,
                )
            )
        )


def write_summary_csv(
    rows: list[dict],
    path: Path,
) -> None:

    with open(
        path,
        "w",
        newline="",
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=SUMMARY_COLUMNS,
            lineterminator="\n",
        )

        writer.writeheader()
        writer.writerows(rows)


# ==============================================================================
# Part 1(c): goodput plot
# ==============================================================================

def plot_goodput(
    results: list[TestResult],
    out_path: Path,
) -> None:

    import matplotlib

    matplotlib.use("Agg")

    import matplotlib.pyplot as plt

    n = len(results)

    if n == 0:
        print(
            "No successful results to plot."
        )
        return

    fig, axes = plt.subplots(
        n,
        1,
        figsize=(8, 3 * n),
        squeeze=False,
    )

    for ax, r in zip(
        axes[:, 0],
        results,
    ):

        xs = [
            s.elapsed_s
            for s in r.samples
        ]

        ys = [
            s.goodput_bps / 1e6
            for s in r.samples
        ]

        ax.plot(
            xs,
            ys,
            marker="o",
            markersize=2,
        )

        ax.set_title(
            f"{r.host}:{r.port}"
        )

        ax.set_xlabel(
            "Time (s)"
        )

        ax.set_ylabel(
            "Goodput (Mbps)"
        )

        ax.grid(
            True,
            alpha=0.3,
        )

    fig.tight_layout()

    fig.savefig(out_path)

    plt.close(fig)

    print(
        f"Saved plot: {out_path}"
    )


# ##############################################################################
# DOCKER LAUNCHER
# ##############################################################################

IMAGE_NAME = "cs422-assignment2"


def launch_in_docker(
    argv: list[str],
) -> int:

    here = (
        Path(__file__)
        .resolve()
        .parent
    )

    print(
        "[launcher] Building Docker image "
        f"'{IMAGE_NAME}' ..."
    )

    build = subprocess.run(
        [
            "docker",
            "build",
            "-t",
            IMAGE_NAME,
            str(here),
        ]
    )

    if build.returncode != 0:

        print(
            "[launcher] docker build failed."
        )

        return build.returncode

    print(
        "[launcher] Running experiment "
        "in container ..."
    )

    cmd = [
        "docker",
        "run",
        "--rm",

        "--user",
        f"{os.getuid()}:{os.getgid()}",

        "-e",
        "MPLCONFIGDIR=/tmp",

        "-v",
        f"{here}:/app",

        IMAGE_NAME,
    ] + argv

    return subprocess.run(
        cmd
    ).returncode


# ##############################################################################
# ENTRY POINT
# ##############################################################################

def main():

    parser = argparse.ArgumentParser(
        description=(
            "CS 422 Assignment 2, "
            "Parts 1 & 2"
        )
    )

    parser.add_argument(
        "--n",
        type=int,
        default=N_DESTINATIONS,
        help=(
            "number of destination "
            "servers to test "
            "(default: 10)"
        ),
    )

    parser.add_argument(
        "--duration",
        type=float,
        default=DURATION,
        help=(
            "seconds to send data "
            "for per destination"
        ),
    )

    parser.add_argument(
        "--max-extra-attempts",
        type=int,
        default=MAX_REPLACEMENT_ATTEMPTS,
        help=(
            "bounded extra attempts "
            "to replace failed "
            "destinations"
        ),
    )

    parser.add_argument(
        "--no-docker",
        action="store_true",
        help=(
            "run directly on this "
            "machine instead of "
            "inside Docker"
        ),
    )

    args = parser.parse_args()

    # Run inside Docker unless explicitly disabled.
    if (
        os.environ.get("IN_DOCKER") != "1"
        and not args.no_docker
    ):

        forwarded = [
            a
            for a in sys.argv[1:]
            if a != "--no-docker"
        ]

        sys.exit(
            launch_in_docker(
                forwarded
            )
        )

    RESULTS_DIR.mkdir(
        exist_ok=True
    )

    # --------------------------------------------------------------------------
    # Parts 1(a) + 1(b)
    # --------------------------------------------------------------------------

    results, log_lines = (
        select_destinations(
            args.n,
            args.duration,
            args.max_extra_attempts,
        )
    )

    # --------------------------------------------------------------------------
    # Part 1(b): destination log
    # --------------------------------------------------------------------------

    log_path = (
        RESULTS_DIR
        / "destination_log.txt"
    )

    log_path.write_text(
        "\n".join(log_lines) + "\n"
    )

    print(
        "Destination log written to "
        f"{log_path}"
    )

    if not results:

        print(
            "No successful destinations "
            "-- nothing to plot or "
            "summarize."
        )

        sys.exit(1)

    # --------------------------------------------------------------------------
    # Part 1(c): raw goodput samples
    # --------------------------------------------------------------------------

    samples_path = (
        RESULTS_DIR
        / "goodput_samples.csv"
    )

    with open(
        samples_path,
        "w",
        newline="",
    ) as f:

        writer = csv.writer(
            f,
            lineterminator="\n",
        )

        writer.writerow(
            [
                "destination",
                "elapsed_s",
                "bytes_acked",
                "goodput_bps",
            ]
        )

        for r in results:

            for s in r.samples:

                writer.writerow(
                    [
                        f"{r.host}:{r.port}",
                        f"{s.elapsed_s:.3f}",
                        s.bytes_acked,
                        f"{s.goodput_bps:.1f}",
                    ]
                )

    print(
        "Raw samples written to "
        f"{samples_path}"
    )

    # --------------------------------------------------------------------------
    # Part 2(a): detailed TCP statistics
    # --------------------------------------------------------------------------

    save_tcp_stats_export(
        results,
        RESULTS_DIR
        / "tcp_stats_trace.csv",
        RESULTS_DIR
        / "tcp_stats_metadata.json",
    )

    # --------------------------------------------------------------------------
    # Part 1(c): summary statistics
    # --------------------------------------------------------------------------

    summary_rows = (
        build_summary_table(
            results
        )
    )

    print(
        "\nSummary (Mbps):"
    )

    print_summary_table(
        summary_rows
    )

    summary_path = (
        RESULTS_DIR
        / "summary_table.csv"
    )

    write_summary_csv(
        summary_rows,
        summary_path,
    )

    print(
        "Summary table written to "
        f"{summary_path}"
    )

    # --------------------------------------------------------------------------
    # Part 1(c): goodput plot
    # --------------------------------------------------------------------------

    plot_goodput(
        results,
        RESULTS_DIR
        / "goodput_plot.png",
    )


if __name__ == "__main__":
    main()