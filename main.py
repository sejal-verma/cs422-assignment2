"""CS 422 Assignment 2 -- Part 1: iPerf Throughput Application.
See README.md for usage, the iperf3 protocol flow, and output files.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import random
import socket
import string
import struct
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

# ==============================================================================
# Run configuration (defaults; most can be overridden on the command line)
# ==============================================================================
N_DESTINATIONS = 10            # how many successful destinations we want (--n)
DURATION = 10.0                # seconds of sending per destination (--duration)
MAX_REPLACEMENT_ATTEMPTS = 30  # extra tries allowed when servers fail (--max-extra-attempts)
SAMPLE_INTERVAL = 0.2          # goodput sampling period in seconds (200 ms)

# Official JSON export of iperf3serverlist.net (the website table itself is
# rendered by JavaScript, so it can't be scraped with a plain HTTP request).
SERVER_LIST_URL = "https://export.iperf3serverlist.net/listed_iperf3_servers.json"
RESULTS_DIR = Path(".")        # output files go in the project folder

# ==============================================================================
# iperf3 protocol constants
# ==============================================================================
COOKIE_SIZE = 37               # iperf3 cookie: 36 random chars + NUL terminator

# Single-byte "state" values sent over the control connection.
# Positive values are normal protocol steps; negative values are errors.
TEST_START = 1
TEST_RUNNING = 2
TEST_END = 4
PARAM_EXCHANGE = 9
CREATE_STREAMS = 10
EXCHANGE_RESULTS = 13
DISPLAY_RESULTS = 14
IPERF_DONE = 16
ACCESS_DENIED = -1             # server is busy or rejected us
SERVER_ERROR = -2              # followed by two 4-byte error codes

DEFAULT_BLKSIZE = 128 * 1024   # bytes written per send() call (iperf3 default)
CONNECT_TIMEOUT = 5.0          # seconds to wait for a TCP connect
IO_TIMEOUT = 10.0              # seconds to wait for a control-channel read


# ==============================================================================
# Part 1(c): reading TCP statistics from the data socket
# ==============================================================================
class _TCPInfoPrefix(ctypes.Structure):
    """Leading fields of Linux's `struct tcp_info`.

    We only declare fields up to `tcpi_bytes_acked`, which is all Part 1 needs.
    ctypes applies the same natural alignment as the kernel's C struct, so
    tcpi_bytes_acked ends up at byte offset 120 without manual offset math.
    (Field order must match the kernel header exactly.)
    """
    _fields_ = [
        ("tcpi_state", ctypes.c_uint8),
        ("tcpi_ca_state", ctypes.c_uint8),
        ("tcpi_retransmits", ctypes.c_uint8),
        ("tcpi_probes", ctypes.c_uint8),
        ("tcpi_backoff", ctypes.c_uint8),
        ("tcpi_options", ctypes.c_uint8),
        ("tcpi_wscale_byte", ctypes.c_uint8),   # snd/rcv wscale packed in one byte
        ("tcpi_flags_byte", ctypes.c_uint8),    # delivery_rate_app_limited etc.
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
        ("tcpi_bytes_acked", ctypes.c_uint64),  # <-- the field Part 1(c) needs
    ]


# TCP_INFO option number; Python exposes socket.TCP_INFO on Linux, and the
# value is 11 there, so fall back to 11 if the constant is missing.
_TCP_INFO_OPT = getattr(socket, "TCP_INFO", 11)


def get_bytes_acked(data_sock: socket.socket) -> Optional[int]:
    """Return the cumulative number of bytes the peer has ACKed on this socket.

    Reads the kernel's TCP_INFO via getsockopt() and returns tcpi_bytes_acked.
    Returns None if the value can't be read (e.g. not running on Linux).
    """
    try:
        raw = data_sock.getsockopt(socket.IPPROTO_TCP, _TCP_INFO_OPT,
                                   ctypes.sizeof(_TCPInfoPrefix))
        # Older kernels may return a shorter struct that lacks bytes_acked.
        if len(raw) < ctypes.sizeof(_TCPInfoPrefix):
            return None
        return _TCPInfoPrefix.from_buffer_copy(raw).tcpi_bytes_acked
    except (OSError, AttributeError):
        return None


def get_congestion_algorithm(sock: socket.socket) -> str:
    """Return the name of the congestion-control algorithm the kernel is using
    for this socket (e.g. "cubic"), read via getsockopt(TCP_CONGESTION).
    Returns "unknown" if it can't be read."""
    try:
        opt = getattr(socket, "TCP_CONGESTION", 13)   # 13 on Linux
        raw = sock.getsockopt(socket.IPPROTO_TCP, opt, 16)
        return raw.split(b"\x00", 1)[0].decode("ascii") or "unknown"
    except (OSError, AttributeError, UnicodeDecodeError):
        return "unknown"


# ==============================================================================
# Part 1(a): low-level protocol helpers
# ==============================================================================
def make_cookie() -> bytes:
    """Build a random 37-byte iperf3 cookie (36 alphanumerics + NUL).

    The cookie identifies one test: it is sent on the control connection and
    again on the data connection so the server can pair the two.
    """
    body = "".join(random.choices(string.ascii_letters + string.digits, k=COOKIE_SIZE - 1))
    return (body + "\x00").encode("ascii")


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes from a TCP socket.

    TCP is a byte stream, so recv(n) may return fewer than n bytes. Loop until
    all n arrive, and raise if the peer closes the connection early.
    """
    chunks, remaining = [], n
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:  # empty read means the peer closed the connection
            raise ConnectionError(f"peer closed while expecting {n} bytes ({remaining} left)")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def send_json(sock: socket.socket, obj: dict) -> None:
    """Send a JSON message using iperf3 framing:
    a 4-byte big-endian length, followed by that many bytes of JSON text.
    """
    payload = json.dumps(obj).encode("utf-8")
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def recv_json(sock: socket.socket) -> dict:
    """Receive one length-prefixed JSON message (inverse of send_json)."""
    (length,) = struct.unpack("!I", recv_exact(sock, 4))
    # Sanity check: a garbage length would make us wait for gigabytes.
    if length > 1_000_000:
        raise ConnectionError(f"implausible JSON length {length}")
    return json.loads(recv_exact(sock, length).decode("utf-8"))


# ==============================================================================
# Data containers
# ==============================================================================
@dataclass
class GoodputSample:
    """One goodput measurement for a single sampling interval."""
    elapsed_s: float       # seconds since the send loop started
    bytes_acked: int       # cumulative ACKed bytes at this instant (from TCP_INFO)
    goodput_bps: float     # (delta bytes acked) * 8 / (delta time), bits per second


@dataclass
class TestResult:
    """Everything we learn from testing one destination."""
    host: str
    port: int
    success: bool = False                    # True only if the full protocol completed
    error: Optional[str] = None              # reason for failure, if any
    bytes_sent: int = 0                      # bytes handed to send() by our client
    duration_actual: float = 0.0             # real length of the send loop (s)
    algorithm: str = "unknown"               # TCP congestion control actually used
    server_results: Optional[dict] = None    # results JSON sent back by the server
    samples: list = field(default_factory=list)  # list[GoodputSample]


# ==============================================================================
# Part 1(a): the iperf3 client
# ==============================================================================
class Iperf3Client:
    """A minimal iperf3 client: one TCP stream, client -> server direction."""

    def __init__(
        self,
        host: str,
        port: int,
        duration: float = 10.0,
        blksize: int = DEFAULT_BLKSIZE,
        on_sample: Optional[Callable[[socket.socket, float, int], None]] = None,
    ):
        """
        host, port  : the iperf3 server to test
        duration    : seconds to send data
        blksize     : bytes per send() call
        on_sample   : callback invoked every SAMPLE_INTERVAL with
                      (data_socket, elapsed_seconds, bytes_sent_so_far);
                      used to record goodput without coupling this class to it
        """
        self.host = host
        self.port = port
        self.duration = duration
        self.blksize = blksize
        self.on_sample = on_sample
        self.cookie = make_cookie()
        self.ctrl_sock: Optional[socket.socket] = None   # control connection
        self.data_sock: Optional[socket.socket] = None   # data connection
        self._peer_ip: Optional[str] = None              # IP the control socket used

    def _open_control(self) -> None:
        """Step (i): open the control connection and send the cookie."""
        sock = socket.create_connection((self.host, self.port), timeout=CONNECT_TIMEOUT)
        sock.settimeout(IO_TIMEOUT)
        sock.sendall(self.cookie)
        self.ctrl_sock = sock
        # Remember the exact IP used so the data socket uses the same
        # address family / address (avoids an IPv4 vs IPv6 mismatch).
        self._peer_ip = sock.getpeername()[0]

    def _open_data_stream(self) -> None:
        """Step (iii): open the data connection and identify it with the cookie."""
        sock = socket.create_connection((self._peer_ip, self.port), timeout=CONNECT_TIMEOUT)
        sock.settimeout(IO_TIMEOUT)
        sock.sendall(self.cookie)
        self.data_sock = sock

    def _send_test_params(self) -> None:
        """Step (ii): send the JSON test parameters requested by the server."""
        send_json(self.ctrl_sock, {
            "tcp": True,                    # TCP test (not UDP/SCTP)
            "omit": 0,                      # no warm-up seconds to discard
            "time": int(self.duration),     # test length; iperf3 expects an integer
            "parallel": 1,                  # a single data stream
            "len": self.blksize,            # bytes per write
            "client_version": "3.9",        # iperf3 sends this; some servers check it
        })

    def _run_send_loop(self, result: TestResult) -> None:
        """Step (iv): send data for `duration` seconds while sampling goodput.

        Sampling is driven by a timer check at the top of each loop iteration,
        NOT by send() returning, so that a full send buffer (which makes send()
        block) can't delay or skip samples.
        """
        result.algorithm = get_congestion_algorithm(self.data_sock)
        buf = bytes(self.blksize)               # payload: a block of zero bytes
        start = time.monotonic()                # monotonic clock: immune to clock changes
        deadline = start + self.duration
        last_sample = start
        # Short timeout so send() never blocks long enough to delay sampling.
        self.data_sock.settimeout(SAMPLE_INTERVAL / 4)

        # Baseline sample at t=0 so the first interval is captured too.
        if self.on_sample:
            self.on_sample(self.data_sock, 0.0, 0)

        while True:
            now = time.monotonic()
            if now >= deadline:
                break

            # Sample on schedule, regardless of whether send() made progress.
            if self.on_sample and (now - last_sample) >= SAMPLE_INTERVAL:
                self.on_sample(self.data_sock, now - start, result.bytes_sent)
                last_sample = now

            try:
                # send() returns how many bytes were accepted (may be < blksize).
                result.bytes_sent += self.data_sock.send(buf)
            except socket.timeout:
                continue  # send buffer full; loop back to sample/check deadline
            except (BrokenPipeError, ConnectionResetError) as e:
                raise ConnectionError(f"data connection dropped mid-transfer: {e}")

        result.duration_actual = time.monotonic() - start
        # One last sample at the end. (The sampler ignores it if the interval
        # since the previous sample is too short to give a stable rate.)
        if self.on_sample:
            self.on_sample(self.data_sock, result.duration_actual, result.bytes_sent)

    def _send_results(self, result: TestResult) -> None:
        """Send our side's results JSON during EXCHANGE_RESULTS.

        The server requires the "streams" list; a results message without it
        is rejected. Stream id 1 is what iperf3 uses for a single stream.
        Fields we can't measure are sent as 0 or -1 (unknown).
        """
        send_json(self.ctrl_sock, {
            "cpu_util_total": 0.0,
            "cpu_util_user": 0.0,
            "cpu_util_system": 0.0,
            "sender_has_retransmits": -1,   # -1 = we don't report retransmits
            "streams": [{
                "id": 1,
                "bytes": result.bytes_sent,
                "retransmits": -1,
                "jitter": 0,
                "errors": 0,
                "packets": 0,
                "start_time": 0,
                "end_time": result.duration_actual,
            }],
        })

    def run(self) -> TestResult:
        """Run one complete iperf3 test and return the outcome.

        Never raises for network problems: any failure is captured in
        result.error and result.success stays False, so the caller can log it
        and move on to a replacement server.
        """
        result = TestResult(host=self.host, port=self.port)
        try:
            self._open_control()

            # The server drives the protocol by sending one state byte at a
            # time on the control connection; we react to each state.
            while True:
                state = struct.unpack("b", recv_exact(self.ctrl_sock, 1))[0]  # signed byte

                if state == PARAM_EXCHANGE:
                    self._send_test_params()
                elif state == CREATE_STREAMS:
                    self._open_data_stream()
                elif state == TEST_START:
                    pass  # nothing to do; wait for TEST_RUNNING
                elif state == TEST_RUNNING:
                    self._run_send_loop(result)
                    # Client is the one that ends the test; the server waits for this.
                    self.ctrl_sock.sendall(struct.pack("b", TEST_END))
                elif state == EXCHANGE_RESULTS:
                    self._send_results(result)
                    result.server_results = recv_json(self.ctrl_sock)
                elif state == DISPLAY_RESULTS:
                    # Final handshake step: tell the server we're done.
                    self.ctrl_sock.sendall(struct.pack("b", IPERF_DONE))
                    result.success = True
                    break
                elif state == ACCESS_DENIED:
                    raise ConnectionError("server sent ACCESS_DENIED (busy or rejected params)")
                elif state == SERVER_ERROR:
                    i_errno, _errno = struct.unpack("!ii", recv_exact(self.ctrl_sock, 8))
                    raise ConnectionError(f"server reported SERVER_ERROR (i_errno {i_errno})")
                else:
                    raise ConnectionError(f"unrecognized state byte {state} -- verify with Wireshark")

        # ---- robust error handling required by the assignment ----
        except socket.timeout:
            result.error = "timeout (server non-responsive)"
        except ConnectionRefusedError:
            result.error = "connection refused"
        except (ConnectionResetError, BrokenPipeError) as e:
            result.error = f"connection reset/broken pipe: {e}"
        except (ConnectionError, OSError) as e:
            result.error = str(e)   # includes premature close, ACCESS_DENIED, etc.
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            result.error = f"malformed JSON from server: {e}"
        finally:
            # Always close both sockets, even after an error.
            for s in (self.data_sock, self.ctrl_sock):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass

        return result


# ==============================================================================
# Part 1(b): destination selection
# ==============================================================================
class _Redirect308(urllib.request.HTTPRedirectHandler):
    """Python < 3.11 does not follow HTTP 308 redirects; treat 308 like 301."""
    def http_error_308(self, req, fp, code, msg, headers):
        return self.http_error_302(req, fp, 301, msg, headers)


def fetch_server_pool() -> list[tuple[str, int]]:
    """Download the public iperf3 server list and expand it to (host, port) pairs.

    Some entries list a port range such as "5201-5209"; ports in a range are
    equivalent listeners, so one is picked at random. Missing or unparseable
    ports fall back to the iperf3 default, 5201.
    """
    opener = urllib.request.build_opener(_Redirect308)
    req = urllib.request.Request(SERVER_LIST_URL, headers={"User-Agent": "cs422-iperf-client/1.0"})
    with opener.open(req, timeout=10) as resp:
        entries = json.loads(resp.read().decode("utf-8"))

    pool = []
    for entry in entries:
        host = (entry.get("IP/HOST") or "").strip()
        port_field = (entry.get("PORT") or "").strip()
        if not host:
            continue  # skip entries with no address

        if not port_field:
            port = 5201                                  # no port listed -> default
        elif "-" in port_field:                          # range, e.g. "5201-5209"
            try:
                lo, hi = (int(x) for x in port_field.split("-", 1))
                port = random.randint(lo, hi)
            except ValueError:
                port = 5201
        else:                                            # single port
            try:
                port = int(port_field)
            except ValueError:
                port = 5201

        pool.append((host, port))

    return pool


def select_destinations(n: int, duration: float, max_extra_attempts: int):
    """Randomly pick and test destinations until n succeed or attempts run out.

    Servers are tried in random order. A failed server (busy, timeout, stalled,
    etc.) is logged and replaced by the next candidate, up to
    n + max_extra_attempts total attempts. Any shortfall is reported.

    Returns (results, log_lines): the successful TestResults, and one log line
    per attempt (plus a SHORTFALL line if fewer than n were reached).
    """
    print(f"Fetching server pool from {SERVER_LIST_URL} ...")
    pool = fetch_server_pool()
    print(f"  {len(pool)} candidate servers available")

    random.shuffle(pool)           # random selection
    candidates = iter(pool)        # each server is tried at most once

    results: list[TestResult] = []
    log_lines: list[str] = []
    attempts_used = 0
    max_total_attempts = n + max_extra_attempts   # the "bounded number of attempts"

    while len(results) < n and attempts_used < max_total_attempts:
        try:
            host, port = next(candidates)
        except StopIteration:
            log_lines.append("Ran out of candidate servers before reaching n.")
            break

        attempts_used += 1
        print(f"[{attempts_used}/{max_total_attempts}] Testing {host}:{port} ...")

        # A fresh sampler per destination keeps each server's samples separate.
        sampler = GoodputSampler()
        client = Iperf3Client(host, port, duration=duration, on_sample=sampler.on_sample)
        result = client.run()
        result.samples = sampler.samples

        # A run that "succeeded" but produced far fewer samples than expected
        # means the connection stalled; its stats would be meaningless.
        min_samples = max(3, int(0.5 * duration / SAMPLE_INTERVAL))
        if result.success and len(result.samples) < min_samples:
            result.success = False
            result.error = (f"too few samples ({len(result.samples)} < {min_samples}); "
                            f"connection stalled")

        if result.success:
            print(f"  OK  ({result.bytes_sent} bytes sent)")
            log_lines.append(f"OK    {host}:{port}")
            results.append(result)
        else:
            print(f"  FAIL: {result.error} -- trying a replacement")
            log_lines.append(f"FAIL  {host}:{port}  error={result.error}")

    # Report any shortfall, as required by 1(b).
    shortfall = n - len(results)
    if shortfall > 0:
        log_lines.append(f"SHORTFALL: requested {n}, got {len(results)} "
                         f"(tried {attempts_used}/{max_total_attempts} attempts)")
        print(f"\nShortfall: requested {n} destinations, only {len(results)} succeeded "
              f"after {attempts_used} attempts.")
    else:
        print(f"\nReached target of {n} successful destinations.")

    return results, log_lines


# ==============================================================================
# Part 1(c): goodput sampling, plotting, summary table
# ==============================================================================
class GoodputSampler:
    """Turns periodic cumulative-ACK counters into goodput samples.

    goodput(t) = (bytes_acked_now - bytes_acked_previous) * 8 / (t_now - t_previous)

    Goodput counts only bytes the receiver has acknowledged, so it excludes
    data still sitting in the send buffer or lost in flight.
    """

    def __init__(self):
        self.samples: list[GoodputSample] = []
        self._last_time: Optional[float] = None    # time of the previous reading
        self._last_bytes: Optional[int] = None     # bytes_acked at the previous reading

    def on_sample(self, data_sock: socket.socket, elapsed_s: float, _bytes_sent: int) -> None:
        """Callback given to Iperf3Client; called once per sampling tick."""
        acked = get_bytes_acked(data_sock)
        if acked is None:
            return  # TCP_INFO unavailable (not Linux); nothing to record

        # The first call only records a baseline; a rate needs two readings.
        if self._last_time is not None:
            dt = elapsed_s - self._last_time
            if dt < SAMPLE_INTERVAL / 2:
                return  # too short an interval; would give a noisy goodput value
            dbytes = acked - self._last_bytes
            goodput_bps = (dbytes * 8 / dt) if dt > 0 else 0.0   # bytes -> bits
            self.samples.append(GoodputSample(elapsed_s, acked, goodput_bps))

        self._last_time = elapsed_s
        self._last_bytes = acked


def build_summary_table(results: list[TestResult]):
    """Build a per-destination table of min / median / mean / p95 goodput (Mbps).

    All samples are included, even zero-goodput ones: stalls are real behavior
    and should pull the minimum and median down. The 95th percentile uses
    pandas' default linear interpolation (same as numpy.percentile).
    """
    import pandas as pd  # imported here so the Docker launcher needs no pandas

    rows = []
    for r in results:
        if not r.samples:
            continue
        vals = pd.Series([s.goodput_bps / 1e6 for s in r.samples])   # bits/s -> Mbps
        rows.append({
            "destination": f"{r.host}:{r.port}",
            "algorithm": r.algorithm,     # read from the data socket (TCP_CONGESTION)
            "min_Mbps": vals.min(),
            "median_Mbps": vals.median(),
            "mean_Mbps": vals.mean(),
            "p95_Mbps": vals.quantile(0.95),
        })
    return pd.DataFrame(rows)


def plot_goodput(results: list[TestResult], out_path: Path) -> None:
    """Plot goodput over time, one panel per destination, saved to out_path."""
    import matplotlib
    matplotlib.use("Agg")  # non-interactive backend: works headless in Docker
    import matplotlib.pyplot as plt

    n = len(results)
    if n == 0:
        print("No successful results to plot.")
        return

    # One row of panels per destination; squeeze=False keeps axes 2-D even for n=1.
    fig, axes = plt.subplots(n, 1, figsize=(8, 3 * n), squeeze=False)
    for ax, r in zip(axes[:, 0], results):
        xs = [s.elapsed_s for s in r.samples]
        ys = [s.goodput_bps / 1e6 for s in r.samples]   # convert to Mbps for readability
        ax.plot(xs, ys, marker="o", markersize=2)
        ax.set_title(f"{r.host}:{r.port}")
        ax.set_xlabel("Time (s)")
        ax.set_ylabel("Goodput (Mbps)")
        ax.grid(True, alpha=0.3)

    fig.tight_layout()
    fig.savefig(out_path)
    plt.close(fig)
    print(f"Saved plot: {out_path}")


# ==============================================================================
# Docker launcher
# ==============================================================================
IMAGE_NAME = "cs422-assignment2"


def launch_in_docker(argv: list[str]) -> int:
    """Run this same script inside Docker and return its exit code.

    Called when main.py is started on the host. It builds the image, then runs
    a container with the same command-line arguments. The project folder is
    mounted at /app so output files appear on the host, and the container runs
    as the current user so those files aren't owned by root.
    """
    here = Path(__file__).resolve().parent
    print(f"[launcher] Building Docker image '{IMAGE_NAME}' ...")
    build = subprocess.run(["docker", "build", "-t", IMAGE_NAME, str(here)])
    if build.returncode != 0:
        print("[launcher] docker build failed.")
        return build.returncode

    print("[launcher] Running experiment in container ...")
    cmd = [
        "docker", "run", "--rm",
        "--user", f"{os.getuid()}:{os.getgid()}",   # keep output files owned by you
        "-e", "MPLCONFIGDIR=/tmp",                  # matplotlib needs a writable config dir
        "-v", f"{here}:/app",                       # share project folder with the container
        IMAGE_NAME,
    ] + argv
    return subprocess.run(cmd).returncode


# ==============================================================================
# Entry point
# ==============================================================================
def main():
    """Parse arguments, run the experiment, and write all outputs."""
    parser = argparse.ArgumentParser(description="CS 422 Assignment 2, Part 1")
    parser.add_argument("--n", type=int, default=N_DESTINATIONS,
                        help="number of destination servers to test (default: 10)")
    parser.add_argument("--duration", type=float, default=DURATION,
                        help="seconds to send data for per destination")
    parser.add_argument("--max-extra-attempts", type=int, default=MAX_REPLACEMENT_ATTEMPTS,
                        help="bounded extra attempts to replace failed destinations")
    parser.add_argument("--no-docker", action="store_true",
                        help="run directly on this machine instead of inside Docker")
    args = parser.parse_args()

    # On the host, hand off to Docker. Inside the container IN_DOCKER=1 is set
    # by the Dockerfile, so the experiment runs for real.
    if os.environ.get("IN_DOCKER") != "1" and not args.no_docker:
        forwarded = [a for a in sys.argv[1:] if a != "--no-docker"]
        sys.exit(launch_in_docker(forwarded))

    RESULTS_DIR.mkdir(exist_ok=True)

    # 1(a)+(b): pick destinations and run the iperf3 test against each.
    results, log_lines = select_destinations(args.n, args.duration, args.max_extra_attempts)

    # 1(b): record the servers tried, with pass/fail and any shortfall.
    log_path = RESULTS_DIR / "destination_log.txt"
    log_path.write_text("\n".join(log_lines) + "\n")
    print(f"Destination log written to {log_path}")

    if not results:
        print("No successful destinations -- nothing to plot or summarize.")
        sys.exit(1)

    # 1(c): save every raw goodput sample ("compute and record").
    samples_path = RESULTS_DIR / "goodput_samples.csv"
    with open(samples_path, "w") as f:
        f.write("destination,elapsed_s,bytes_acked,goodput_bps\n")
        for r in results:
            for s in r.samples:
                f.write(f"{r.host}:{r.port},{s.elapsed_s:.3f},{s.bytes_acked},{s.goodput_bps:.1f}\n")
    print(f"Raw samples written to {samples_path}")

    # 1(c): summary table (min / median / mean / p95 per destination).
    summary = build_summary_table(results)
    print("\nSummary (Mbps):")
    print(summary.to_string(index=False))
    summary.to_csv(RESULTS_DIR / "summary_table.csv", index=False)
    print(f"Summary table written to {RESULTS_DIR / 'summary_table.csv'}")

    # 1(c): goodput-vs-time plot, one panel per destination.
    plot_goodput(results, RESULTS_DIR / "goodput_plot.png")


if __name__ == "__main__":
    main()