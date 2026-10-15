"""CS 422 Assignment 2 -- Parts 1 & 2(a): iperf3 client + TCP statistics trace.

Run:   python main.py [OR] python main.py --n ... --duration ... --max-extra-attempts ... --algorithm ... --host ... --port ... --repetitions ...

Needs: Linux (for TCP_INFO), matplotlib, numpy.

Outputs: destination_log.txt, tcp_stats_trace.csv, summary_table.csv, goodput_plot.png, representative_tcp_time_series.pdf, representative_tcp_scatter.pdf


How the numbers are computed:
  decoding   : getsockopt(IPPROTO_TCP, TCP_INFO) on the DATA socket, decoded with a
               ctypes mirror of Linux `struct tcp_info` (fields in kernel order).
  goodput    : (bytes_acked_now - bytes_acked_prev) * 8 / (t_now - t_prev)   [bits/s]
  loss proxy : new_retrans = total_retrans_now - total_retrans_prev  [segments/interval]
               (lost = tcpi_lost, the kernel's current count of segments presumed lost)
"""

import argparse
import csv
import ctypes
import json
import random
import socket
import string
import struct
import sys
import time
import urllib.request
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Callable, Optional

import matplotlib
matplotlib.use("Agg")          # draw plots without a display
import matplotlib.pyplot as plt
import numpy as np

# configuration
N_DESTINATIONS = 10            # --n
DURATION = 10.0                # --duration (seconds of sending per destination)
MAX_REPLACEMENT_ATTEMPTS = 30  # --max-extra-attempts
SAMPLE_INTERVAL = 0.2          # seconds between samples
SERVER_LIST_URL = "https://export.iperf3serverlist.net/listed_iperf3_servers.json"
RESULTS_DIR = Path(".")

# protocol constants
COOKIE_SIZE = 37               # 36 random chars + NUL
TEST_START, TEST_RUNNING, TEST_END = 1, 2, 4          # iperf3 state bytes
PARAM_EXCHANGE, CREATE_STREAMS = 9, 10
EXCHANGE_RESULTS, DISPLAY_RESULTS, IPERF_DONE = 13, 14, 16
ACCESS_DENIED, SERVER_ERROR = -1, -2                  # negative = error
DEFAULT_BLKSIZE = 128 * 1024   # bytes per send()
CONNECT_TIMEOUT = 5.0
IO_TIMEOUT = 10.0


# ==============================================================================
# Reading TCP statistics from the data socket (Part 1(c) and 2(a))
# ==============================================================================
class _TCPInfoPrefix(ctypes.Structure):
    """Leading fields of Linux's `struct tcp_info`, in kernel order.
    ctypes uses the same alignment as C, so tcpi_bytes_acked lands at offset 120."""
    _fields_ = [
        ("tcpi_state", ctypes.c_uint8),
        ("tcpi_ca_state", ctypes.c_uint8),
        ("tcpi_retransmits", ctypes.c_uint8),
        ("tcpi_probes", ctypes.c_uint8),
        ("tcpi_backoff", ctypes.c_uint8),
        ("tcpi_options", ctypes.c_uint8),
        ("tcpi_wscale_byte", ctypes.c_uint8),   # snd/rcv wscale packed in one byte
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


_TCP_INFO_OPT = getattr(socket, "TCP_INFO", 11)   # 11 on Linux


def read_tcp_info(sock: socket.socket) -> Optional[_TCPInfoPrefix]:
    """Read and decode TCP_INFO. Returns None if unavailable (not Linux / old kernel)."""
    try:
        raw = sock.getsockopt(socket.IPPROTO_TCP, _TCP_INFO_OPT,
                              ctypes.sizeof(_TCPInfoPrefix))
    except OSError:
        return None
    if len(raw) < ctypes.sizeof(_TCPInfoPrefix):
        return None
    return _TCPInfoPrefix.from_buffer_copy(raw)


def get_congestion_algorithm(sock: socket.socket) -> str:
    """Congestion control algorithm the kernel is using for this socket."""
    try:
        opt = getattr(socket, "TCP_CONGESTION", 13)   # 13 on Linux
        raw = sock.getsockopt(socket.IPPROTO_TCP, opt, 16)
        return raw.split(b"\x00", 1)[0].decode("ascii") or "unknown"
    except (OSError, UnicodeDecodeError):
        return "unknown"


#part 3a
def set_congestion_algorithm(sock: socket.socket, algorithm: str) -> None:
    """Set the TCP congestion-control algorithm for this socket."""

    if algorithm not in ("cubic", "reno", "bbr"):
        raise ValueError(f"Unsupported congestion-control algorithm: {algorithm}")

    opt = getattr(socket, "TCP_CONGESTION", 13)

    sock.setsockopt(
        socket.IPPROTO_TCP,
        opt,
        algorithm.encode("ascii")
    )


# ==============================================================================
# iperf3 protocol helpers (Part 1(a))
# ==============================================================================
def make_cookie() -> bytes:
    """Random 37-byte cookie; sent on both connections so the server can pair them."""
    body = "".join(random.choices(string.ascii_letters + string.digits, k=COOKIE_SIZE - 1))
    return (body + "\x00").encode("ascii")


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """TCP is a byte stream: keep reading until exactly n bytes have arrived."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError(f"peer closed while expecting {n} bytes")
        data += chunk
    return data


def send_json(sock: socket.socket, obj: dict) -> None:
    """iperf3 framing: 4-byte big-endian length, then the JSON text."""
    payload = json.dumps(obj).encode("utf-8")
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def recv_json(sock: socket.socket) -> dict:
    (length,) = struct.unpack("!I", recv_exact(sock, 4))
    if length > 1_000_000:                      # garbage length: don't wait for GBs
        raise ConnectionError(f"implausible JSON length {length}")
    return json.loads(recv_exact(sock, length).decode("utf-8"))


# ==============================================================================
# Data containers
# ==============================================================================
@dataclass
class TCPSample:
    """One sampling interval. Units are in the field names."""
    elapsed_s: float         # seconds since the send loop started
    goodput_bps: float       # bits/s, from the change in bytes_acked
    snd_cwnd: int            # congestion window, segments
    rtt_us: int              # smoothed RTT, microseconds
    rttvar_us: int           # RTT variation, microseconds
    total_retrans: int       # cumulative retransmitted segments
    new_retrans: int         # retransmitted segments during this interval (loss proxy)
    lost: int                # segments the kernel currently presumes lost
    pacing_rate_Bps: int     # bytes/s
    bytes_acked: int         # cumulative bytes ACKed


@dataclass
class TestResult:
    """Everything we learn from testing one destination."""
    host: str
    port: int
    run_id: str = ""
    success: bool = False
    error: Optional[str] = None
    bytes_sent: int = 0
    duration_actual: float = 0.0
    algorithm: str = "unknown"
    server_results: Optional[dict] = None
    samples: list = field(default_factory=list)   # list[TCPSample]


# ==============================================================================
# Sampler: turns periodic TCP_INFO readings into TCPSamples
# ==============================================================================
class TCPStatsSampler:
    """Callback object for Iperf3Client. The first call only records a baseline
    (a rate needs two readings); every later call appends one TCPSample."""

    def __init__(self):
        self.samples: list[TCPSample] = []
        self._prev = None      # (elapsed_s, bytes_acked, total_retrans) at last reading

    def on_sample(self, data_sock: socket.socket, elapsed_s: float, _bytes_sent: int) -> None:
        info = read_tcp_info(data_sock)
        if info is None:
            return

        if self._prev is not None:
            prev_t, prev_acked, prev_retrans = self._prev
            dt = elapsed_s - prev_t                      # actual elapsed time
            if dt < SAMPLE_INTERVAL / 2:
                return                                   # too short: noisy rate
            self.samples.append(TCPSample(
                elapsed_s=round(elapsed_s, 3),
                goodput_bps=round((info.tcpi_bytes_acked - prev_acked) * 8 / dt, 1),
                snd_cwnd=info.tcpi_snd_cwnd,
                rtt_us=info.tcpi_rtt,
                rttvar_us=info.tcpi_rttvar,
                total_retrans=info.tcpi_total_retrans,
                new_retrans=info.tcpi_total_retrans - prev_retrans,
                lost=info.tcpi_lost,
                pacing_rate_Bps=info.tcpi_pacing_rate,
                bytes_acked=info.tcpi_bytes_acked,
            ))

        self._prev = (elapsed_s, info.tcpi_bytes_acked, info.tcpi_total_retrans)


# ==============================================================================
# The iperf3 client (Part 1(a))
# ==============================================================================
class Iperf3Client:
    """A minimal iperf3 client: one TCP stream, client -> server direction."""

    def __init__(self, host: str, port: int, duration: float = 10.0,
                 blksize: int = DEFAULT_BLKSIZE,
                 on_sample: Optional[Callable[[socket.socket, float, int], None]] = None,
                 algorithm: str = "cubic"):
        self.host = host
        self.port = port
        self.duration = duration
        self.blksize = blksize
        self.on_sample = on_sample        # called every SAMPLE_INTERVAL with (data_sock, elapsed, bytes_sent)
        self.algorithm = algorithm
        self.cookie = make_cookie()
        self.ctrl_sock: Optional[socket.socket] = None
        self.data_sock: Optional[socket.socket] = None
        self._peer_ip: Optional[str] = None

    def _open_control(self) -> None:
        """Step (i): control connection + cookie."""
        sock = socket.create_connection((self.host, self.port), timeout=CONNECT_TIMEOUT)
        sock.settimeout(IO_TIMEOUT)
        sock.sendall(self.cookie)
        self.ctrl_sock = sock
        self._peer_ip = sock.getpeername()[0]   # reuse the exact IP for the data socket

    def _open_data_stream(self) -> None:
        """Step (iii): data connection + the same cookie."""
        family = self.ctrl_sock.family
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(CONNECT_TIMEOUT)
        set_congestion_algorithm(sock, self.algorithm)
        sock.connect((self._peer_ip, self.port))
        sock.settimeout(IO_TIMEOUT)
        sock.sendall(self.cookie)
        self.data_sock = sock

    def _send_test_params(self) -> None:
        """Step (ii): JSON test parameters."""
        send_json(self.ctrl_sock, {
            "tcp": True, "omit": 0, "time": int(self.duration),
            "parallel": 1, "len": self.blksize, "client_version": "3.9",
        })

    def _run_send_loop(self, result: TestResult) -> None:
        """Step (iv): send zeros for `duration` seconds, sampling on a timer.

        Sampling is checked at the top of every iteration (not after send()
        returns), so a full send buffer can't delay or skip samples."""
        result.algorithm = get_congestion_algorithm(self.data_sock)
        buf = bytes(self.blksize)
        start = time.monotonic()
        deadline = start + self.duration
        last_sample = start
        self.data_sock.settimeout(SAMPLE_INTERVAL / 4)   # send() never blocks long

        if self.on_sample:
            self.on_sample(self.data_sock, 0.0, 0)       # baseline at t=0

        while True:
            now = time.monotonic()
            if now >= deadline:
                break
            if self.on_sample and (now - last_sample) >= SAMPLE_INTERVAL:
                self.on_sample(self.data_sock, now - start, result.bytes_sent)
                last_sample = now
            try:
                result.bytes_sent += self.data_sock.send(buf)
            except socket.timeout:
                continue                                 # buffer full; go sample / check deadline
            except (BrokenPipeError, ConnectionResetError) as e:
                raise ConnectionError(f"data connection dropped mid-transfer: {e}")

        result.duration_actual = time.monotonic() - start
        if self.on_sample:
            self.on_sample(self.data_sock, result.duration_actual, result.bytes_sent)

    def _send_results(self, result: TestResult) -> None:
        """Our side's results JSON; the server rejects it without "streams"."""
        send_json(self.ctrl_sock, {
            "cpu_util_total": 0.0, "cpu_util_user": 0.0, "cpu_util_system": 0.0,
            "sender_has_retransmits": -1,
            "streams": [{"id": 1, "bytes": result.bytes_sent, "retransmits": -1,
                         "jitter": 0, "errors": 0, "packets": 0,
                         "start_time": 0, "end_time": result.duration_actual}],
        })

    def run(self) -> TestResult:
        """Run one full iperf3 test. Never raises for network problems:
        failures are stored in result.error so the caller can pick a replacement."""
        result = TestResult(host=self.host, port=self.port)
        try:
            self._open_control()
            # The server drives the protocol with one state byte at a time.
            while True:
                state = struct.unpack("b", recv_exact(self.ctrl_sock, 1))[0]   # signed

                if state == PARAM_EXCHANGE:
                    self._send_test_params()
                elif state == CREATE_STREAMS:
                    self._open_data_stream()
                elif state == TEST_START:
                    pass
                elif state == TEST_RUNNING:
                    self._run_send_loop(result)
                    self.ctrl_sock.sendall(struct.pack("b", TEST_END))   # step (v)
                elif state == EXCHANGE_RESULTS:
                    self._send_results(result)
                    result.server_results = recv_json(self.ctrl_sock)
                elif state == DISPLAY_RESULTS:
                    self.ctrl_sock.sendall(struct.pack("b", IPERF_DONE))
                    result.success = True
                    break
                elif state == ACCESS_DENIED:
                    raise ConnectionError("server sent ACCESS_DENIED (busy or rejected params)")
                elif state == SERVER_ERROR:
                    i_errno, _ = struct.unpack("!ii", recv_exact(self.ctrl_sock, 8))
                    raise ConnectionError(f"server reported SERVER_ERROR (i_errno {i_errno})")
                else:
                    raise ConnectionError(f"unrecognized state byte {state}")

        except socket.timeout:
            result.error = "timeout (server non-responsive)"
        except ConnectionRefusedError:
            result.error = "connection refused"
        except (ConnectionResetError, BrokenPipeError) as e:
            result.error = f"connection reset/broken pipe: {e}"
        except (ConnectionError, OSError) as e:
            result.error = str(e)          # premature close, ACCESS_DENIED, DNS errors, ...
        except ValueError as e:            # JSONDecodeError / UnicodeDecodeError
            result.error = f"malformed JSON from server: {e}"
        finally:
            for s in (self.data_sock, self.ctrl_sock):
                if s is not None:
                    s.close()
        return result


# ==============================================================================
# Destination selection (Part 1(b))
# ==============================================================================
def fetch_server_pool() -> list[tuple[str, int]]:
    """Download the public server list as (host, port) pairs.
    A port range like "5201-5209" -> one random port from it; missing/bad -> 5201."""
    req = urllib.request.Request(SERVER_LIST_URL, headers={"User-Agent": "cs422-iperf-client/1.0"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        entries = json.loads(resp.read().decode("utf-8"))

    pool = []
    for entry in entries:
        host = (entry.get("IP/HOST") or "").strip()
        if not host:
            continue
        lo, _, hi = (entry.get("PORT") or "").strip().partition("-")
        try:
            port = random.randint(int(lo), int(hi or lo))
        except ValueError:
            port = 5201
        pool.append((host, port))
    return pool


def select_destinations(n: int, duration: float, max_extra_attempts: int, algorithm: str):
    """Test random servers until n succeed or n + max_extra_attempts are used.
    Returns (successful TestResults, log lines)."""
    print(f"Fetching server pool from {SERVER_LIST_URL} ...")
    pool = fetch_server_pool()
    print(f"  {len(pool)} candidate servers available")
    random.shuffle(pool)

    results, log_lines = [], []
    attempts = 0
    max_attempts = n + max_extra_attempts

    for host, port in pool:
        if len(results) >= n or attempts >= max_attempts:
            break
        attempts += 1
        print(f"[{attempts}/{max_attempts}] Testing {host}:{port} ...")

        sampler = TCPStatsSampler()          # fresh sampler keeps servers separate
        client = Iperf3Client(
            host,
            port,
            duration=duration,
            on_sample=sampler.on_sample,
            algorithm=algorithm
        )
        result = client.run()
        result.samples = sampler.samples
        result.run_id = f"run_{attempts}"

        if result.success and not result.samples:      # e.g. TCP_INFO unavailable
            result.success = False
            result.error = "no TCP_INFO samples recorded"

        if result.success:
            print(f"  OK  ({result.bytes_sent} bytes sent)")
            log_lines.append(f"OK    {host}:{port}")
            results.append(result)
        else:
            print(f"  FAIL: {result.error} -- trying a replacement")
            log_lines.append(f"FAIL  {host}:{port}  error={result.error}")

    if len(results) < n:
        msg = (f"SHORTFALL: requested {n}, got {len(results)} "
               f"(tried {attempts}/{max_attempts} attempts)")
        log_lines.append(msg)
        print("\n" + msg)
    else:
        print(f"\nReached target of {n} successful destinations.")
    return results, log_lines


def run_fixed_destination(host: str, port: int, duration: float,
                          algorithm: str, repetitions: int):
    results, log_lines = [], []

    for repetition in range(1, repetitions + 1):
        print(f"[{repetition}/{repetitions}] Testing {host}:{port} "
              f"with {algorithm} ...")

        sampler = TCPStatsSampler()
        client = Iperf3Client(
            host,
            port,
            duration=duration,
            on_sample=sampler.on_sample,
            algorithm=algorithm
        )

        result = client.run()
        result.samples = sampler.samples
        result.run_id = f"{algorithm}_run_{repetition}"

        if result.success and not result.samples:
            result.success = False
            result.error = "no TCP_INFO samples recorded"

        if result.success:
            print(f"  OK  ({result.bytes_sent} bytes sent)")
            log_lines.append(
                f"OK    {host}:{port}  algorithm={result.algorithm}  "
                f"run={repetition}"
            )
            results.append(result)
        else:
            print(f"  FAIL: {result.error}")
            log_lines.append(
                f"FAIL  {host}:{port}  algorithm={algorithm}  "
                f"run={repetition}  error={result.error}"
            )

    return results, log_lines


# ==============================================================================
# Outputs: trace CSV, summary table, plot
# ==============================================================================
def write_trace_csv(results: list[TestResult], path: Path) -> None:
    """One row per sample, with destination / run_id / algorithm on every row."""
    columns = ["destination", "run_id", "algorithm"] + [f.name for f in fields(TCPSample)]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        for r in results:
            for s in r.samples:
                writer.writerow({"destination": f"{r.host}:{r.port}", "run_id": r.run_id,
                                 "algorithm": r.algorithm, **asdict(s)})


def build_summary_table(results: list[TestResult]) -> list[dict]:
    """Min / median / mean / p95 goodput (Mbps) per destination.
    All samples count, even zero-goodput ones: stalls are real behavior."""
    rows = []
    for r in results:
        mbps = np.array([s.goodput_bps for s in r.samples]) / 1e6
        rows.append({
            "destination": f"{r.host}:{r.port}",
            "run_id": r.run_id,
            "algorithm": r.algorithm,
            "min_Mbps": mbps.min(),
            "median_Mbps": np.median(mbps),
            "mean_Mbps": mbps.mean(),
            "p95_Mbps": np.percentile(mbps, 95),
        })
    return rows


def write_summary_csv(rows: list[dict], path: Path) -> None:
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def plot_goodput(results: list[TestResult], out_path: Path) -> None:
    """Goodput over time, one panel per destination."""
    fig, axes = plt.subplots(len(results), 1, figsize=(8, 3 * len(results)), squeeze=False)
    for ax, r in zip(axes[:, 0], results):
        ax.plot([s.elapsed_s for s in r.samples],
                [s.goodput_bps / 1e6 for s in r.samples], marker="o", markersize=2)
        ax.set_title(f"{r.host}:{r.port} ({r.algorithm})")
        ax.set_xlabel("Time (s)")
        ax.set_ylabel("Goodput (Mbps)")
        ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(out_path)
    plt.close(fig)
    print(f"Saved plot: {out_path}")

def generate_representative_plots(results: list[TestResult], out_dir: Path) -> None:
    """Write PDF time-series and relationship plots for a representative run.

    The representative destination is the successful run whose mean goodput is
    closest to the median mean goodput across all successful destinations.
    The congestion-control algorithm is only observed from TCP_CONGESTION; this
    method does not change the kernel's default algorithm.
    """
    representative = min(
        results,
        key=lambda result: abs(
            np.mean([sample.goodput_bps for sample in result.samples])
            - np.median([
                np.mean([sample.goodput_bps for sample in candidate.samples])
                for candidate in results
            ])
        ),
    )
    samples = representative.samples
    title = (f"Representative destination: {representative.host}:{representative.port} "
             f"({representative.algorithm})")

    elapsed = [sample.elapsed_s for sample in samples]
    goodput_mbps = [sample.goodput_bps / 1e6 for sample in samples]
    cwnd = [sample.snd_cwnd for sample in samples]
    rtt_ms = [sample.rtt_us / 1e3 for sample in samples]
    loss_signal = [sample.new_retrans for sample in samples]

    fig, axes = plt.subplots(4, 1, figsize=(9, 11), sharex=True)
    time_series = [
        (cwnd, "snd_cwnd (segments)"),
        (rtt_ms, "RTT (ms)"),
        (loss_signal, "Loss proxy: new retransmissions (segments/interval)"),
        (goodput_mbps, "Throughput / goodput (Mbps)"),
    ]
    for ax, (values, ylabel) in zip(axes, time_series):
        ax.plot(elapsed, values, marker="o", markersize=2, linewidth=1)
        ax.set_ylabel(ylabel)
        ax.grid(True, alpha=0.3)
    axes[-1].set_xlabel("Time (s)")
    fig.suptitle(title)
    fig.tight_layout()
    time_series_path = out_dir / "representative_tcp_time_series.pdf"
    fig.savefig(time_series_path)
    plt.close(fig)

    fig, axes = plt.subplots(1, 3, figsize=(15, 4.5))
    scatter_data = [
        (cwnd, "snd cwnd (segments)", "snd cwnd vs goodput"),
        (rtt_ms, "RTT (ms)", "RTT vs goodput"),
        (loss_signal, "New retransmissions (segments/interval)",
         "Loss signal vs goodput"),
    ]
    for ax, (values, xlabel, plot_title) in zip(axes, scatter_data):
        ax.scatter(values, goodput_mbps, alpha=0.75)
        ax.set_xlabel(xlabel)
        ax.set_ylabel("Goodput (Mbps)")
        ax.set_title(plot_title)
        ax.grid(True, alpha=0.3)
    fig.suptitle(title)
    fig.tight_layout()
    scatter_path = out_dir / "representative_tcp_scatter.pdf"
    fig.savefig(scatter_path)
    plt.close(fig)

    print(f"Saved representative plots: {time_series_path}, {scatter_path}")

# ==============================================================================
# Entry point
# ==============================================================================
def main():
    parser = argparse.ArgumentParser(description="CS 422 Assignment 2, Parts 1 and 2(a)")
    parser.add_argument("--n", type=int, default=N_DESTINATIONS,
                        help="number of destination servers to test (default: 10)")
    parser.add_argument("--duration", type=float, default=DURATION,
                        help="seconds to send data for per destination")
    parser.add_argument("--max-extra-attempts", type=int, default=MAX_REPLACEMENT_ATTEMPTS,
                        help="bounded extra attempts to replace failed destinations")
    parser.add_argument("--algorithm", choices=["cubic", "reno", "bbr"], default="cubic",
                        help="TCP congestion-control algorithm: cubic, reno, or bbr")
    parser.add_argument("--host", default="speedtest.lagoon.nc",
                        help="fixed destination host for repeated tests")
    parser.add_argument("--port", type=int, default="5202",
                        help="fixed destination port for repeated tests")
    parser.add_argument("--repetitions", type=int, default=1,
                        help="number of repetitions for a fixed destination")
    args = parser.parse_args()

    RESULTS_DIR.mkdir(exist_ok=True)

    # 1(a) + 1(b): pick destinations and run the iperf3 test on each
    if args.host:
        if args.port is None:
            parser.error("--port is required when --host is provided")

        results, log_lines = run_fixed_destination(
            args.host,
            args.port,
            args.duration,
            args.algorithm,
            args.repetitions
        )
    else:
        results, log_lines = select_destinations(
            args.n,
            args.duration,
            args.max_extra_attempts,
            args.algorithm
        )

    output_prefix = args.algorithm
    (RESULTS_DIR / f"{output_prefix}_destination_log.txt").write_text(
        "\n".join(log_lines) + "\n"
    )

    if not results:
        print("No successful destinations -- nothing to plot or summarize.")
        sys.exit(1)

    # 1(c) + 2(a): every sample, with goodput and TCP stats side by side
    write_trace_csv(
        results,
        RESULTS_DIR / f"{output_prefix}_tcp_stats_trace.csv"
    )

    # 1(c): summary table
    rows = build_summary_table(results)
    write_summary_csv(
        rows,
        RESULTS_DIR / f"{output_prefix}_summary_table.csv"
    )
    print("\nSummary (Mbps):")
    for row in rows:
        print(f"  {row['destination']:<30} {row['algorithm']:<8} "
              f"min={row['min_Mbps']:.2f}  median={row['median_Mbps']:.2f}  "
              f"mean={row['mean_Mbps']:.2f}  p95={row['p95_Mbps']:.2f}")

    # 1(c): goodput-versus-time plot
    plot_goodput(
        results,
        RESULTS_DIR / f"{output_prefix}_goodput_plot.png"
    )

    # 2(b): representative TCP time-series and relationship plots
    generate_representative_plots(results, RESULTS_DIR)

if __name__ == "__main__":
    main()