# CS 422 Assignment 2: iPerf, TCP Statistics, and Congestion Control

A from-scratch Python iperf3 client (raw sockets, no iperf3 binary) that:

- **(1a)** speaks the iperf3 TCP protocol against public iperf3 servers,
- **(1b)** picks destinations (random from the public list, or one fixed host) and replaces failed ones (bounded),
- **(1c)** measures goodput from `TCP_INFO` (`tcpi_bytes_acked`) and writes a CSV, a summary table and a plot,
- **(2a/2b)** logs TCP stats (cwnd, RTT, loss proxy) next to goodput and plots a representative run as PDFs,
- **(3a)** selects CUBIC, Reno or BBR on the data socket before connecting.

Everything lives in `main.py`.

## Requirements

- Linux, or Windows with WSL2 (a real Linux kernel is needed for `TCP_INFO`)
- Python 3, `matplotlib`, `numpy` (see `requirements.txt`)
- Docker (optional, see below)
- For `--algorithm bbr`: the `tcp_bbr` module must be loaded
  (`sudo modprobe tcp_bbr`) and the algorithm must be allowed
  (`cat /proc/sys/net/ipv4/tcp_available_congestion_control`).
  Unprivileged sockets also need it in `tcp_allowed_congestion_control`.

Host kernel used for our results: `<output of uname -r>`

## How to run

```bash
# one fixed destination, 3 repetitions, one algorithm per invocation
python3 main.py --host speedtest.lagoon.nc --port 5202 --duration 10 --repetitions 3 --algorithm cubic
python3 main.py --host speedtest.lagoon.nc --port 5202 --duration 10 --repetitions 3 --algorithm reno
python3 main.py --host speedtest.lagoon.nc --port 5202 --duration 10 --repetitions 3 --algorithm bbr
```

Docker:

```bash
docker build -t cs422-assignment2 .
docker run --rm -e MPLCONFIGDIR=/tmp -v "$PWD:/app" cs422-assignment2 \
  --host speedtest.lagoon.nc --port 5202 --duration 10 --repetitions 3 --algorithm bbr
```

The container uses the host kernel, so congestion-control availability and the
`TCP_INFO` layout come from the host.

### Command-line options

| Option | Default | Meaning |
|---|---|---|
| `--algorithm` | cubic | `cubic`, `reno` or `bbr`; set on the data socket before `connect()` |
| `--host` | speedtest.lagoon.nc | Fixed destination host (repeated tests) |
| `--port` | 5202 | Port for the fixed destination |
| `--repetitions` | 1 | Number of runs against the fixed destination |
| `--duration` | 10.0 | Seconds of sending per run |
| `--n` | 10 | Number of successful destinations wanted (random-selection mode) |
| `--max-extra-attempts` | 30 | Extra servers to try when some fail (bounded) |

The sampling interval (`SAMPLE_INTERVAL`, 0.2 s) is a constant near the top of `main.py`.

## Output files

Every file name starts with the algorithm (`cubic_`, `reno_` or `bbr_`):

| File | Contents |
|---|---|
| `*_destination_log.txt` | Every attempt, OK/FAIL with reason, and any shortfall |
| `*_tcp_stats_trace.csv` | One row per sample: destination, run_id, algorithm, elapsed_s, goodput_bps, snd_cwnd (segments), rtt_us, rttvar_us, total_retrans, new_retrans, lost, pacing_rate_Bps, bytes_acked |
| `*_summary_table.csv` | Per run: min / median / mean / p95 goodput (Mbps) and the algorithm read back from the socket |
| `*_goodput_plot.png` | Goodput over time, one panel per run |
| `*_representative_tcp_time_series.pdf` | snd_cwnd, RTT, loss proxy and goodput over time |
| `*_representative_tcp_scatter.pdf` | snd_cwnd, RTT and loss proxy versus goodput |

The representative run is the successful run whose mean goodput is closest to the median
of the mean goodputs. Axis limits are fixed constants in `generate_representative_plots`
so the three algorithms can be compared directly.

## How the numbers are computed

- **Decoding:** `getsockopt(IPPROTO_TCP, TCP_INFO)` on the data socket, decoded with a ctypes
  mirror of the leading fields of Linux `struct tcp_info`, in kernel order
  (`tcpi_bytes_acked` is at byte offset 120). This assumes a modern Linux kernel.
- **Goodput:** `(bytes_acked_now - bytes_acked_prev) * 8 / (t_now - t_prev)` bits/s, using the
  actual elapsed time.
- **Loss proxy:** `new_retrans = total_retrans_now - total_retrans_prev`, in segments per
  interval. `lost` (`tcpi_lost`) is also logged: the kernel's current count of segments it
  presumes lost.
- **RTT:** `tcpi_rtt` (smoothed RTT, microseconds), plotted in ms.
- **Sampling:** timer-driven inside the send loop, so a full send buffer cannot delay samples.
  Intervals shorter than half the sampling interval are skipped. All other samples,
  including zero-goodput ones, are kept in the CSV, plots and statistics.
  The 95th percentile uses linear interpolation (`numpy.percentile`).

## Destination selection and failure handling

Random mode uses the JSON export of iperf3serverlist.net
(`https://export.iperf3serverlist.net/listed_iperf3_servers.json`). Servers are tried in
random order, and a port range such as `5201-5209` resolves to a random port in it.
A failed server (busy, timeout, reset, malformed reply, or no samples recorded) is logged and
replaced, up to `n + max-extra-attempts` attempts. Any shortfall is printed and logged.

## iperf3 protocol flow implemented

(unchanged from previous version: control connection with cookie, PARAM_EXCHANGE,
CREATE_STREAMS, TEST_START/TEST_RUNNING, client sends TEST_END, EXCHANGE_RESULTS,
DISPLAY_RESULTS, IPERF_DONE; error states ACCESS_DENIED and SERVER_ERROR.)

## Notes and limitations

- Results come from public Internet paths and vary between runs.
- If the congestion-control module is missing, setting the algorithm fails with
  `[Errno 2] No such file or directory`, and the run is logged as FAIL.
- Repetitions against the same host can influence each other through the kernel's cached
  TCP metrics; consider `sudo ip tcp_metrics flush` between algorithms.
- Many public servers are busy and reject tests, so a shortfall against `--n` is possible.

## AI usage

Claude (Anthropic) was used for research, to help us learn how the iperf3 client works,
to help reconstruct the protocol implementation, and for debugging. All code was reviewed,
run, and tested as a group.