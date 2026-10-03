# CS 422 Assignment 2 — Part 1: iPerf Throughput Application

A from-scratch Python iperf3 client (raw sockets, no iperf3 binary) that:

- **(a)** speaks the iperf3 TCP protocol against public iperf3 servers,
- **(b)** picks random destinations from the public server list and replaces failed ones (bounded),
- **(c)** measures goodput from `TCP_INFO` (`tcpi_bytes_acked`) and produces a raw-sample CSV, a summary table, and a plot.

Everything lives in a single file: `main.py`.

## Requirements

- Linux, or Windows with WSL2 (a real Linux kernel is needed for `TCP_INFO`)
- Docker
- Python 3 on the host (the launcher uses only the standard library)

Inside the container: Python 3, `pandas`, `matplotlib`, `numpy` (see `requirements.txt`).

## How to run

```bash
python3 main.py                        # defaults; builds and runs in Docker automatically
python3 main.py --n 5 --duration 20    # custom number of servers / seconds per server
python3 main.py --no-docker            # skip Docker, run directly on this machine
```

When started on the host, `main.py` builds the Docker image and re-runs itself inside the
container with the same arguments. Inside the container the environment variable `IN_DOCKER=1`
(set in the `Dockerfile`) tells the script to run the experiment itself.

You can also run the container directly:

```bash
docker build -t cs422-assignment2 .
docker run --rm --user "$(id -u):$(id -g)" -e MPLCONFIGDIR=/tmp \
  -v "$PWD:/app" cs422-assignment2 --n 10 --duration 10
```
You can also run the container directly (Windows only):
```bash
docker build -t cs422-assignment2 .
docker run --rm `
  -e MPLCONFIGDIR=/tmp `
  -v "$($PWD.Path):/app" `
  cs422-assignment2 --n 10 --duration 10
```

### Command-line options

| Option | Default | Meaning |
|---|---|---|
| `--n` | 10 | Number of successful destinations wanted |
| `--duration` | 10.0 | Seconds of sending per destination |
| `--max-extra-attempts` | 30 | Extra servers to try when some fail (bounded) |
| `--no-docker` | off | Run directly on this machine instead of in Docker |

The sampling interval (`SAMPLE_INTERVAL`, 0.2 s) and the other defaults are constants near the
top of `main.py`.

## Output files

Written to the project folder:

| File | Contents |
|---|---|
| `destination_log.txt` | Every server tried, OK/FAIL with the reason, and any shortfall |
| `goodput_samples.csv` | Raw samples: destination, elapsed seconds, cumulative bytes acked, goodput (bits/s) |
| `summary_table.csv` | Per-destination min / median / mean / p95 goodput in Mbps, with the congestion-control algorithm actually in use (read from the data socket via `TCP_CONGESTION`) |
| `goodput_plot.png` | Goodput over time, one panel per destination |

## How goodput is computed

At every sampling tick the client reads the cumulative acknowledged-byte counter from the
**data socket** with `getsockopt(IPPROTO_TCP, TCP_INFO)` and computes:

```
goodput(t) = (bytes_acked_now - bytes_acked_previous) * 8 / (t_now - t_previous)   [bits/s]
```

Sampling is driven by a timer inside the send loop, not by `send()` returning, so a full send
buffer cannot delay samples. Intervals shorter than half the sampling interval (e.g. at the very
end of a run) are not recorded, since they are not a regular sampling interval. All other samples, including the first interval and zero-goodput samples, are kept in the CSV, the plots and the summary statistics. The 95th percentile uses linear interpolation (same as `numpy.percentile`).

## Destination selection and failure handling

Servers come from the official JSON export of iperf3serverlist.net
(`https://export.iperf3serverlist.net/listed_iperf3_servers.json`). The website's own table is
rendered by JavaScript, so it can't be scraped with a plain HTTP request.

- Servers are tried in random order; a port range such as `5201-5209` is resolved to a random port in the range.
- A failed server (busy, timeout, connection reset, malformed reply, or a stalled run with too few samples) is logged and replaced, up to `n + max-extra-attempts` total attempts.
- Any shortfall against the requested `n` is printed and written to `destination_log.txt`.

## iperf3 protocol flow implemented

TCP, client sends, one stream:

```
client -> server : opens control connection, sends a 37-byte cookie
server -> client : PARAM_EXCHANGE     (9)   ; client replies with a JSON params blob
server -> client : CREATE_STREAMS     (10)  ; client opens the data connection and
                                              sends the same cookie on it
server -> client : TEST_START (1), TEST_RUNNING (2)
                                            ; client sends data for `duration`
client -> server : TEST_END           (4)   ; the CLIENT ends the test
server -> client : EXCHANGE_RESULTS   (13)  ; client sends its results JSON,
                                              then reads the server's results JSON
server -> client : DISPLAY_RESULTS    (14)  ; client sends IPERF_DONE (16) and closes
```

Error states: `ACCESS_DENIED` (-1, server busy or rejected the test) and `SERVER_ERROR` (-2).

JSON messages use iperf3 framing: a 4-byte big-endian length followed by that many bytes of JSON.

> This state machine was reconstructed from the iperf3 source. If a server misbehaves, confirm it
> against a Wireshark/tcpdump capture.

## Notes and limitations

- Results come from public Internet paths and vary from run to run; exact numbers won't reproduce.
- Many public servers are busy and reject tests (`ACCESS_DENIED`), so a shortfall against `--n` is possible.
- The first sampling interval (~0.2 s) shows a similar spike (about 24 Mbps) on most servers regardless of path speed. We did not investigate its cause, and it is included in all statistics and plots.
- A destination whose run completes but yields fewer than half the expected samples is treated as a stalled/failed destination, logged, and replaced. With timer-driven sampling this is rare.
- `TCP_INFO` decoding assumes a modern Linux kernel layout (`tcpi_bytes_acked` at byte offset 120).

## AI usage

Claude (Anthropic) was used for research and to help us learn how the iperf3 client works, to help reconstruct the protocol implementation, and to help with debugging; all code was reviewed, run, and tested as a group.
