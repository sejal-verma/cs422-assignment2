import socket


SUPPORTED_ALGORITHMS = ("cubic", "reno", "bbr")


def set_congestion_algorithm(sock: socket.socket, algorithm: str) -> None:
    """Set the TCP congestion-control algorithm on a socket before connect()."""

    algorithm = algorithm.lower()

    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(
            f"Unsupported congestion-control algorithm: {algorithm}"
        )

    opt = getattr(socket, "TCP_CONGESTION", 13)

    sock.setsockopt(
        socket.IPPROTO_TCP,
        opt,
        algorithm.encode("ascii")
    )


def get_congestion_algorithm(sock: socket.socket) -> str:
    """Return the congestion-control algorithm actually used by the socket."""

    try:
        opt = getattr(socket, "TCP_CONGESTION", 13)

        raw = sock.getsockopt(
            socket.IPPROTO_TCP,
            opt,
            16
        )

        return raw.split(b"\x00", 1)[0].decode("ascii") or "unknown"

    except (OSError, AttributeError, UnicodeDecodeError):
        return "unknown"