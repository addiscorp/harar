"""harar's client for Python:

    from harar import vault
    v = vault(socket="/run/harar.sock")
    v.hosts("prod/shop/STRIPE_KEY")                    # ['api.stripe.com']
    v.send("prod/shop/STRIPE_KEY", "api.stripe.com")   # the key, for that host only

One JSON request on harar's local socket, the write side closed, one JSON
answer: the protocol the per-user agent and a primary both speak. harar
decides every send, and records the host; this client holds nothing.
"""

import json
import socket as _socket

__all__ = ["HararError", "Vault", "vault"]

# harar's answers are small; anything longer is refused.
MAX_ANSWER = 1024 * 1024
# How long harar has to answer (a per-user agent may be asking for Touch ID).
TIMEOUT_S = 60


class HararError(Exception):
    """harar refused, or could not be asked; the message names why."""


def _ask(path, request, what):
    """One request to harar, and its answer if it says ok; otherwise why not."""
    try:
        with _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM) as conn:
            conn.settimeout(TIMEOUT_S)
            conn.connect(path)
            conn.sendall(json.dumps(request).encode("utf-8"))
            conn.shutdown(_socket.SHUT_WR)
            chunks, size = [], 0
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_ANSWER:
                    raise HararError("harar sent too long an answer")
                chunks.append(chunk)
    except _socket.timeout:
        raise HararError(f"harar did not answer in {TIMEOUT_S} s") from None
    except OSError as e:
        raise HararError(f"harar at {path}: {e.strerror or e}") from None
    try:
        answer = json.loads(b"".join(chunks).decode("utf-8"))
    except ValueError:
        raise HararError(f"harar at {path} did not answer with JSON") from None
    if not isinstance(answer, dict):
        raise HararError(f"harar at {path} did not answer with an object")
    if answer.get("ok") is True:
        return answer
    error = answer.get("error")
    raise HararError(f"harar refused {what}: {error if isinstance(error, str) else 'no answer'}")


class Vault:
    """A vault on harar's socket: where each secret may go, and the secret
    itself for one host only."""

    def __init__(self, socket):
        if not isinstance(socket, str) or not socket.startswith("/"):
            raise ValueError("vault(socket=...): the socket is an absolute path")
        self._socket = socket

    def hosts(self, secret):
        """The host patterns `secret` may go to: an exact name, or
        `*.example.com` for any name under it (never the name itself)."""
        hosts = _ask(self._socket, {"op": "hosts", "key": secret}, secret).get("hosts")
        if not isinstance(hosts, list) or not all(isinstance(h, str) for h in hosts):
            raise HararError(f"harar sent no hosts for {secret}")
        return hosts

    def send(self, secret, host):
        """`secret`'s value, for a request to `host` only. harar decides, and
        records the host."""
        value = _ask(
            self._socket, {"op": "send", "key": secret, "host": host}, f"{secret} to {host}"
        ).get("value")
        if not isinstance(value, str):
            raise HararError(f"harar refused {secret} to {host}: no value")
        return value


def vault(socket):
    """harar at `socket`: a per-user agent or a primary."""
    return Vault(socket)
