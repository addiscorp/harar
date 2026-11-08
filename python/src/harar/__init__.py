"""harar's client for Python:

    from harar import vault
    harar = vault()                                      # the agent on this machine
    harar.secrets.resolve("harar://prod/shop/STRIPE_KEY")  # the key it names

A gateway that attaches keys on their way out asks where each may go, and for
it for one host only: hosts(secret) and send(secret, host).

One JSON request on harar's local socket, the write side closed, one JSON
answer: the protocol the per-user agent and a primary both speak. harar
decides every send, and records the host; this client holds nothing.
"""

import json
import os
import re
import socket as _socket
import sys

__all__ = ["REFERENCE_PREFIX", "EdgeSecrets", "EdgeVault", "HararError", "Secrets", "Vault", "agent_socket", "reference", "vault"]

# harar's answers are small; anything longer is refused.
MAX_ANSWER = 1024 * 1024
# How long harar has to answer (a per-user agent may be asking for Touch ID).
TIMEOUT_S = 60


# What a reference to a vault key starts with, as op:// for 1Password.
REFERENCE_PREFIX = "harar://"


class HararError(Exception):
    """harar refused, or could not be asked; the message names why."""


def reference(value):
    """The vault key `value` names, if the whole value is a harar:// reference."""
    if not isinstance(value, str) or not value.startswith(REFERENCE_PREFIX):
        return None
    key = value[len(REFERENCE_PREFIX):]
    return key if key and not re.search(r"\s", key) else None


def agent_socket():
    """Where the per-user agent (`harar agent`) listens: the harar binary's rule."""
    home, runtime = os.environ.get("HOME"), os.environ.get("XDG_RUNTIME_DIR")
    if sys.platform == "darwin" and home:
        return os.path.join(home, "Library/Application Support/harar", "agent.sock")
    if runtime:
        return os.path.join(runtime, "harar", "agent.sock")
    return os.path.join(home or "/", ".harar", "agent.sock")


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


class Secrets:
    """harar:// references resolved to their values, the shape of 1Password's
    client.secrets.resolve("op://..."). Read when asked for; held only by you."""

    def __init__(self, socket):
        self._socket = socket

    def resolve(self, ref):
        """The value `ref` (harar://prod/shop/STRIPE_KEY) names."""
        key = reference(ref)
        if key is None:
            raise HararError(f"not a harar:// reference: {ref!r}")
        value = _ask(self._socket, {"op": "get", "key": key}, ref).get("value")
        if not isinstance(value, str):
            raise HararError(f"harar sent no value for {ref}")
        return value

    def resolve_all(self, refs):
        """Each reference's value, in order; the first that fails is the error."""
        return [self.resolve(ref) for ref in refs]


class Vault:
    """A vault on harar's socket: the secrets its references name, and for a
    gateway, where each may go and the secret itself for one host only."""

    def __init__(self, socket):
        if not isinstance(socket, str) or not socket.startswith("/"):
            raise ValueError("vault(socket=...): the socket is an absolute path")
        self._socket = socket
        self.secrets = Secrets(socket)

    def hosts(self, secret):
        """For a gateway: the host patterns `secret` may go to: an exact name, or
        `*.example.com` for any name under it (never the name itself)."""
        hosts = _ask(self._socket, {"op": "hosts", "key": secret}, secret).get("hosts")
        if not isinstance(hosts, list) or not all(isinstance(h, str) for h in hosts):
            raise HararError(f"harar sent no hosts for {secret}")
        return hosts

    def send(self, secret, host):
        """For a gateway: `secret`'s value, for a request to `host` only."""
        value = _ask(
            self._socket, {"op": "send", "key": secret, "host": host}, f"{secret} to {host}"
        ).get("value")
        if not isinstance(value, str):
            raise HararError(f"harar refused {secret} to {host}: no value")
        return value


# A harar edge service token, as `harar edge token create` makes it.
_EDGE_TOKEN = re.compile(r"\Aharar_edge_[0-9a-f]{16}_[A-Za-z0-9_-]{43}\Z")
# https://, or http:// to this machine only.
_EDGE_URL = re.compile(r"\A(https://[^/]|http://(127\.0\.0\.1|localhost|\[::1\])([:/]|\Z))")


def _ask_edge(edge, token, refs, what):
    """The values `refs` name, from a harar edge (docs/edge.md): one POST of
    /v1/resolve with the service token, all or nothing."""
    import urllib.error
    import urllib.request

    request = urllib.request.Request(
        edge + "/v1/resolve",
        data=json.dumps({"refs": refs}).encode("utf-8"),
        method="POST",
        headers={"content-type": "application/json", "authorization": "Bearer " + token},
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_S) as res:
            status, body = res.status, res.read(MAX_ANSWER + 1)
    except urllib.error.HTTPError as e:
        status, body = e.code, e.read(MAX_ANSWER + 1)
    except _socket.timeout:
        raise HararError(f"harar at {edge}: did not answer in {TIMEOUT_S} s") from None
    except (urllib.error.URLError, OSError) as e:
        raise HararError(f"harar at {edge}: {getattr(e, 'reason', e)}") from None
    if len(body) > MAX_ANSWER:
        raise HararError("harar sent too long an answer")
    try:
        answer = json.loads(body.decode("utf-8"))
    except ValueError:
        raise HararError(f"harar at {edge} did not answer with JSON ({status})") from None
    if not isinstance(answer, dict):
        raise HararError(f"harar at {edge} did not answer with an object")
    if not 200 <= status < 300:
        code = answer.get("error") if isinstance(answer.get("error"), str) else str(status)
        message = answer.get("message")
        raise HararError(f"harar refused {what}: {code}" + (f": {message}" if isinstance(message, str) else ""))
    values = answer.get("values")
    if not isinstance(values, list) or len(values) != len(refs) or not all(isinstance(v, str) for v in values):
        raise HararError(f"harar sent no value for {what}")
    return values


class EdgeSecrets:
    """harar:// references resolved at a harar edge, with a service token."""

    def __init__(self, edge, token):
        self._edge, self._token = edge, token

    def resolve(self, ref):
        """The value `ref` names."""
        if reference(ref) is None:
            _not_a_reference(ref)
        return self.resolve_all([ref])[0]

    def resolve_all(self, refs):
        """Each reference's value, in order, in one request: all or nothing."""
        refs = list(refs)
        if not refs:
            return []
        for ref in refs:
            if reference(ref) is None:
                _not_a_reference(ref)
        return _ask_edge(self._edge, self._token, refs, refs[0] if len(refs) == 1 else f"{len(refs)} references")


def _not_a_reference(ref):
    raise HararError(f"not a harar:// reference: {ref!r}")


class EdgeVault:
    """A vault at a harar edge (docs/edge.md): it resolves references, and
    only those its service token may read. hosts and send are for gateways
    on harar's local socket."""

    def __init__(self, edge, token):
        if not isinstance(edge, str) or not _EDGE_URL.match(edge):
            raise ValueError("vault(edge=...): the edge is an https:// URL")
        if not isinstance(token, str) or not _EDGE_TOKEN.match(token):
            raise ValueError("vault(edge=..., token=...): the token is a harar edge service token (harar edge token create)")
        self.secrets = EdgeSecrets(edge.rstrip("/"), token)


def vault(socket=None, edge=None, token=None):
    """harar at `socket`: by default the per-user agent on this machine
    (`harar agent`), else a primary (/run/harar.sock). Or, with `edge` and
    `token`, a harar edge, for a service off your network: its URL and a
    service token from `harar edge token create`, read from the platform's
    secrets."""
    if edge is not None or token is not None:
        if socket is not None:
            raise ValueError("vault(): a socket or an edge, not both")
        return EdgeVault(edge, token)
    return Vault(agent_socket() if socket is None else socket)
