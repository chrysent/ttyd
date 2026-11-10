#!/usr/bin/env python3
"""ttyd integration / security regression tests.

Covers the fixes tracked in SECURITY-AUDIT.md. Stdlib only: no external
dependencies. Each test starts its own ttyd instance on an ephemeral port
and drives it over raw sockets.

Usage:  python3 tests/ws_test.py [path-to-ttyd]   (default: ./build/ttyd)

Not covered here (require TLS+h2 or platform specifics):
  - h2 :authority origin fallback (upstream #1566) - needs --ssl + ALPN h2
  - macOS/BSD-specific read paths (VULN-17 platform half)
"""
import base64
import json
import os
import random
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

TTYD = sys.argv[1] if len(sys.argv) > 1 else "./build/ttyd"
RESULTS = []


# ---------------------------------------------------------------- helpers
def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Server:
    def __init__(self, *args):
        self.port = free_port()
        self.logfile = tempfile.NamedTemporaryFile(prefix="ttyd-test-", delete=False)
        self.args = [TTYD, "-p", str(self.port)] + list(args)
        self.proc = None

    def __enter__(self):
        self.proc = subprocess.Popen(self.args, stdout=self.logfile, stderr=self.logfile)
        deadline = time.time() + 10
        while time.time() < deadline:
            with socket.socket() as s:
                if s.connect_ex(("127.0.0.1", self.port)) == 0:
                    return self
            if self.proc.poll() is not None:
                raise AssertionError(f"ttyd exited early rc={self.proc.returncode}: {self.log()}")
            time.sleep(0.05)
        raise AssertionError("ttyd did not start listening: " + self.log())

    def __exit__(self, *exc):
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()

    def log(self):
        with open(self.logfile.name, "rb") as f:
            return f.read().decode("utf-8", "replace")

    def alive(self):
        return self.proc is not None and self.proc.poll() is None


def http_get(port, path, headers=None):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    hdrs = f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n"
    for k, v in (headers or {}).items():
        hdrs += f"{k}: {v}\r\n"
    s.sendall((hdrs + "\r\n").encode())
    data = b""
    s.settimeout(5)
    while True:
        try:
            c = s.recv(65536)
        except socket.timeout:
            break
        if not c:
            break
        data += c
        # stop once we have the full body per Content-Length
        head, _, body = data.partition(b"\r\n\r\n")
        if b"\r\n\r\n" in data:
            cl = -1
            for l in head.decode("latin1").split("\r\n")[1:]:
                if l.lower().startswith("content-length:"):
                    cl = int(l.split(":", 1)[1].strip())
            if cl >= 0 and len(body) >= cl:
                break
    s.close()
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("latin1").split("\r\n")
    hmap = {}
    for l in lines[1:]:
        if ":" in l:
            k, v = l.split(":", 1)
            hmap[k.strip().lower()] = v.strip()
    return lines[0], hmap, body


def ws_connect(port, path="/ws", origin=None, host=None, authorization=None, subproto=True):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    key = base64.b64encode(os.urandom(16)).decode()
    req = (
        f"GET {path} HTTP/1.1\r\nHost: {host or f'127.0.0.1:{port}'}\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
        + (f"Origin: {origin}\r\n" if origin else "")
        + (f"Authorization: {authorization}\r\n" if authorization else "")
        + f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
        + ("Sec-WebSocket-Protocol: tty\r\n" if subproto else "")
        + "\r\n"
    )
    s.sendall(req.encode())
    resp = b""
    while b"\r\n\r\n" not in resp:
        c = s.recv(4096)
        if not c:
            break
        resp += c
    first = resp.split(b"\r\n")[0].decode("latin1")
    return s, first


def ws_frame(s, opcode, payload, fin=True):
    b0 = (0x80 if fin else 0) | opcode
    mask = os.urandom(4)
    n = len(payload)
    if n < 126:
        hdr = struct.pack("!BB", b0, 0x80 | n)
    elif n < 65536:
        hdr = struct.pack("!BBH", b0, 0x80 | 126, n)
    else:
        hdr = struct.pack("!BBQ", b0, 0x80 | 127, n)
    s.sendall(hdr + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))


def ws_drain(s, secs):
    s.settimeout(0.2)
    end = time.time() + secs
    data = b""
    while time.time() < end:
        try:
            c = s.recv(65536)
            if not c:
                break
            data += c
        except socket.timeout:
            pass
        except OSError:
            break
    return data


def spawn_terminal(s, columns=80, rows=24, auth_token=None):
    msg = {"columns": columns, "rows": rows}
    if auth_token is not None:
        msg["AuthToken"] = auth_token
    ws_frame(s, 2, json.dumps(msg).encode())


# ---------------------------------------------------------------- tests
def test_zero_length_frame_no_crash():  # VULN-14 / upstream #1546
    with Server("-W", "bash") as srv:
        s, first = ws_connect(srv.port)
        assert "101" in first, first
        spawn_terminal(s)
        ws_drain(s, 0.8)
        ws_frame(s, 2, b"", fin=False)  # zero-length first fragment
        time.sleep(0.5)
        assert srv.alive(), "server died on zero-length frame"
        # protocol-legal continuation completes the message: command byte comes
        # from this fragment since the empty one contributed nothing
        ws_frame(s, 0, b"0echo ok\n", fin=True)
        data = ws_drain(s, 1.5)
        assert b"ok" in data, "connection unusable after zero-length frame"
        assert srv.alive()
        s.close()


def test_flood_message_capped():  # VULN-1
    with Server("-W", "bash") as srv:
        s, first = ws_connect(srv.port)
        assert "101" in first, first
        spawn_terminal(s)
        ws_drain(s, 0.5)
        chunk = b"0" + b"A" * 65535
        ws_frame(s, 2, chunk, fin=False)
        sent = len(chunk)
        closed = False
        deadline = time.time() + 15
        try:
            while time.time() < deadline and sent < 64 * 1024 * 1024:
                ws_frame(s, 0, chunk, fin=False)
                sent += len(chunk)
                # poll for the server close (FIN is not seen by send, and a
                # close frame or EOF arrives on the read side)
                s.settimeout(0)
                try:
                    d = s.recv(65536)
                    if d == b"" or (d and (d[0] & 0x0F) == 0x8):
                        closed = True
                        break
                except (BlockingIOError, socket.timeout):
                    pass
                except OSError:
                    closed = True
                    break
                s.settimeout(5)
                time.sleep(0.002)
        except (BrokenPipeError, ConnectionResetError, OSError):
            closed = True
        assert closed, f"connection never closed after {sent} bytes of fragments"
        assert srv.alive(), "server died during flood"
        s2, f2 = ws_connect(srv.port)  # server still serves new clients
        assert "101" in f2, f2
        s2.close()


def test_credential_not_logged():  # VULN-2
    with Server("-c", "alice:secretpw", "bash") as srv:
        log = srv.log()
        assert "credential: configured" in log, "credential marker missing"
        b64 = base64.b64encode(b"alice:secretpw").decode()
        assert b64 not in log, "base64 credential leaked to log"
        assert "secretpw" not in log, "plaintext credential leaked to log"


def test_basepath_bounds():  # VULN-3
    # overlong base path must be rejected with a clear error
    p = subprocess.run([TTYD, "-b", "A" * 200, "-p", str(free_port()), "true"],
                       capture_output=True, timeout=10)
    assert p.returncode != 0, "overlong -b accepted"
    assert b"base path too long" in p.stderr or b"base path too long" in p.stdout
    # normal base path: endpoints mounted
    with Server("-b", "/mounted", "bash") as srv:
        status, _, body = http_get(srv.port, "/mounted/token")
        assert "200" in status, status
        assert b'"token"' in body


def test_ws_path_exact():  # VULN-4
    with Server("bash") as srv:
        for path, accept in [("/ws", True), ("/ws?arg=x", True), ("/w", False),
                             ("/", False), ("/wsfoo", False), ("", False)]:
            s, first = ws_connect(srv.port, path)
            accepted = "101" in first
            assert accepted == accept, f"path {path!r}: {'accepted' if accepted else 'rejected'}, expected {'accept' if accept else 'reject'}"
            s.close()


def test_http_basic_auth():  # VULN-5 (http half)
    cred = base64.b64encode(b"alice:pw123").decode()
    with Server("-c", "alice:pw123", "bash") as srv:
        status, headers, body = http_get(srv.port, "/token", {"Authorization": f"Basic {cred}"})
        assert "200" in status, status
        assert b'"token"' in body
        for hdr in ({}, {"Authorization": "Basic d3Jvbmc="}):
            status, _, _ = http_get(srv.port, "/token", hdr)
            assert "401" in status, status


def test_token_content_length():  # VULN-8
    with Server("bash") as srv:
        status, headers, body = http_get(srv.port, "/token")
        assert "200" in status, status
        cl = int(headers.get("content-length", "-1"))
        assert cl == len(body), f"content-length {cl} != body {len(body)}"


def test_ws_token_auth():  # VULN-5 (ws half) + VULN-6
    cred = base64.b64encode(b"alice:pw123").decode()
    with Server("-c", "alice:pw123", "-W", "bash") as srv:
        # valid token: session starts (initial messages arrive)
        s, first = ws_connect(srv.port, authorization=f"Basic {cred}")
        assert "101" in first, first
        spawn_terminal(s, auth_token=cred)
        data = ws_drain(s, 1.5)
        assert len(data) > 0, "no initial messages with valid token"
        s.close()
        # invalid token: connection closed, token not echoed into logs
        bad = "WRONGTOKEN" + "x" * random.randrange(8)
        s, first = ws_connect(srv.port, authorization=f"Basic {cred}")
        assert "101" in first, first
        spawn_terminal(s, auth_token=bad)
        ws_drain(s, 1.5)
        try:
            s.settimeout(1)
            d = s.recv(4096)
            assert d == b"", "expected close after invalid token"
        except (ConnectionResetError, OSError):
            pass
        s.close()
        log = srv.log()
        assert "invalid AuthToken" in log
        assert bad not in log, "failed token echoed into log"


def test_origin_allowlist():  # VULN-15
    port = free_port()
    with tempfile.NamedTemporaryFile(prefix="ttyd-o-", delete=False) as lf:
        proc = subprocess.Popen([TTYD, "-p", str(port), "-W",
                                 f"--check-origin=http://127.0.0.1:{port}", "bash"],
                                stdout=lf, stderr=lf)
        try:
            deadline = time.time() + 10
            while time.time() < deadline:
                with socket.socket() as sk:
                    if sk.connect_ex(("127.0.0.1", port)) == 0:
                        break
                time.sleep(0.05)
            else:
                raise AssertionError("allowlist server did not start")
            s, first = ws_connect(port, origin=f"http://127.0.0.1:{port}")
            assert "101" in first, f"allowlisted origin rejected: {first}"
            s.close()
            s, first = ws_connect(port, origin="http://evil.example:1")
            assert "101" not in first, "hostile origin accepted"
            s.close()
            s, first = ws_connect(port, origin=None)
            assert "101" not in first, "missing origin accepted"
            s.close()
        finally:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            with open(lf.name, "rb") as f:
                log = f.read().decode("utf-8", "replace")
            os.unlink(lf.name)
            assert "allow origin: http://127.0.0.1:" in log, "allowlist not logged"


def test_origin_legacy():  # VULN-15 legacy mode still behaves on http/1.1
    with Server("-O", "bash") as srv:
        s, first = ws_connect(srv.port, origin=f"http://127.0.0.1:{srv.port}")
        assert "101" in first, f"same-origin rejected: {first}"
        s.close()
        s, first = ws_connect(srv.port, origin="http://evil.example:1")
        assert "101" not in first, "cross origin accepted"
        s.close()


def test_pause_resume():  # VULN-12
    with Server("-W", "bash") as srv:
        s, first = ws_connect(srv.port)
        assert "101" in first
        spawn_terminal(s)
        ws_drain(s, 0.8)
        ws_frame(s, 2, b"0seq 1 100\n")
        out1 = ws_drain(s, 1.2)
        assert len(out1) > 0, "no output before pause"
        ws_frame(s, 2, b"2")  # PAUSE
        time.sleep(0.3)
        ws_frame(s, 2, b"0echo AFTER_PAUSE_MARKER\n")
        out2 = ws_drain(s, 1.2)
        assert len(out2) == 0, f"output flowed while paused ({len(out2)} bytes)"
        ws_frame(s, 2, b"3")  # RESUME
        out3 = ws_drain(s, 2.0)
        assert b"AFTER_PAUSE_MARKER" in out3, "backlog not flushed after resume"
        s.close()


def test_initial_message_clamp():  # VULN-7
    # long command (drives the 4KB title clamp) that produces no output
    long_arg = "sleep 30 # " + "y" * 5000
    with Server("-W", "bash", "-c", long_arg) as srv:
        s, first = ws_connect(srv.port)
        assert "101" in first, first
        spawn_terminal(s)
        data = ws_drain(s, 1.5)
        assert 0 < len(data) <= 4200, f"initial messages {len(data)} bytes, expected clamped <= 4200"
        assert srv.alive()
        s.close()


def test_overlong_credential_rejected():  # VULN-9
    p = subprocess.run([TTYD, "-c", "u:" + "p" * 300, "-p", str(free_port()), "true"],
                       capture_output=True, timeout=10)
    assert p.returncode != 0, "overlong -c accepted"
    assert b"credential too long" in p.stderr or b"credential too long" in p.stdout


def test_signal_option_forms():  # VULN-10 / VULN-11
    for sig in ("KILL", "SIGKILL", "9"):
        with Server("-s", sig, "bash") as srv:
            assert srv.alive(), f"-s {sig} failed to start"
    p = subprocess.run([TTYD, "-s", "AB", "-p", str(free_port()), "true"],
                       capture_output=True, timeout=10)
    assert p.returncode != 0, "-s AB accepted"


def test_resize_absurd_ignored():  # VULN-18
    with Server("-W", "bash") as srv:
        s, first = ws_connect(srv.port)
        assert "101" in first
        spawn_terminal(s)
        ws_drain(s, 0.8)
        for cols, rows in ((99999, 99999), (-1, -1), (65536, 65536)):
            ws_frame(s, 2, json.dumps({"columns": cols, "rows": rows}).encode())
            time.sleep(0.2)
        ws_frame(s, 2, b"0echo RESIZE_OK\n")
        data = ws_drain(s, 1.5)
        assert b"RESIZE_OK" in data, "session broken after absurd resizes"
        assert srv.alive()
        s.close()


def test_session_churn():  # VULN-13 / VULN-16 / VULN-17 hygiene
    with Server("-W", "bash") as srv:
        for _ in range(10):
            s, first = ws_connect(srv.port)
            assert "101" in first, first
            spawn_terminal(s)
            ws_frame(s, 2, b"0true\n")
            time.sleep(0.15)
            s.close()
        time.sleep(0.5)
        s, first = ws_connect(srv.port)  # still healthy afterwards
        assert "101" in first, first
        spawn_terminal(s)
        data = ws_drain(s, 1.0)
        assert len(data) > 0
        s.close()
        assert srv.alive()


def test_sigterm_clean_exit():
    port = free_port()
    with tempfile.NamedTemporaryFile(prefix="ttyd-sig-", delete=False) as lf:
        proc = subprocess.Popen([TTYD, "-p", str(port), "bash"], stdout=lf, stderr=lf)
        deadline = time.time() + 10
        while time.time() < deadline:
            with socket.socket() as sk:
                if sk.connect_ex(("127.0.0.1", port)) == 0:
                    break
            time.sleep(0.05)
        proc.send_signal(signal.SIGTERM)
        rc = proc.wait(timeout=5)
        with open(lf.name, "rb") as f:
            log = f.read().decode("utf-8", "replace")
        os.unlink(lf.name)
        assert rc == 0, f"exit code {rc}"
        assert "received signal: SIGTERM" in log


# ---------------------------------------------------------------- runner
def main():
    if not os.path.exists(TTYD):
        print(f"ttyd binary not found: {TTYD}")
        return 2
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        name = t.__name__
        try:
            t()
            RESULTS.append((name, "PASS", ""))
            print(f"PASS {name}")
        except Exception as e:  # noqa: BLE001
            RESULTS.append((name, "FAIL", str(e)))
            print(f"FAIL {name}: {e}")
    failed = [r for r in RESULTS if r[1] == "FAIL"]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
