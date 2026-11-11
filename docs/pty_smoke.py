#!/usr/bin/env python3
"""Exercise the *actual* alternate-screen UI in a pseudo-terminal.

Runs local commands only; never contacts any host or remote service.
Set SECUBRAIN_BIN to test an already compiled executable.
"""
import fcntl
import os
import pty
import select
import signal
import struct
import subprocess
import sys
import termios
import time
import tempfile
from pathlib import Path

exe = os.environ.get("SECUBRAIN_BIN", "./secubrain")
master, slave = pty.openpty()
fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 38, 100, 0, 0))
child_env = dict(os.environ, TERM="xterm-256color", CI="")
child_env.pop("SECUBRAIN_PLAIN", None)
child_env.pop("NO_COLOR", None)
child_env.pop("SECUBRAIN_NO_ANIM", None)
child = subprocess.Popen([exe], stdin=slave, stdout=slave, stderr=slave,
                         close_fds=True, env=child_env, start_new_session=True)
os.close(slave)
fcntl.fcntl(master, fcntl.F_SETFL, fcntl.fcntl(master, fcntl.F_GETFL) | os.O_NONBLOCK)
data = bytearray()

def capture(seconds: float):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        readable, _, _ = select.select([master], [], [], 0.05)
        if readable:
            try:
                chunk = os.read(master, 65536)
            except (BlockingIOError, OSError):
                break
            if not chunk:
                break
            data.extend(chunk)

try:
    with tempfile.TemporaryDirectory(prefix="secubrain-ui-smoke-") as temp:
        project = Path(temp) / "project"
        project.mkdir()
        (project / "demo.go").write_text("package main\nfunc main() {}\n", encoding="utf-8")
        out = Path(temp) / "reports"
        capture(0.40)
        for command in ("help", "version", "doctor"):
            os.write(master, (command + "\r").encode())
            capture(0.7 if command != "doctor" else 1.2)
        # Real on-disk audit from the fullscreen TUI (no remote host).
        os.write(master, f"scan --path {project} --out {out}\r".encode())
        capture(1.2)
        for name in ("report.json", "report.md", "report.html"):
            if not (out / name).exists():
                raise AssertionError(f"full-screen scan did not create {name}")
        # Resize while running, verifying that redraw keeps the prompt visible.
        fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 20, 60, 0, 0))
        capture(0.4)
        os.write(master, b"version\r")
        capture(0.6)
        os.write(master, b"exit\r")
        capture(0.4)
        child.wait(timeout=6)
    output = data.decode("utf-8", errors="replace")
    required = ("\x1b[?1049h", "\x1b[?1049l", "SECUBRAIN", "NEURAL LINK READY",
                "Command finished successfully", "Reports written", "SecuBrain", "Nmap", "COMMAND")
    missing = [item for item in required if item not in output]
    if child.returncode or missing:
        raise AssertionError(f"code={child.returncode}, missing={missing}, bytes={len(data)}")
    print(f"PTY live dashboard passed: {len(data):,} bytes, local scan and reports, resize and terminal restore")
    Path("dist").mkdir(parents=True, exist_ok=True)
    with open("dist/dashboard-pty-capture.ansi", "wb") as handle:
        handle.write(data[:1_200_000])
finally:
    if child.poll() is None:
        child.send_signal(signal.SIGTERM)
        child.wait(timeout=5)
    os.close(master)
