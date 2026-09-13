#!/usr/bin/env python3
"""Run a command attached to a real pty, then type a canned line of input.

Plain stdin/stdout redirection (`</dev/null`) can't exercise a prompter that
insists on a real terminal -- like pkinit-trust-brokerd's client-tty
prompter, which resolves the *connecting client's* pid via SO_PEERCRED and
opens whichever of its stdin/stderr/stdout is a tty device. This gives the
command (kinit) a genuine pty so that prompter can find and use it, then
"types" --answer into it the way a person answering the prompt would.

There's no need to wait for the prompt text specifically before typing:
writing to the pty master queues the bytes in the kernel tty input buffer
regardless of whether anything has read from the slave side yet, so an
early write just waits there until pkinit-trust-brokerd's read_line() call
consumes it.

Usage:
    pty_kinit.py --answer 3 --transcript FILE [--delay SECONDS] -- CMD [ARGS...]

Exits with CMD's own exit status.
"""

import argparse
import os
import pty
import select
import subprocess
import sys
import time


def drain(master_fd, transcript, timeout):
    """Read whatever's available from master_fd for up to timeout seconds,
    appending it to transcript. Returns early once nothing more arrives."""
    deadline = time.time() + timeout
    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            return
        r, _, _ = select.select([master_fd], [], [], remaining)
        if not r:
            return
        try:
            chunk = os.read(master_fd, 4096)
        except OSError:
            return
        if not chunk:
            return
        transcript.extend(chunk)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--answer", required=True,
        help="Line of input to type once the command is running "
             "(a trailing newline is added)",
    )
    parser.add_argument(
        "--transcript", required=True,
        help="File to write everything the command printed on its pty",
    )
    parser.add_argument(
        "--delay", type=float, default=1.0,
        help="Seconds to wait before typing --answer (default: 1.0); "
             "not timing-critical, see module docstring",
    )
    parser.add_argument("cmd", nargs=argparse.REMAINDER,
                         help="Command to run, e.g. -- kinit ...")
    args = parser.parse_args()

    if not args.cmd:
        parser.error("no command given (pass it after --)")
    cmd = args.cmd[1:] if args.cmd[0] == "--" else args.cmd

    master_fd, slave_fd = pty.openpty()
    proc = subprocess.Popen(
        cmd, stdin=slave_fd, stdout=slave_fd, stderr=slave_fd, close_fds=True,
    )
    os.close(slave_fd)

    transcript = bytearray()
    drain(master_fd, transcript, args.delay)
    try:
        os.write(master_fd, (args.answer + "\n").encode())
    except OSError:
        pass

    while proc.poll() is None:
        drain(master_fd, transcript, 0.2)
    drain(master_fd, transcript, 0.2)  # final flush after exit

    with open(args.transcript, "wb") as f:
        f.write(bytes(transcript))

    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())
