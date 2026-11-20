#!/usr/bin/env python3
"""Drive 'wyrm top' through a pseudo-terminal against a running daemon.

  tui_drive.py <daemon socket> <wyrm binary>

Presses keys, then checks both the rendered screen and the daemon's state.
"""
import fcntl, os, pty, re, select, struct, subprocess, sys, termios, time

sock, binp = sys.argv[1], sys.argv[2]
env = dict(os.environ, WYRM_SOCK=sock, TERM="xterm")
pid, fd = pty.fork()
if pid == 0:
    os.execve(binp, [binp, "top"], env)
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 140, 0, 0))
out = b""

def pump(seconds):
    global out
    end = time.time() + seconds
    while time.time() < end:
        if select.select([fd], [], [], 0.05)[0]:
            try:
                out += os.read(fd, 65536)
            except OSError:
                return

def screen():
    # The dashboard repaints from cursor-home each frame: keep the last frame.
    s = out.split(b"\x1b[H")[-1].decode("ascii", "replace")
    return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", s).replace("\r", "")

def cli(*args):
    return subprocess.run([binp, *args], env=env, capture_output=True, text=True).stdout

def press(keys, wait=0.4):
    os.write(fd, keys)
    pump(wait)

steps = []
pump(1.5)
steps.append(("peers view on start", "NAME" in screen() and "[1 Peers]" in screen()))
press(b"2"); steps.append(("key 2 -> flows", "PROTO" in screen() and "[2 Flows]" in screen()))
press(b"\t"); steps.append(("tab -> packets", "[3 Packets]" in screen()))
press(b"4"); steps.append(("key 4 -> rules", "[4 Rules]" in screen() and "ACTION" in screen()))
press(b"S", 1.5); steps.append(("S turns shields on", "shields true" in " ".join(cli("status").split()) and "shields ON" in screen()))
press(b"S", 1.5); steps.append(("S turns shields off", "shields false" in " ".join(cli("status").split())))
before = cli("rules").count("drop")
press(b"1\x1b[B\x1b[Ab", 1.5)
steps.append(("b blocks the selected peer", cli("rules").count("drop") == before + 1 and "blocked  " in screen()))
press(b"u", 1.5)
steps.append(("u unblocks it", cli("rules").count("drop") == before and "blocked  " not in screen()))
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 12, 60, 0, 0))
pump(0.8)
lines = screen().split("\n")
steps.append(("resize redraws within the new bounds", max(map(len, lines)) <= 60 and len(lines) <= 12))
final = screen()
press(b"q", 0.5)
_, st = os.waitpid(pid, 0)
steps.append(("q exits cleanly and restores the terminal", os.WEXITSTATUS(st) == 0 and out.endswith(b"\x1b[?25h\x1b[?1049l")))

failed = 0
for name, good in steps:
    print("PASS " if good else "FAIL ", name)
    failed += not good
if "-v" in sys.argv:
    print(final)
sys.exit(failed)
