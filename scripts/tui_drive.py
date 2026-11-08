"""Drive an interactive command in a pseudo-terminal (TUI tests).

Used by scripts/tui_scenarios.sh to run `luksbox wizard` and the
terminal-only deniable commands without a person at the keyboard.

usage: tui_drive.py <script.json> -- cmd args...
PTY_LOG=<file> appends the whole screen transcript (escape codes removed).
script: [["regex to wait for", "keys to send"], ...]; keys use \\r for Enter,
["<SLEEP>", "2"] waits two seconds,
\\x1b[B for arrow down. Exits 0 when every step matched and the process
ended with status 0 (or the last step is ["<EXIT>", code]; a signal is
its negative number, -2 for SIGINT).
"""
import json, os, pty, re, select, sys, time

ANSI = re.compile(rb"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[()][A-Z0-9]|\r")

def main():
    sep = sys.argv.index("--")
    steps = json.load(open(sys.argv[1]))
    cmd = sys.argv[sep + 1:]
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(cmd[0], cmd)
    buf = b""
    log = open(os.environ.get("PTY_LOG", "/dev/null"), "ab")
    def read_until(pat, timeout):
        nonlocal buf
        rx = re.compile(pat.encode(), re.S)
        end = time.time() + timeout
        while time.time() < end:
            clean = ANSI.sub(b"", buf)
            m = rx.search(clean)
            if m:
                # consume up to the match in the raw buffer (approx.)
                buf = b""
                return True
            r, _, _ = select.select([fd], [], [], 0.2)
            if r:
                try:
                    data = os.read(fd, 65536)
                except OSError:
                    break
                if not data:
                    break
                buf += data
                log.write(ANSI.sub(b"", data)); log.flush()
        return False
    expect_exit = None
    for i, (pat, keys) in enumerate(steps):
        if pat == "<EXIT>":
            expect_exit = int(keys)
            break
        if pat == "<SLEEP>":
            # Let the program get somewhere before the next key (a mount
            # to come up before Ctrl-C), reading what it prints meanwhile.
            end = time.time() + float(keys)
            while time.time() < end:
                r, _, _ = select.select([fd], [], [], 0.1)
                if r:
                    try:
                        data = os.read(fd, 65536)
                    except OSError:
                        break
                    buf += data
                    log.write(ANSI.sub(b"", data)); log.flush()
            continue
        if not read_until(pat, 120):
            sys.stdout.write(f"STEP {i} TIMEOUT waiting for /{pat}/\n--- screen ---\n")
            sys.stdout.write(ANSI.sub(b"", buf).decode(errors="replace")[-2500:] + "\n")
            os.kill(pid, 9)
            sys.exit(3)
        time.sleep(0.15)
        os.write(fd, keys.encode())
    # drain until exit
    out = b""
    end = time.time() + 120
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            try:
                d = os.read(fd, 65536)
            except OSError:
                break
            if not d:
                break
            out += d
            log.write(ANSI.sub(b"", d)); log.flush()
        wpid, status = os.waitpid(pid, os.WNOHANG)
        if wpid:
            code = os.waitstatus_to_exitcode(status)
            tail = ANSI.sub(b"", buf + out).decode(errors="replace")[-1500:]
            want = 0 if expect_exit is None else expect_exit
            if code != want:
                sys.stdout.write(f"EXIT {code} (wanted {want})\n--- tail ---\n{tail}\n")
                sys.exit(4)
            sys.stdout.write(f"OK exit {code}\n--- tail ---\n{tail[-600:]}\n")
            return
    try:
        _, status = os.waitpid(pid, 0)
        code = os.waitstatus_to_exitcode(status)
        want = 0 if expect_exit is None else expect_exit
        sys.stdout.write(f"{'OK' if code == want else 'EXIT'} exit {code}\n")
        sys.exit(0 if code == want else 4)
    except ChildProcessError:
        pass
    sys.stdout.write("TIMEOUT waiting for exit\n" + ANSI.sub(b"", buf + out).decode(errors="replace")[-2000:])
    os.kill(pid, 9)
    sys.exit(5)

main()
