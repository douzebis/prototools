# SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

"""Spec 0406 S6: press Tab in an interactive bash and check the line.

Usage: tab_completion.py BINDIR

For each of prototext and protolens found in BINDIR, sources the script that
`<TOOL>_COMPLETE=bash <tool>` prints into a fresh interactive bash on a
pseudo-terminal, types each line of the spec's table, presses Tab, and
compares the resulting command line with the expected one. Exits non-zero if
any line differs.
"""

import os
import pty
import re
import select
import shutil
import sys
import tempfile
import time

# (typed, expected), with "{sub}" standing for the tool's subcommand prefix:
# "decode " for prototext, nothing for protolens. Paths refer to the tree
# built by make_tree.
PATH_ROWS = [
    ("{sub}da", "{sub}data/"),
    ("{sub}dir", r"{sub}dir\ with\ space/"),
    ('{sub}"dir w', '{sub}"dir with space"/'),
    ("{sub}'dir w", "{sub}'dir with space'/"),
    (r"{sub}dir\ w", r"{sub}dir\ with\ space/"),
    ("{sub}a:", "{sub}a:b/"),
    ("{sub}a:b/", "{sub}a:b/z.pb "),
    ("{sub}ka:", "{sub}ka:li.pb "),
    ("--descriptor-set=da", "--descriptor-set=data/"),
    (r"--descriptor-set=dir\ w", r"--descriptor-set=dir\ with\ space/"),
    ('--descriptor-set="dir w', '--descriptor-set="dir with space"/'),
    ("--descriptor-set da", "--descriptor-set data/"),
    ("{sub}ét", "{sub}été/"),
    ("{sub}data/x", "{sub}data/x.pb "),
]

# protoscan (spec 0407) takes a positional FILE and --proto-out DIR, so its
# option rows are --proto-out's. "--proto-o" must complete to --proto-out
# alone: the deprecated --proto_out is a hidden alias, never offered.
PROTOSCAN_ROWS = [
    (typed.replace("--descriptor-set", "--proto-out"),
     expected.replace("--descriptor-set", "--proto-out"))
    for typed, expected in PATH_ROWS
] + [("--proto-o", "--proto-out ")]

TOOLS = {
    "prototext": PATH_ROWS + [("decode --t", "decode --type "), ("dec", "decode ")],
    "protolens": PATH_ROWS + [("--ty", "--type ")],
    "protoscan": PROTOSCAN_ROWS,
}
SUB = {"prototext": "decode ", "protolens": "", "protoscan": ""}


def make_tree(root):
    for d in ["data", "dir with space", "a:b", "été"]:
        os.makedirs(os.path.join(root, d))
    for f in ["data/x.pb", "dir with space/y.pb", "a:b/z.pb", "ka:li.pb"]:
        open(os.path.join(root, f), "w").close()


def tab(bindir, root, tool, typed):
    """The command line after typing `tool typed` and pressing Tab."""
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(root)
        env = {
            "PATH": bindir + os.pathsep + os.environ["PATH"],
            "HOME": root,
            "TERM": "dumb",
            "PS1": "$ ",
            "LC_ALL": "C.UTF-8",
        }
        os.execvpe("bash", ["bash", "--norc", "--noprofile", "-i"], env)

    def read(seconds):
        out, end = b"", time.time() + seconds
        while time.time() < end:
            if select.select([fd], [], [], 0.05)[0]:
                try:
                    out += os.read(fd, 4096)
                except OSError:
                    break
        return out

    var = tool.upper() + "_COMPLETE"
    read(0.5)
    os.write(fd, f'source <({var}=bash {tool}); bind "set bell-style none"\n'.encode())
    read(1.0)
    os.write(fd, f"{tool} {typed}\t".encode())
    out = read(2.0)
    os.write(fd, b"\x15exit\n")
    read(0.3)
    os.waitpid(pid, 0)
    text = out.decode(errors="replace").replace("\r", "")
    text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]|\x07|\x08", "", text)
    # The line as echoed: everything after the last prompt-less echo of it.
    start = text.rfind(f"{tool} ")
    return text[start:].split("\n")[0] if start >= 0 else text


def main():
    bindir = os.path.abspath(sys.argv[1])
    failures = 0
    with tempfile.TemporaryDirectory() as root:
        make_tree(root)
        for tool, rows in TOOLS.items():
            if not shutil.which(tool, path=bindir):
                continue
            for typed, expected in rows:
                typed = typed.format(sub=SUB[tool])
                expected = f"{tool} " + expected.format(sub=SUB[tool])
                got = tab(bindir, root, tool, typed)
                ok = got == expected
                failures += not ok
                print(f"{'ok  ' if ok else 'FAIL'} {tool} {typed!r:42} -> {got!r}"
                      + ("" if ok else f" (expected {expected!r})"))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
