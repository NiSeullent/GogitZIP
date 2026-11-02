"""Regressions of the portable core, engine, POSIX layer and CLI: folder tree cost of very
deep names, nested archives deeper than the view chain, terminal escapes in archive text,
out-of-range timestamps, archives whose names are all empty, hard links onto their own
target on case-insensitive file systems, the quarantine mark on folders / links / copies,
the mode of created archives, and the first code-page lookup from several threads."""
import os, io, sys, struct, zlib, shutil, tarfile, zipfile, subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
EXEC = os.environ.get("GZ_TEST_EXEC", "").split()
SANITIZED = "sanitize" in os.environ.get("HOST_CFLAGS", "")
ESC = "\x1b"
MARK = b"0081;00000000;Safari;"
MARK_NAME = "com.apple.quarantine" if sys.platform == "darwin" else "user.com.apple.quarantine"


class Ctx:
    def __init__(self, t):
        self.t = t
        self.cli = os.path.join(os.path.dirname(t.gzt), "gogitzip")

    def env(self, **extra):
        e = {k: v for k, v in os.environ.items() if k not in ("LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE")}
        e["LANG"] = "C.UTF-8"
        e["TZ"] = "UTC"
        e.update(extra)
        return e

    def run(self, args, prog=None, env=None, timeout=120, umask=None):
        cmd = [prog or self.cli] + list(args)
        if umask is not None:                  # (no preexec_fn: the runner uses threads)
            cmd = ["sh", "-c", 'umask %03o && exec "$0" "$@"' % umask] + cmd
        try:
            r = subprocess.run(cmd, cwd=self.t.work, env=env or self.env(),
                               input=b"", capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return -999, b"", b"timeout"
        if b"Sanitizer" in r.stderr or b"runtime error" in r.stderr:
            self.t.record(False, "sanitizer: " + " ".join(map(str, args))[:80],
                          r.stderr.decode("utf-8", "replace")[-1500:])
        return r.returncode, r.stdout, r.stderr

    def check(self, ok, label, detail=""):
        return self.t.record(ok, label, detail if not ok else "")

    def fresh(self, *names):
        p = os.path.join(self.t.work, *names)
        if os.path.lexists(p):
            if os.path.isdir(p) and not os.path.islink(p):
                shutil.rmtree(p)
            else:
                os.remove(p)
        return p


# Runs one command and writes "<exit code> <seconds> <peak RSS in MiB>" to argv[1]. A
# process of its own: the test runner's other threads start (and reap) their own children.
MEASURE = r"""
import resource, subprocess, sys, time
t0 = time.time()
try:
    rc = subprocess.run(sys.argv[3:], timeout=float(sys.argv[2])).returncode
except subprocess.TimeoutExpired:
    rc = -999
ru = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
rss = ru / (1 << 20) if sys.platform == "darwin" else ru / 1024.0
open(sys.argv[1], "w").write("%d %.3f %.1f" % (rc, time.time() - t0, rss))
"""


def measured(cmd, timeout, work, as_limit=None):
    """(rc, stdout, stderr, seconds, peak RSS in MiB) of one command"""
    if as_limit:                               # address space limit (KiB), set by the shell
        cmd = ["sh", "-c", 'ulimit -v %d && exec "$0" "$@"' % (as_limit >> 10)] + cmd
    res = os.path.join(work, "measured.txt")
    if os.path.exists(res):
        os.remove(res)
    r = subprocess.run([sys.executable, "-I", "-c", MEASURE, res, str(timeout)] + cmd,
                       capture_output=True, timeout=timeout + 60)
    try:
        rc, secs, rss = open(res).read().split()
        return int(rc), r.stdout, r.stderr, float(secs), float(rss)
    except (OSError, ValueError):
        return -998, r.stdout, r.stderr, 0.0, 0.0


def stored_zip(path, entries, comment=b""):
    """ZIP with stored entries [(name bytes, data)], written by hand (any name length)"""
    body, cd = b"", b""
    for name, data in entries:
        crc = zlib.crc32(data)
        off = len(body)
        body += struct.pack("<IHHHHHIIIHH", 0x04034b50, 20, 0, 0, 0, 0, crc, len(data), len(data),
                            len(name), 0) + name + data
        cd += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014b50, 20, 20, 0, 0, 0, 0, crc, len(data), len(data),
                          len(name), 0, 0, 0, 0, 0, off) + name
    eocd = struct.pack("<IHHHHIIH", 0x06054b50, 0, 0, len(entries), len(entries), len(cd), len(body),
                       len(comment)) + comment
    with open(path, "wb") as f:
        f.write(body + cd + eocd)


def tar_add(tf, name, data=None, kind="f", target=None, mtime=1500000000):
    ti = tarfile.TarInfo(name)
    ti.mtime = mtime
    if kind == "d":
        ti.type = tarfile.DIRTYPE
        ti.mode = 0o755
    elif kind in ("l", "h"):
        ti.type = tarfile.SYMTYPE if kind == "l" else tarfile.LNKTYPE
        ti.linkname = target
    else:
        ti.size = len(data)
    tf.addfile(ti, io.BytesIO(data) if kind == "f" else None)


# ---------------------------------------------------------------------------------------
# core-engine-1: deep names


def test_deep_names(c):
    t = c.t
    limit = 1500 << 20 if sys.platform.startswith("linux") and not (SANITIZED or EXEC) else None
    # 'a/' x 32766 + 'b/f': 65535 bytes, 32768 levels (used to take 2 GiB and many seconds)
    deep = c.fresh("deep_name.zip")
    stored_zip(deep, [(b"a/" * 32766 + b"b/f", b"deep\n")])
    rc, out, err, secs, rss = measured([t.gzt, "l", deep], 60, t.work, limit)
    lines = out.decode("utf-8", "replace").splitlines()
    typ = [l.split("\t") for l in lines if l.startswith("TYPE\t")]
    c.check(rc == 0 and secs < 20 and rss < 400 and typ and int(typ[0][4]) == 1023,
            "65535-byte name 32768 levels deep: listed fast and small",
            "rc=%s %.1fs %.0f MiB folders=%s %s" % (rc, secs, rss, typ and typ[0][4:], err[-200:]))
    rc, out, err = c.run(["l", "-slt", deep], timeout=60)
    names = [l[7:] for l in out.decode("utf-8", "replace").splitlines() if l.startswith("Path = ") and l != "Path = " + deep]
    name = names[0] if names else ""
    want = "a/" * 1022 + "_".join(["a"] * (32766 - 1022) + ["b"]) + "/f"
    c.check(name == want, "levels past 1024 become one folder, the file name is kept",
            "got %r...%r (%d chars)" % (name[:20], name[-20:], len(name)))
    # 16 names of 64 KiB with long components and different roots: folder paths would
    # need 16 x 66 MB; the folder budget keeps the tree linear in the input
    wide = c.fresh("deep_wide.zip")
    ents = []
    for k in range(16):
        comp = ("%c%04d" % (65 + k, k) + "x" * 58 + "/").encode()
        ents.append(((comp * (65000 // len(comp)) + b"f")[:65535], b"payload %d\n" % k))
    stored_zip(wide, ents)
    rc, out, err, secs, rss = measured([t.gzt, "l", wide], 60, t.work, limit)
    lines = out.decode("utf-8", "replace").splitlines()
    rows = [l.split("\t") for l in lines if l[:1].isdigit()]
    c.check(rc == 0 and secs < 20 and rss < 600 and len(rows) == 16,
            "16 names of 64 KiB, 1015 levels each: folder names stay within budget",
            "rc=%s %.1fs %.0f MiB rows=%d %s" % (rc, secs, rss, len(rows), err[-200:]))
    rc, out, err = c.run(["l", "-slt", wide], timeout=60)
    names = [l[7:] for l in out.decode("utf-8", "replace").splitlines() if l.startswith("Path = ") and l != "Path = " + wide]
    c.check(len(names) == 16 and all(n.endswith("x/f") for n in names),
            "past the budget the rest of a path becomes one folder, the file name is kept",
            "%r" % [n[-30:] for n in names][:4])
    # every entry still opens and reads
    r, rows2, outd = t.extract(wide)
    good = sum(1 for i, (st, isd, size, n) in rows2.items()
               if st == 0 and open(os.path.join(outd, "%d.bin" % i), "rb").read() == b"payload %d\n" % i)
    c.check(r.returncode == 0 and good == 16, "deep entries extract (%d/16)" % good, r.stderr[-300:])
    shutil.rmtree(outd, ignore_errors=True)
    # ordinary trees are unchanged: same folder for "d/x" and "d/y", case kept
    small = c.fresh("tree.zip")
    stored_zip(small, [(b"d/e/x.txt", b"1"), (b"d/e/y.txt", b"2"), (b"d/E/z.txt", b"3"), (b"top.txt", b"4"),
                       (b"d/e/", b"")])
    r = t.run_gzt(["l", small])
    lines = r.stdout.decode().splitlines()
    typ = [l.split("\t") for l in lines if l.startswith("TYPE\t")]
    want_dirs = 2 if sys.platform == "darwin" else 3      # d, d/e (+ d/E unless case-folded)
    ndirs = int(typ[0][4]) if typ else -1
    c.check(r.returncode == 0 and ndirs == want_dirs, "small tree: %d folders (want %d)" % (ndirs, want_dirs),
            r.stdout.decode()[-300:])


# ---------------------------------------------------------------------------------------
# core-engine-2: nested archives


def nested_tar(path, levels):
    def wrap(name, data):
        b = io.BytesIO()
        with tarfile.open(fileobj=b, mode="w", format=tarfile.USTAR_FORMAT) as tf:
            tar_add(tf, "pad%s.bin" % name, b"P" * 1000)
            tar_add(tf, name, data)
        return b.getvalue()
    data = wrap("secret.txt", b"INNER-PAYLOAD-OK\n")
    for i in range(levels - 1, 0, -1):
        data = wrap("lv%d.tar" % i, data)
    with open(path, "wb") as f:
        f.write(data)


def test_layers(c):
    t = c.t
    try:
        drv = t.build_driver("tests/drivers/core_layers.c")
    except Exception as e:
        return c.check(False, "build core_layers driver", str(e)[-500:])
    for levels in (9, 10, 12, 66, 70):
        p = c.fresh("nest%d.tar" % levels)
        nested_tar(p, levels)
        r = subprocess.run(EXEC + [drv, p, str(levels)], capture_output=True, timeout=600, cwd=t.work)
        out = r.stdout.decode("utf-8", "replace")
        err = r.stderr.decode("utf-8", "replace")
        lines = [l for l in out.splitlines() if l.startswith(("ok ", "FAIL "))]
        bad = [l for l in lines if l.startswith("FAIL")]
        c.check(r.returncode == 0 and lines and not bad and "Sanitizer" not in err,
                "tar nested %d levels: every level read from the right place" % levels,
                "rc=%d %s %s" % (r.returncode, "; ".join(bad or lines)[-600:], err[-600:]))
        os.remove(p)


# ---------------------------------------------------------------------------------------
# core-engine-3: terminal escapes


def bad_bytes(b):
    """control bytes a terminal acts on (C0 except \\t \\n, DEL, UTF-8 C1) or invalid UTF-8"""
    for i, x in enumerate(b):
        if (x < 0x20 and x not in (9, 10)) or x == 0x7F:
            return "byte %02x at %d: %r" % (x, i, b[max(0, i - 20):i + 20])
        if x == 0xC2 and i + 1 < len(b) and 0x80 <= b[i + 1] <= 0x9F:
            return "C1 at %d: %r" % (i, b[max(0, i - 20):i + 20])
    try:
        b.decode("utf-8")
    except UnicodeDecodeError as e:
        return "invalid UTF-8: %s" % e
    return None


def test_escapes(c):
    title = ESC + "]0;PWNED-TITLE\x07" + ESC + "[2J" + ESC + "[31mFAKE OUTPUT" + ESC + "[0m"
    tarp = c.fresh("esc.tar")
    with tarfile.open(tarp, "w", format=tarfile.PAX_FORMAT) as tf:
        tar_add(tf, "abs", kind="l", target="/" + title)                 # absolute: refused, printed
        tar_add(tf, "up", kind="l", target="../" + title)                # escapes: refused, printed
        tar_add(tf, "hard", kind="h", target="missing" + title)          # no target: printed
        tar_add(tf, "del\x7f\u009b[2Jname.txt", b"x")                    # DEL and C1 in a name
        tar_add(tf, "ok.txt", b"hi")
    # raw bytes in a link target that no code page takes (shown as escaped bytes)
    rawp = c.fresh("esc_raw.tar")
    with tarfile.open(rawp, "w", format=tarfile.GNU_FORMAT, encoding="latin-1") as tf:
        tar_add(tf, "rawlink", kind="l", target="/\x81\x9b[2J\xc2\x9b[3J")
    zipp = c.fresh("esc.zip")
    with zipfile.ZipFile(zipp, "w") as z:
        z.writestr("a.txt", b"x")
        z.comment = (ESC + "]0;ZIP-COMMENT\x07" + ESC + "[2JEverything is Ok\r\nsecond\tline").encode()
    problems = []
    runs = [["x", tarp, "-o", c.fresh("esc_out"), "-y"], ["l", tarp], ["l", "-slt", tarp],
            ["x", rawp, "-o", c.fresh("esc_out2"), "-y"], ["l", "-slt", rawp],
            ["l", zipp], ["l", "-slt", zipp], ["t", tarp]]
    seen = b""
    for args in runs:
        rc, out, err = c.run(args)
        for what, b in (("stdout", out), ("stderr", err)):
            p = bad_bytes(b)
            if p:
                problems.append("%s %s: %s" % (" ".join(args[:2]), what, p))
        seen += out + err
    c.check(not problems, "archive text reaches the terminal without control characters",
            "; ".join(problems[:4]))
    c.check(b"\\x1B]0;PWNED-TITLE\\x07" in seen and b"\\x1B]0;ZIP-COMMENT" in seen and b"\\x7F\\x9B[2Jname" in seen,
            "escaped text is still shown (\\xNN)", seen.decode("utf-8", "replace")[-600:])
    c.check(b"Everything is Ok\\x0D\nsecond\tline" in seen, "comments keep line breaks and tabs",
            seen.decode("utf-8", "replace")[-400:])
    for d in ("esc_out", "esc_out2"):
        c.fresh(d)


# ---------------------------------------------------------------------------------------
# core-engine-4: timestamps out of range


def test_times(c):
    # t * 10^7 wrapped around 2^64 used to come out as 1970-01-01
    wrap = 1844674407371
    # (pax "-9223372036854775808" is left out: the TAR reader negates it itself)
    cases = [("wrap.txt", wrap, ""), ("neg.txt", -wrap, ""), ("max.txt", (1 << 63) - 1, ""),
             ("min.txt", -(1 << 63) + 1, ""), ("pre1601.txt", -11644473601, ""),
             ("y1601.txt", -11644473600, ""),            # FILETIME 0: "no time"
             ("y2514.txt", 1 << 34, "2514-05-30 01:53:04"), ("y1969.txt", -1, "1969-12-31 23:59:59")]
    probs = []
    for fmt, label in ((tarfile.GNU_FORMAT, "base-256"), (tarfile.PAX_FORMAT, "pax")):
        p = c.fresh("times_%s.tar" % label)
        with tarfile.open(p, "w", format=fmt) as tf:
            for name, mt, _ in cases:
                tar_add(tf, name, b"x", mtime=mt)
        rc, out, err = c.run(["l", "-slt", p])
        got, cur = {}, None
        for line in out.decode("utf-8", "replace").splitlines():
            if line.startswith("Path = "):
                cur = line[7:]
            elif line.startswith("Modified = ") and cur:
                got[cur] = line[11:].strip()
        if rc:
            probs.append("%s: rc=%d %s" % (label, rc, err[-200:]))
        for name, mt, want in cases:
            if got.get(name, "?") != want:
                probs.append("%s %s: %r (want %r)" % (label, name, got.get(name), want))
    c.check(not probs, "out-of-range archive times show as unknown, in-range ones exactly", "; ".join(probs[:6]))


# ---------------------------------------------------------------------------------------
# core-engine-5: every name empty


def test_empty_names(c):
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        tar_add(tf, "x", b"data")
    d = bytearray(b.getvalue())
    d[0:100] = b"\0" * 100
    d[148:156] = b" " * 8
    d[148:156] = ("%06o\0 " % sum(d[:512])).encode()
    p = c.fresh("empty_name.tar")
    with open(p, "wb") as f:
        f.write(bytes(d))
    for cp in ("0", "949", "65001"):
        r = c.t.run_gzt(["l", p, cp])
        err = r.stderr.decode("utf-8", "replace")
        c.check(r.returncode == 0 and b"TYPE\tTAR\t1\t" in r.stdout and "runtime error" not in err,
                "archive whose only name is empty (code page %s)" % cp, "rc=%d %s" % (r.returncode, err[-400:]))
    # the fault was arithmetic on a NULL name buffer, which only clang's UBSan reports:
    # gzt with the archive model built that way (plain builds only: no runtime mixing)
    clang = shutil.which("clang")
    if not clang or EXEC or SANITIZED:
        return
    t = c.t
    host = os.path.join(os.path.dirname(t.gzt), "host")
    objs = sorted(os.path.join(dp, f) for dp, dns, fns in os.walk(host) for f in fns
                  if f.endswith(".o") and os.path.join(dp, f) != os.path.join(host, "core", "arc.o"))
    out = os.path.join(t.work, "gzt_ubsan")
    inc = ["-I" + os.path.join(ROOT, d) for d in ("src/core", "src/codec", "src/fmt", "src/posix")]
    r = subprocess.run([clang, "-std=gnu11", "-O1", "-g", "-fsanitize=pointer-overflow,null",
                        "-fno-sanitize-recover=all", "-finput-charset=UTF-8", "-pthread"] + inc +
                       ["-o", out, os.path.join(ROOT, "tests/gzt.c"), os.path.join(ROOT, "src/core/arc.c")] + objs +
                       ["-pthread"] + (["-liconv"] if sys.platform == "darwin" else []), capture_output=True)
    if r.returncode:
        return c.check(True, "empty names under clang UBSan: cannot build here (skipped)")
    for cp in ("0", "65001"):
        rr = subprocess.run([out, "l", p, cp], capture_output=True, timeout=60)
        err = rr.stderr.decode("utf-8", "replace")
        c.check(rr.returncode == 0 and "runtime error" not in err,
                "archive whose only name is empty: no pointer arithmetic on NULL (clang UBSan, cp %s)" % cp,
                "rc=%d %s" % (rr.returncode, err[-400:]))


# ---------------------------------------------------------------------------------------
# shim for case-insensitive / link-less file systems (Linux, glibc)


def build_shim(c):
    if not sys.platform.startswith("linux") or EXEC:
        return None
    out = os.path.join(c.t.work, "fs_shim.so")
    r = subprocess.run([os.environ.get("HOSTCC", "cc"), "-shared", "-fPIC", "-O1", "-o", out,
                        os.path.join(ROOT, "tests/drivers/fs_shim.c"), "-ldl"], capture_output=True)
    return out if r.returncode == 0 else None


def shim_env(c, shim, **flags):
    e = c.env(LD_PRELOAD=shim, **flags)
    e["ASAN_OPTIONS"] = (e.get("ASAN_OPTIONS", "") + ":verify_asan_link_order=0").lstrip(":")
    return e


# ---------------------------------------------------------------------------------------
# core-engine-6: hard link onto its own target on a case-insensitive file system


def case_insensitive(d):
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, "CaseProbe")
    open(p, "w").close()
    ci = os.path.exists(os.path.join(d, "caseprobe"))
    os.remove(p)
    return ci


def test_hardlink_case(c, shim):
    tp = c.fresh("hlcase.tar")
    with tarfile.open(tp, "w", format=tarfile.USTAR_FORMAT) as tf:
        tar_add(tf, "A.txt", b"x")
        tar_add(tf, "a.txt", kind="h", target="A.txt")
        tar_add(tf, "B.txt", b"y")
        tar_add(tf, "c.txt", kind="h", target="B.txt")       # an ordinary hard link next to it
    base = c.fresh("cisim")
    out = os.path.join(base, "out")
    if sys.platform == "darwin" and case_insensitive(base):
        env, real = c.env(), {"A.txt": "a.txt", "B.txt": "b.txt", "c.txt": "c.txt"}
    elif shim:
        env, real = shim_env(c, shim, GZ_SHIM_CI="1"), {"A.txt": "a.txt", "B.txt": "b.txt", "c.txt": "c.txt"}
    else:
        return c.check(True, "hard link onto its own target: no case-insensitive file system to test (skipped)")
    os.makedirs(base, exist_ok=True)
    for ow in ("-y", "-n"):
        shutil.rmtree(out, ignore_errors=True)
        rc, so, se = c.run(["x", tp, "-o", out, ow], env=env)
        def rd(n):
            for cand in (n, real[n]):
                q = os.path.join(out, cand)
                if os.path.exists(q):
                    return open(q, "rb").read()
            return None
        ok = rc == 0 and rd("A.txt") == b"x" and rd("B.txt") == b"y" and rd("c.txt") == b"y"
        c.check(ok, "case-insensitive file system: 'a.txt' -> 'A.txt' keeps A.txt (%s)" % ow,
                "rc=%d files=%s %s" % (rc, sorted(os.listdir(out)) if os.path.isdir(out) else None,
                                       se.decode("utf-8", "replace")[-300:]))
    shutil.rmtree(base, ignore_errors=True)


# ---------------------------------------------------------------------------------------
# core-engine-7: quarantine mark on folders, links and copies


def build_mark_cli(c):
    """gogitzip whose POSIX layer keeps the macOS mark in user.com.apple.quarantine"""
    t = c.t
    bdir = os.path.dirname(t.gzt)
    skip = {os.path.join("app", "engine.o"), os.path.join("posix", "os_posix.o")}
    objs = []
    host = os.path.join(bdir, "host")
    for dp, dns, fns in os.walk(host):
        for f in fns:
            if f.endswith(".o") and os.path.relpath(os.path.join(dp, f), host) not in skip:
                objs.append(os.path.join(dp, f))
    out = os.path.join(t.work, "gogitzip_mark")
    flags = os.environ.get("HOST_CFLAGS", "-O2 -g").split()
    inc = ["-I" + os.path.join(ROOT, d) for d in ("src/core", "src/codec", "src/fmt", "src/posix", "src/app")]
    srcs = [os.path.join(ROOT, s) for s in ("src/app/cli.c", "src/app/engine.c", "src/posix/os_posix.c")]
    t.sh([os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-pthread", "-finput-charset=UTF-8",
          "-DGZ_TEST_MARK_XATTR"] + flags + inc + ["-o", out] + srcs + sorted(objs) + ["-pthread"])
    return out


def get_mark(p):
    if sys.platform == "darwin":
        r = subprocess.run(["xattr", "-p", "-s", MARK_NAME, p], capture_output=True)
        return r.stdout.strip() if r.returncode == 0 else None
    try:
        return os.getxattr(p, MARK_NAME, follow_symlinks=False)
    except OSError:
        return None


def set_mark(p):
    if sys.platform == "darwin":
        subprocess.run(["xattr", "-w", MARK_NAME, MARK.decode(), p], check=True)
    else:
        os.setxattr(p, MARK_NAME, MARK)


def test_marks(c, shim):
    if sys.platform == "darwin":
        if not shutil.which("xattr"):
            return c.check(True, "quarantine mark: no xattr tool (skipped)")
        cli = c.cli
    elif sys.platform.startswith("linux"):
        probe = c.fresh("xattr_probe")
        open(probe, "w").close()
        try:
            os.setxattr(probe, MARK_NAME, b"1")
        except OSError:
            os.remove(probe)
            return c.check(True, "quarantine mark: no user extended attributes here (skipped)")
        os.remove(probe)
        try:
            cli = build_mark_cli(c)
        except Exception as e:
            return c.check(False, "build gogitzip with the test mark", str(e)[-500:])
    else:
        return
    zp = c.fresh("evil.zip")
    with zipfile.ZipFile(zp, "w") as z:
        z.writestr("Evil.app/Contents/MacOS/evil", b"#!/bin/sh\necho evil\n")
        z.writestr("Evil.app/Contents/Info.plist", b"<plist/>")
        z.writestr("Docs/", b"")                                  # an explicit folder entry
    tp = c.fresh("links.tar")
    with tarfile.open(tp, "w", format=tarfile.USTAR_FORMAT) as tf:
        tar_add(tf, "d/A.txt", b"x")
        tar_add(tf, "d/b.txt", kind="h", target="d/A.txt")
        tar_add(tf, "d/lnk", kind="l", target="A.txt")
    for p in (zp, tp):
        set_mark(p)
    parent = c.fresh("mark")
    os.makedirs(parent)
    out = os.path.join(parent, "new", "out")                       # made by the job
    rc, so, se = c.run(["x", zp, "-o", out], prog=cli)
    items = ["", "Evil.app", "Evil.app/Contents", "Evil.app/Contents/MacOS", "Evil.app/Contents/MacOS/evil",
             "Evil.app/Contents/Info.plist", "Docs"]
    miss = [i or "." for i in items if get_mark(os.path.join(out, i)) != MARK]
    c.check(rc == 0 and not miss, "every extracted folder and file carries the archive's mark",
            "rc=%d unmarked: %s %s" % (rc, miss, se.decode("utf-8", "replace")[-300:]))
    c.check(get_mark(os.path.join(parent, "new")) == MARK and get_mark(parent) is None,
            "folders above the destination: marked only when the job made them")
    # into an existing folder: what was there stays as it was
    pre = os.path.join(parent, "pre")
    os.makedirs(os.path.join(pre, "Evil.app"))
    rc, so, se = c.run(["x", zp, "-o", pre], prog=cli)
    c.check(rc == 0 and get_mark(os.path.join(pre, "Evil.app")) is None and get_mark(pre) is None and
            get_mark(os.path.join(pre, "Evil.app", "Contents")) == MARK,
            "folders that existed before keep no mark, new ones get it", se.decode("utf-8", "replace")[-300:])
    # links (macOS keeps marks on symbolic links; Linux has no user attributes on them)
    lo = os.path.join(parent, "links")
    rc, so, se = c.run(["x", tp, "-o", lo], prog=cli)
    ok = rc == 0 and get_mark(os.path.join(lo, "d", "b.txt")) == MARK and get_mark(os.path.join(lo, "d")) == MARK
    if sys.platform == "darwin":
        ok = ok and get_mark(os.path.join(lo, "d", "lnk")) == MARK
    c.check(ok, "hard and symbolic links carry the mark", "rc=%d %s" % (rc, se.decode("utf-8", "replace")[-300:]))
    # hard link copied where links are impossible (FAT): the copy gets the mark too
    if shim and sys.platform.startswith("linux"):
        co = os.path.join(parent, "copied")
        rc, so, se = c.run(["x", tp, "-o", co], prog=cli, env=shim_env(c, shim, GZ_SHIM_NOLINK="1"))
        b = os.path.join(co, "d", "b.txt")
        same = os.path.exists(b) and os.stat(b).st_ino == os.stat(os.path.join(co, "d", "A.txt")).st_ino
        c.check(rc == 0 and os.path.exists(b) and not same and open(b, "rb").read() == b"x" and get_mark(b) == MARK,
                "hard link copied on a file system without links: the copy is marked",
                "rc=%d same=%s mark=%r %s" % (rc, same, get_mark(b), se.decode("utf-8", "replace")[-300:]))
    # no mark on the archive: nothing marked
    plain = c.fresh("plain.zip")
    shutil.copyfile(zp, plain)
    po = os.path.join(parent, "plain")
    rc, so, se = c.run(["x", plain, "-o", po], prog=cli)
    c.check(rc == 0 and get_mark(po) is None and get_mark(os.path.join(po, "Evil.app")) is None,
            "archive without a mark: nothing marked")
    shutil.rmtree(parent, ignore_errors=True)


# ---------------------------------------------------------------------------------------
# core-engine-8: mode of created archives


def test_archive_mode(c):
    src = c.fresh("mode_src.txt")
    with open(src, "wb") as f:
        f.write(b"hello\n")
    probs = []
    for um, want in ((0o022, 0o644), (0o027, 0o640), (0o077, 0o600), (0o002, 0o664)):
        for ext in ("zip", "7z", "tar.gz"):
            p = c.fresh("mode_new.%s" % ext)
            rc, so, se = c.run(["a", p, src, "-bd"], umask=um)
            m = os.stat(p).st_mode & 0o777 if os.path.exists(p) else None
            if rc or m != want:
                probs.append("umask %03o %s: rc=%d mode %s (want %03o)" % (um, ext, rc, m and oct(m), want))
    # replacing an archive keeps its mode
    p = c.fresh("mode_old.zip")
    with open(p, "wb") as f:
        f.write(b"old")
    os.chmod(p, 0o640)
    rc, so, se = c.run(["a", p, src, "-bd", "-y"], umask=0o077)
    m = os.stat(p).st_mode & 0o777
    if rc or m != 0o640 or not zipfile.is_zipfile(p):
        probs.append("replaced: rc=%d mode %o (want 640)" % (rc, m))
    # replacing a symbolic link: the new archive is a new file (the link's 777 is not a mode)
    ln = c.fresh("mode_link.zip")
    os.symlink("mode_old.zip", ln)
    rc, so, se = c.run(["a", ln, src, "-bd", "-y"], umask=0o022)
    m = os.lstat(ln).st_mode & 0o777
    if rc or os.path.islink(ln) or m != 0o644:
        probs.append("replaced link: rc=%d link=%s mode %o" % (rc, os.path.islink(ln), m))
    c.check(not probs, "created archives follow the umask, replaced ones keep their mode", "; ".join(probs[:6]))
    for n in ("mode_old.zip", "mode_link.zip", "mode_src.txt"):
        c.fresh(n)


# ---------------------------------------------------------------------------------------
# core-engine-9: first code-page lookup on several threads


def test_cp_race(c):
    t = c.t
    cc = os.environ.get("HOSTCC", "cc")
    inc = ["-I" + os.path.join(ROOT, d) for d in ("src/core", "src/codec", "src/fmt", "src/posix")]
    srcs = [os.path.join(ROOT, s) for s in ("tests/drivers/core_cp_race.c", "src/posix/plat_posix.c",
                                             "src/core/str.c")]
    libs = ["-pthread"] + (["-liconv"] if sys.platform == "darwin" else [])
    out = os.path.join(t.work, "core_cp_race")
    tsan = False
    if not EXEC:
        r = subprocess.run([cc, "-std=gnu11", "-O1", "-g", "-fsanitize=thread"] + inc + ["-o", out] + srcs + libs,
                           capture_output=True)
        if r.returncode == 0:
            p = subprocess.run([out], capture_output=True, timeout=120, env=c.env(TSAN_OPTIONS="halt_on_error=1"))
            err = p.stderr.decode("utf-8", "replace")
            if "ThreadSanitizer" in err and "data race" not in err:
                pass                                   # TSan cannot run here: plain build below
            else:
                tsan = True
                c.check(p.returncode == 0 and b"ok code pages" in p.stdout and "data race" not in err,
                        "code pages looked up by 4 threads at once (ThreadSanitizer)",
                        "rc=%d %s %s" % (p.returncode, p.stdout.decode()[-200:], err[-800:]))
    if tsan:
        return
    flags = os.environ.get("HOST_CFLAGS", "-O2 -g").split()
    t.sh([cc, "-std=gnu11"] + flags + inc + ["-o", out] + srcs + libs)
    bad = []
    for i in range(200):
        p = subprocess.run(EXEC + [out], capture_output=True, timeout=60)
        if p.returncode or b"ok code pages" not in p.stdout:
            bad.append(p.stdout.decode("utf-8", "replace").strip())
            break
    c.check(not bad, "code pages looked up by 4 threads at once (200 runs)", "; ".join(bad))


def run(t):
    c = Ctx(t)
    if not os.path.exists(c.cli):
        t.skip("%s missing: run make build/gogitzip (make test builds it)" % c.cli)
    shim = build_shim(c)
    test_deep_names(c)
    test_layers(c)
    test_escapes(c)
    test_times(c)
    test_empty_names(c)
    test_hardlink_case(c, shim)
    test_marks(c, shim)
    test_archive_mode(c)
    test_cp_race(c)
