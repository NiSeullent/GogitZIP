"""Regression tests for the installers-ms slice: crafted inputs whose cost used to
grow much faster than their size (review findings installers-ms-1..5).

  NSIS  SetOutPath naming one huge string N times: every command decoded the whole
        string (O(N x L), no cancel). Same for the Park-fork detection, which
        compared two huge strings per EW_WRITEUNINSTALLER-like command.
  NSIS  one long SetOutPath prefix copied into every entry name (64 KiB per 28-byte
        command) -> GZ_E_LIMIT instead of gigabytes of names.
  WIM   a 65 KB directory name repeated in the path of every child (~112 bytes of
        metadata each) -> GZ_E_LIMIT instead of gigabytes of names.
  XAR   the same with a 16 KB directory name, and fifo children that are never
        listed but whose paths were stored anyway.
  CPIO / XAR  hard link groups found with a linear-probing hash table of archive
        chosen keys (dev + inode, file ids): keys picked to share one bucket made
        open() quadratic. Groups are now found by sorting.
  CPIO  an empty first name (fuzzer find: a->raw stayed NULL, clang UBSan flags
        a->raw + 0 in the name code page detection).

Every input is generated here. Checks: `gzt l` finishes in time, with bounded
memory (peak RSS of the child), and either lists the expected entries or reports
GZ_E_LIMIT (15). Benign variants of each layout must still list correctly.
"""
import os, struct, subprocess, sys, time, zlib, hashlib

E_LIMIT = 15
MB = 1 << 20

# Runs the command given after OUT TIMEOUT and prints "rc secs maxrss_kb". A small
# process in between: a child forked from the (big) test runner would report the
# runner's resident set as its own peak (ru_maxrss survives fork + exec).
MEASURE = r"""
import resource, subprocess, sys, time
t0 = time.time()
try:
    with open(sys.argv[1], "wb") as fo:
        rc = subprocess.run(sys.argv[3:], stdout=fo, stderr=subprocess.STDOUT, timeout=float(sys.argv[2])).returncode
except subprocess.TimeoutExpired:
    print("TIMEOUT"); sys.exit(0)
print(rc, time.time() - t0, resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)
"""


def run_l(t, path, timeout=60):
    """gzt l path -> dict(rc, out, secs, rss_mb), or None on timeout."""
    outp = path + ".lst"
    r = subprocess.run([sys.executable, "-c", MEASURE, outp, str(timeout), t.gzt, "l", path, "0"],
                       capture_output=True, timeout=timeout + 60)
    res = r.stdout.decode().split()
    if not res or res[0] == "TIMEOUT":
        return None
    out = open(outp, "rb").read().decode("utf-8", "replace")
    return dict(rc=int(res[0]), out=out, secs=float(res[1]), rss_mb=int(res[2]) / 1024.0)


def rows_of(out):
    rows = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 7 and parts[0].isdigit():
            rows.append(dict(is_dir=int(parts[1]), mode=int(parts[5], 8), name="\t".join(parts[6:])))
    return rows


def check(t, label, path, want_limit=None, want_rows=None, max_secs=30, max_rss=None, extra=None, timeout=60):
    """want_limit: True = must fail with GZ_E_LIMIT; None = LIMIT or a listing is fine.
    want_rows: expected row count of a listing. extra(rows) -> problem text or ''."""
    r = run_l(t, path, timeout)
    if r is None:
        return t.record(False, label, "timeout after %ds (%d bytes)" % (timeout, os.path.getsize(path)))
    probs = []
    limit = ("OPEN_ERROR %d" % E_LIMIT) in r["out"]
    rows = rows_of(r["out"])
    if "Sanitizer" in r["out"] or "runtime error" in r["out"]:
        probs.append("sanitizer: " + r["out"][-300:])
    if r["rc"] not in (0, 1):
        probs.append("rc=%d" % r["rc"])
    if want_limit is True and not limit:
        probs.append("expected GZ_E_LIMIT, got rc=%d %d rows %r" % (r["rc"], len(rows), r["out"][:120]))
    if want_limit is False and (r["rc"] or limit):
        probs.append("expected a listing: %r" % r["out"][:200])
    if want_rows is not None and not limit and len(rows) != want_rows:
        probs.append("rows %d, want %d" % (len(rows), want_rows))
    if r["secs"] > max_secs:
        probs.append("too slow: %.1fs" % r["secs"])
    if max_rss and r["rss_mb"] > max_rss:
        probs.append("peak RSS %.0f MB > %d MB" % (r["rss_mb"], max_rss))
    if extra and not probs and not limit:
        x = extra(rows)
        if x:
            probs.append(x)
    detail = "; ".join(probs) or "%s %.2fs %.0f MB, %d bytes" % ("LIMIT" if limit else "%d rows" % len(rows),
                                                                 r["secs"], r["rss_mb"], os.path.getsize(path))
    return t.record(not probs, label, detail)


# ------------------------------------------------------------------ NSIS

SIG = bytes([0xEF, 0xBE, 0xAD, 0xDE]) + b"NullsoftInst"


def nsis_installer(cmds, strings):
    """Non-solid raw-Deflate header, 32-bit block table, firstheader at offset 0.
    cmds: bytes of 28-byte commands; strings: the string table (ANSI or UTF-16LE)."""
    ent_off = 4 + 8 * 8
    n = len(cmds) // 28
    str_off = ent_off + len(cmds)
    blocks = [(0, 0)] * 8
    blocks[2] = (ent_off, n)
    blocks[3] = (str_off, 0)
    blocks[4] = (str_off + len(strings), 0)                # language tables = end of the string table
    hdr = struct.pack("<I", 0) + b"".join(struct.pack("<II", o, k) for o, k in blocks) + cmds + strings
    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    comp = co.compress(hdr) + co.flush()
    body = struct.pack("<I", len(comp) | 0x80000000) + comp
    return struct.pack("<I", 0) + SIG + struct.pack("<II", len(hdr), 28 + len(body)) + body


def cmd(*a):
    a = list(a) + [0] * (7 - len(a))
    return struct.pack("<7I", *a)


def test_nsis(t):
    # installers-ms-1: N SetOutPath commands (EW_CREATEDIR, param1 != 0) naming one
    # L-char string. Before: O(N x L) in open() (~minutes here), no cancel.
    L, N = 2 * MB, 32000
    strings = b"A" * (L - 1) + b"\0"
    p = t.path("nsis_setoutpath_quad.exe")
    open(p, "wb").write(nsis_installer(cmd(11, 0, 1) * N, strings))
    check(t, "nsis: %d SetOutPath x %d MiB string (ms-1)" % (N, L >> 20), p, max_secs=30, max_rss=400)

    # Park-fork detection: EW_WRITEUNINSTALLER-like commands whose "$INSTDIR\" + name
    # and name parameters are two huge strings equal up to the last char
    L = 2 * MB
    strings = b"x\0"
    s_p3 = len(strings)
    strings += b"\xfd\x95\x80\\" + b"A" * L + b"B\0"         # NSIS 2 code for $INSTDIR, '\', name
    s_p0 = len(strings)
    strings += b"A" * L + b"C\0"
    p = t.path("nsis_park_detect_quad.exe")
    open(p, "wb").write(nsis_installer(cmd(62, s_p0, 0, 0, s_p3) * N, strings))
    check(t, "nsis: %d uninstaller commands, Park detection on %d MiB strings (ms-1)" % (N, L >> 20), p,
          max_secs=30, max_rss=400)

    # benign: a 1 MiB string as SetOutPath of 3 files -> 3 entries (names cut at 32K)
    strings = b"A" * (MB - 1) + b"\0"
    names = []
    for i in range(3):
        names.append(len(strings))
        strings += b"f%d\0" % i
    cmds = cmd(11, 0, 1) + b"".join(cmd(20, 0, names[i], i) for i in range(3))
    p = t.path("nsis_long_prefix_ok.exe")
    open(p, "wb").write(nsis_installer(cmds, strings))
    check(t, "nsis: 1 MiB SetOutPath, 3 files", p, want_limit=False, want_rows=3, max_secs=10,
          extra=lambda rows: "" if all(r["name"].startswith("A" * 1000) for r in rows) else "names %r" %
          [r["name"][:20] for r in rows])

    # installers-ms-3: one 32767-unit SetOutPath, then N "File x" with distinct data
    # positions: every name repeats the prefix (64 KiB per 28-byte command).
    # Before: ~500 MB of names for N = 4000 (8 KB file).
    PL, N = 32767, 4000
    strings = ("\0" + "P" * PL + "\0" + "x" + "\0").encode("utf-16-le")
    s_x = PL + 2
    cmds = cmd(11, 1, 1) + b"".join(cmd(20, 0, s_x, i) for i in range(N))
    p = t.path("nsis_prefix_names.exe")
    open(p, "wb").write(nsis_installer(cmds, strings))
    check(t, "nsis: %d files x 64 KiB SetOutPath prefix (ms-3)" % N, p, want_limit=True, max_secs=20, max_rss=150)

    # benign: the same layout with 40 files lists every one with the long prefix
    cmds = cmd(11, 1, 1) + b"".join(cmd(20, 0, s_x, i) for i in range(40))
    p = t.path("nsis_prefix_names_ok.exe")
    open(p, "wb").write(nsis_installer(cmds, strings))
    check(t, "nsis: 40 files x 64 KiB SetOutPath prefix", p, want_limit=False, want_rows=40, max_secs=10,
          extra=lambda rows: "" if all(r["name"].startswith("P" * 1000) for r in rows) else "names")


# ------------------------------------------------------------------ WIM

def wim_dentry(attr, sub, name):
    nb = len(name)
    ln = (102 + (nb + 2 if nb else 0) + 7) & ~7
    d = bytearray(ln)
    struct.pack_into("<QII", d, 0, ln, attr, 0xFFFFFFFF)
    struct.pack_into("<Q", d, 16, sub)
    struct.pack_into("<Q", d, 0x38, 0x01D0000000000000)
    struct.pack_into("<HHH", d, 0x60, 0, 0, nb)
    d[102:102 + nb] = name
    return bytes(d)


def wim_file(k, nb=65000):
    """Uncompressed WIM, one image: root -> directory D (nb-byte name) -> k files."""
    meta = bytearray(struct.pack("<II", 8, 0))                       # security data
    d_off = 8 + ((102 + 7) & ~7)
    d_name = ("d" * (nb // 2)).encode("utf-16-le")
    kids = d_off + ((102 + nb + 2 + 7) & ~7) + 8
    meta += wim_dentry(0x10, d_off, b"")
    meta += wim_dentry(0x10, kids, d_name)
    meta += b"\0" * 8
    for i in range(k):
        meta += wim_dentry(0x20, 0, chr(0x4E00 + i % 20000).encode("utf-16-le"))
    meta += b"\0" * 8
    meta = bytes(meta)
    ent = bytearray(50)
    struct.pack_into("<QQQ", ent, 0, len(meta) | (0x02 << 56), 208, len(meta))   # RF_METADATA
    struct.pack_into("<HI", ent, 24, 1, 1)
    ent[30:50] = hashlib.sha1(meta).digest()
    h = bytearray(208)
    h[0:8] = b"MSWIM\0\0\0"
    struct.pack_into("<IIII", h, 8, 208, 0x10D00, 0, 0)
    h[24:40] = b"G" * 16
    struct.pack_into("<HHI", h, 40, 1, 1, 1)
    struct.pack_into("<QQQ", h, 48, len(ent), 208 + len(meta), len(ent))
    return bytes(h) + meta + bytes(ent)


def test_wim(t):
    # installers-ms-2: before ~500 MB of names from a 513 KB file
    p = t.path("wim_deep_names.wim")
    open(p, "wb").write(wim_file(4000))
    check(t, "wim: 4000 children of a 65 KB directory name (ms-2)", p, want_limit=True, max_secs=20, max_rss=150)
    p = t.path("wim_deep_names_ok.wim")
    open(p, "wb").write(wim_file(100))
    check(t, "wim: 100 children of a 65 KB directory name", p, want_limit=False, want_rows=101, max_secs=10,
          extra=lambda rows: "" if sum(r["is_dir"] for r in rows) == 1 else "dirs")


# ------------------------------------------------------------------ XAR

def xar_file(toc):
    zt = zlib.compress(toc, 9)
    return b"xar!" + struct.pack(">HHQQI", 28, 1, len(zt), len(toc), 0) + zt


def xar_deep(k, nl=16000, typ=b"file"):
    return xar_file(b'<?xml version="1.0" encoding="UTF-8"?><xar><toc><file id="1"><name>' + b"a" * nl +
                    b"</name><type>directory</type>" +
                    b"".join(b"<file><name>b%d</name><type>%s</type></file>" % (i, typ) for i in range(k)) +
                    b"</file></toc></xar>")


def test_xar(t):
    # installers-ms-4: before ~750 MB (16000 files) and 256 MB of names for one
    # listed entry (16000 fifos)
    p = t.path("xar_deep_names.xar")
    open(p, "wb").write(xar_deep(16000))
    check(t, "xar: 16000 children of a 16 KB directory name (ms-4)", p, want_limit=True, max_secs=20, max_rss=200)
    p = t.path("xar_deep_fifos.xar")
    open(p, "wb").write(xar_deep(16000, typ=b"fifo"))
    check(t, "xar: 16000 fifo children of a 16 KB directory name (ms-4)", p, want_limit=False, want_rows=1,
          max_secs=20, max_rss=120)
    p = t.path("xar_deep_names_ok.xar")
    open(p, "wb").write(xar_deep(300))
    check(t, "xar: 300 children of a 16 KB directory name", p, want_limit=False, want_rows=301, max_secs=10)


# ------------------------------------------------- hard link groups (sorting)

def cpio_newc(entries):
    """entries: (name, ino, devmajor, devminor, nlink, data)"""
    out = bytearray()

    def one(name, ino, dmaj, dmin, nlink, data, mode=0o100644):
        nm = name + b"\0"
        out.extend(b"070701" + b"".join(b"%08X" % v for v in
                   (ino, mode, 0, 0, nlink, 0, len(data), dmaj, dmin, 0, 0, len(nm), 0)))
        out.extend(nm)
        out.extend(b"\0" * ((-len(out)) & 3))
        out.extend(data)
        out.extend(b"\0" * ((-len(out)) & 3))
    for e in entries:
        one(*e)
    one(b"TRAILER!!!", 0, 0, 0, 1, b"", 0)
    return bytes(out)


def links_ok(rows, link, held):
    """every entry named link+X is a hard link to held+X"""
    bad = []
    for r in rows:
        nm, _, target = r["name"].partition(" -> ")
        if nm.startswith(link) and target != held + nm[len(link):]:
            bad.append(r["name"])
    return "unresolved hard links: %r" % bad[:3] if bad else ""


def test_cpio_links(t):
    # installers-ms-5: hard link pairs (size 0 + holder) whose dev/inode keys all hash
    # into one run of buckets of the old table: ((key * K) >> 40) & (cap - 1)
    K = 0x9E3779B97F4A7C15
    KI = pow(K, -1, 1 << 64)
    groups = 1 << 16
    n = 2 * groups
    cap = 16
    while cap < n * 2:
        cap <<= 1
    per = (1 << 24) // cap                               # keys per home bucket
    keys = []
    for j in range((groups + per - 1) // per):
        for v in range(per):
            keys.append(((((v * cap) + 1000 + j) << 40) * KI) & ((1 << 64) - 1))
    keys = keys[:groups]
    ents = []
    for g, key in enumerate(keys):
        ino, hi = key & 0xFFFFFFFF, key >> 32
        ents.append((b"l%05x" % g, ino, 0, hi, 2, b""))
        ents.append((b"h%05x" % g, ino, 0, hi, 2, b"z"))
    p = t.path("cpio_link_collide.cpio")
    open(p, "wb").write(cpio_newc(ents))

    check(t, "cpio: %d hard links with colliding dev/inode keys (ms-5)" % n, p, want_limit=False, want_rows=n,
          max_secs=30, extra=lambda rows: links_ok(rows, "l", "h"))
    for f in (p, p + ".lst"):                            # 16 MB + listing: not worth keeping
        os.remove(f)

    # fuzzer find: an empty first name left a->raw NULL (a->raw + 0 is undefined; seen
    # by UBSan in the code page detection of the listing)
    p = t.path("cpio_empty_first_name.cpio")
    open(p, "wb").write(cpio_newc([(b"", 1, 0, 0, 1, b""), (b"b\xc3\xa9", 2, 0, 0, 1, b"x")]))
    check(t, "cpio: empty first name", p, want_limit=False, max_secs=10)

    # XAR: <file id> values with equal (id * 0x9E3779B1) & (cap - 1); half are hard
    # links naming an earlier id
    nfiles = 1 << 18
    cap = 16
    while cap < nfiles * 2:
        cap <<= 1
    KI32 = pow(0x9E3779B1, -1, 1 << 32)
    per = (1 << 32) // cap                               # ids per home bucket
    ids = [((77 + i // per + (i % per) * cap) * KI32) & 0xFFFFFFFF for i in range(nfiles // 2)]
    parts = [b'<?xml version="1.0" encoding="UTF-8"?><xar><toc>']
    for i, fid in enumerate(ids):
        parts.append(b'<file id="%d"><name>f%d</name><type>file</type></file>' % (fid, i))
    for i, fid in enumerate(ids):
        parts.append(b'<file><name>g%d</name><type link="%d">hardlink</type></file>' % (i, fid))
    parts.append(b"</toc></xar>")
    p = t.path("xar_link_collide.xar")
    open(p, "wb").write(xar_file(b"".join(parts)))

    check(t, "xar: %d hard links to colliding file ids (ms-5)" % (nfiles // 2), p, want_limit=False, want_rows=nfiles,
          max_secs=30, extra=lambda rows: links_ok(rows, "g", "f"))


def run(t):
    test_nsis(t)
    test_wim(t)
    test_xar(t)
    test_cpio_links(t)
