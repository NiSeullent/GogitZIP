"""Regression tests for the disk image readers (ISO 9660, UDF, VMDK, VHD, MBR):

  * ISO interleaved records whose units lie past the end of the image (and overlapping
    interleaved records inside it) must not make a small image build millions of runs;
    files made only of empty extents extract as empty files
  * UDF: allocation descriptors over a sparable partition with packet length 1 and a dense
    sparing table, referenced by several FIDs, must not cost seconds and gigabytes per FID;
    hard links share the runs of the first FID
  * VMDK extents and VHD parent locators must not open files outside the image's folder
    (absolute, UNC, "..", DOS device names), nor anything for an image nested in an archive
  * VHD differencing chains across folders: a parent's locators are relative to its own folder
  * MBR: a one-sector partition must not be sniffed from uninitialised stack bytes (LVM label)

Fixtures are generated here; peak memory and time of the reader are measured per process."""
import importlib.util, os, shutil, struct, subprocess, sys, tarfile, tempfile, threading, time, uuid

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_ISO = os.path.join(os.path.dirname(HERE), "data", "iso")
SEC = 2048
RSS_MAX = 256          # MiB: the readers stay far below; the bombs used to reach 1.5 GiB
TIME_MAX = 20          # s: the bombs used to take 12 - 40 s (they now take milliseconds)


def load(name):
    spec = importlib.util.spec_from_file_location("gz_regress_" + name, os.path.join(DATA_ISO, name + ".py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


_MEASURE = """
import os, subprocess, sys, threading
p = subprocess.Popen(sys.argv[2:], stdin=subprocess.DEVNULL)
t = threading.Timer(float(sys.argv[1]), p.kill)
t.start()
_, st, ru = os.wait4(p.pid, 0)
t.cancel()
rc = os.WEXITSTATUS(st) if os.WIFEXITED(st) else -os.WTERMSIG(st)
sys.stderr.write("\\nGZMEASURE %d %d\\n" % (rc, ru.ru_maxrss))
"""


def measured(cmd, timeout=120, cwd=None):
    """Run cmd: (exit code, stdout, stderr, peak RSS of that process in MiB, seconds)."""
    with tempfile.TemporaryFile() as fo, tempfile.TemporaryFile() as fe:
        t0 = time.time()
        # Linux carries the forking process's RSS high-water mark into the child's ru_maxrss,
        # so a large test runner would be measured instead of gzt: fork from a small helper.
        p = subprocess.Popen([sys.executable, "-I", "-S", "-c", _MEASURE, str(timeout)] + list(cmd),
                             stdout=fo, stderr=fe, stdin=subprocess.PIPE, cwd=cwd)
        try:
            p.communicate(timeout=timeout + 30)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
        dt = time.time() - t0
        fo.seek(0)
        fe.seek(0)
        err = fe.read().decode("utf-8", "replace")
        rc, rss = -9, 1e9
        tail = err.rstrip("\n").rsplit("\n", 1)
        if tail and tail[-1].startswith("GZMEASURE "):
            _, a, b = tail[-1].split()
            rc, rss = int(a), int(b) / (1024.0 * 1024.0 if sys.platform == "darwin" else 1024.0)
            err = tail[0] + "\n" if len(tail) > 1 else ""
        return rc, fo.read().decode("utf-8", "replace"), err, rss, dt


def gzt_list(t, path, timeout=120):
    """gzt l under measurement: (rc, type, rows [(name, usize)], rss, seconds, raw output)"""
    rc, out, err, rss, dt = measured([t.gzt, "l", path], timeout)
    typ, rows = None, []
    for line in out.splitlines():
        p = line.split("\t")
        if p[0] == "TYPE":
            typ = p[1]
        elif len(p) >= 7 and p[0].isdigit():
            rows.append((p[6], int(p[2])))
    return rc, typ, rows, rss, dt, out


def gzt_extract(t, path, timeout=120):
    """gzt x under measurement: (rc, {index: (status, name)}, outdir, rss, seconds)"""
    out = path + ".out"
    shutil.rmtree(out, ignore_errors=True)
    rc, txt, err, rss, dt = measured([t.gzt, "x", path, out], timeout)
    rows = {}
    for line in txt.splitlines():
        p = line.split("\t")
        if len(p) == 5 and p[0].isdigit():
            rows[int(p[0])] = (int(p[1]), p[4])
    return rc, rows, out, rss, dt


def bounded(t, label, rss, dt, extra_ok=True, detail=""):
    ok = extra_ok and rss < RSS_MAX and dt < TIME_MAX
    return t.record(ok, label, "%s rss=%.1f MiB time=%.2fs" % (detail, rss, dt))


# ---------------------------------------------------------------------------
# ISO 9660

def both16(v):
    return struct.pack("<H", v) + struct.pack(">H", v)


def both32(v):
    return struct.pack("<I", v) + struct.pack(">I", v)


def iso_rec(lba, size, flags, ident, fus=0, gap=0):
    nl = len(ident)
    r = bytearray(33 + nl + (0 if nl & 1 else 1))
    r[0] = len(r)
    r[2:10] = both32(lba)
    r[10:18] = both32(size)
    r[18:25] = bytes([100, 1, 1, 0, 0, 0, 0])
    r[25] = flags
    r[26] = fus
    r[27] = gap
    r[28:32] = both16(1)
    r[32] = nl
    r[33:33 + nl] = ident
    return bytes(r)


def iso_image(files, data=None, pad=0):
    """files: [(ident bytes, lba, size, fus, gap[, flags])] in the root; data: {lba: bytes} after the
    directory; pad: zero bytes appended. The root directory starts at sector 18."""
    def layout(recs):                                       # records never cross sectors
        sectors, cur = [], b""
        for r in recs:
            if len(cur) + len(r) > SEC:
                sectors.append(cur.ljust(SEC, b"\0"))
                cur = b""
            cur += r
        return sectors + [cur.ljust(SEC, b"\0")]

    recs = [iso_rec(18, 0, 2, b"\0"), iso_rec(18, 0, 2, b"\1")]
    recs += [iso_rec(f[1], f[2], f[5] if len(f) > 5 else 0, f[0], f[3], f[4]) for f in files]
    root_size = len(layout(recs)) * SEC
    recs[0] = iso_rec(18, root_size, 2, b"\0")
    recs[1] = iso_rec(18, root_size, 2, b"\1")
    sectors = layout(recs)
    pvd = bytearray(SEC)
    pvd[0] = 1
    pvd[1:6] = b"CD001"
    pvd[6] = 1
    pvd[40:72] = b"REGRESS".ljust(32)
    pvd[120:124] = both16(1)
    pvd[124:128] = both16(1)
    pvd[128:132] = both16(SEC)
    pvd[156:156 + 34] = iso_rec(18, root_size, 2, b"\0")
    term = bytearray(SEC)
    term[0] = 255
    term[1:6] = b"CD001"
    term[6] = 1
    img = bytearray(b"\0" * (16 * SEC) + bytes(pvd) + bytes(term) + b"".join(sectors))
    for lba, blob in sorted((data or {}).items()):
        end = lba * SEC + len(blob)
        if len(img) < end:
            img += b"\0" * (end - len(img))
        img[lba * SEC:end] = blob
    img += b"\0" * pad
    struct.pack_into("<I", img, 16 * SEC + 80, len(img) // SEC)
    struct.pack_into(">I", img, 16 * SEC + 84, len(img) // SEC)
    return bytes(img)


def names(n):
    return [bytes([0x41 + i % 26, 0x41 + i // 26 % 26, 0x30 + i // 676]) for i in range(n)]


def iso_cases(t):
    W = t.path("iso")
    os.makedirs(W, exist_ok=True)

    # 70 interleaved records (file unit 1, gap 1, 4 GiB - 1) pointing past the end of a 40 KiB
    # image: used to build 1M runs each (1.5 GiB, 65 of 70 listed; NOMEM on 32-bit)
    p = os.path.join(W, "interleave_beyond.iso")
    open(p, "wb").write(iso_image([(n, 100, 0xFFFFFFFF, 1, 1) for n in names(70)]))
    rc, typ, rows, rss, dt, out = gzt_list(t, p)
    bounded(t, "iso interleaved units past the image: all listed, bounded", rss, dt,
            rc == 0 and typ == "ISO" and len(rows) == 70 and all(s == 0xFFFFFFFF for _, s in rows),
            "rc=%d type=%s rows=%d" % (rc, typ, len(rows)))
    rc, ext, outdir, rss, dt = gzt_extract(t, p)
    st = sorted({s for s, _ in ext.values()})
    bounded(t, "iso interleaved units past the image: extraction fails with TRUNC", rss, dt,
            rc == 0 and len(ext) == 70 and st == [9], "statuses=%s" % st)
    shutil.rmtree(outdir, ignore_errors=True)

    # 70 overlapping interleaved records over an 8 MiB image: ~2K runs each, more than the
    # budget of the open allows -> the files over it are listed but refuse extraction
    p = os.path.join(W, "interleave_inside.iso")
    open(p, "wb").write(iso_image([(n, 0, 0xFFFFFFFF, 1, 1) for n in names(70)], pad=8 << 20))
    rc, typ, rows, rss, dt, out = gzt_list(t, p)
    bounded(t, "iso overlapping interleaved records: all listed, bounded", rss, dt,
            rc == 0 and len(rows) == 70, "rc=%d rows=%d" % (rc, len(rows)))

    # interleaved data still reads right, also when the declared length runs past the image
    unit = [bytes([0x61 + k]) * SEC for k in range(5)]
    D = 40
    data = {D + 2 * k: unit[k] for k in range(3)}          # units 0..2 (gap 1), image ends after 2
    data[D + 1] = data[D + 3] = b"\x99" * SEC               # gaps: garbage
    full = iso_image([(b"INSIDE.BIN;1", D, 3 * SEC - 100, 1, 1), (b"PAST.BIN;1", D, 5 * SEC, 1, 1)], data=data)
    assert len(full) == (D + 5) * SEC                       # PAST.BIN units 3, 4 lie past the end
    p = os.path.join(W, "interleave_partial.iso")
    open(p, "wb").write(full)
    rc, ext, outdir, rss, dt = gzt_extract(t, p)
    by = {n: (s, i) for i, (s, n) in ext.items()}
    good = by.get("INSIDE.BIN", (None,))[0] == 0 and \
        open(os.path.join(outdir, "%d.bin" % by["INSIDE.BIN"][1]), "rb").read() == b"".join(unit[:3])[:3 * SEC - 100]
    t.record(good and by.get("PAST.BIN", (None,))[0] == 9, "iso interleaved data / TRUNC past the image", str(by))
    shutil.rmtree(outdir, ignore_errors=True)

    # files made only of empty extents (multi-extent chain, interleaved) have no runs: they
    # extract as empty files (found by fuzzing: NULL run list + GZ_E_NOMEM before)
    p = os.path.join(W, "empty_extents.iso")
    open(p, "wb").write(iso_image([(b"MULTI.BIN;1", 30, 0, 0, 0, 0x80), (b"MULTI.BIN;1", 31, 0, 0, 0, 0),
                                   (b"INTER0.BIN;1", 30, 0, 1, 1), (b"PLAIN.TXT;1", 30, 5, 0, 0)],
                                  data={30: b"plain" + b"\0" * (SEC - 5)}))
    t.check_extract(p, {"MULTI.BIN": b"", "INTER0.BIN": b"", "PLAIN.TXT": b"plain"}, expect_type="ISO",
                    label="iso files of empty extents extract as empty files")
    # views (random access) agree with extraction (every file must extract for this check)
    open(os.path.join(W, "interleave_ok.iso"), "wb").write(
        iso_image([(b"INSIDE.BIN;1", D, 3 * SEC - 100, 1, 1), (b"MULTI.BIN;1", D + 2, 100, 0, 0, 0x80),
                   (b"MULTI.BIN;1", D, SEC, 0, 0, 0)], data=data))
    ls = t.build_driver("tests/drivers/fmt_iso_ls.c", "regress_iso_ls")
    for name in ("empty_extents.iso", "interleave_ok.iso"):
        r = subprocess.run([ls, "viewcheck", os.path.join(W, name)], capture_output=True, timeout=120)
        out = r.stdout.decode(errors="replace").strip().splitlines()
        t.record(r.returncode == 0 and out and "BAD 0" in out[-1], "iso views " + name, out[-1] if out else "")


# ---------------------------------------------------------------------------
# UDF

def udf_bomb(U, nref):
    """Sparable volume, packet length 1, one sparing table remapping every other block of 128K
    blocks, partition length 0; one EFE with info length 2^62 and short ADs of 1 GiB at block 0
    referenced by 1 + nref FIDs."""
    bs = 2048
    u = U.Udf(layout="sparable", rev=0x201, bs=bs)
    f = u.file(u.root, "big", b"x" * bs)
    for i in range(nref):
        u.ref(u.root, "r%03d" % i, target=f, is_dir=False)
    img = bytearray(u.build())

    def tag_fix(o):
        img[o + 4] = sum(img[o + i] for i in range(16) if i != 4) & 0xff

    nsec = len(img) // bs
    st_sec, NENT = nsec, 65535
    found = [0, 0, 0]
    for s in range(nsec):
        o = s * bs
        tid = struct.unpack_from("<H", img, o)[0]
        if tid == 6 and img[o + 440] == 2 and img[o + 441] == 64:
            m = o + 440
            struct.pack_into("<H", img, m + 40, 1)
            img[m + 42] = 1
            struct.pack_into("<I", img, m + 44, 56 + 8 * NENT)
            struct.pack_into("<I", img, m + 48, st_sec)
            found[0] += 1
        elif tid == 5 and img[o + 1] == 0:
            struct.pack_into("<I", img, o + 192, 0)
            found[1] += 1
        elif tid in (261, 266) and img[o + 27] == 5:
            base = 216 if tid == 266 else 176
            lea = struct.unpack_from("<I", img, o + base - 8)[0]
            nad = (bs - base - lea) // 8
            struct.pack_into("<Q", img, o + 56, 1 << 62)
            struct.pack_into("<H", img, o + 34, struct.unpack_from("<H", img, o + 34)[0] & ~7)
            struct.pack_into("<I", img, o + base - 4, nad * 8)
            for k in range(nad):
                struct.pack_into("<II", img, o + base + lea + 8 * k, 0x3FFFFFFF, 0)
            found[2] += 1
    assert found[0] and found[1] and found[2] == 1, found
    st = bytearray(56 + 8 * NENT)
    st[17:35] = b"*UDF Sparing Table"
    struct.pack_into("<H", st, 48, NENT)
    for i in range(NENT):
        struct.pack_into("<II", st, 56 + 8 * i, 4096 + 2 * i, 3000000 + 2 * i)
    struct.pack_into("<H", st, 2, 2)
    struct.pack_into("<I", st, 12, st_sec)
    img += st
    img += b"\0" * ((-len(img)) % bs)
    tag_fix(st_sec * bs)
    return bytes(img)


def udf_cases(t):
    U = load("udfgen")
    W = t.path("udf")
    os.makedirs(W, exist_ok=True)
    p = os.path.join(W, "sparable_bomb.udf")
    open(p, "wb").write(udf_bomb(U, 4))
    rc, typ, rows, rss, dt, out = gzt_list(t, p)
    bounded(t, "udf sparable AD bomb (5 FIDs): listed, bounded", rss, dt,
            rc == 0 and typ == "UDF" and len(rows) == 5, "rc=%d type=%s rows=%d" % (rc, typ, len(rows)))
    rc, ext, outdir, rss, dt = gzt_extract(t, p)
    st = sorted({s for s, _ in ext.values()})
    bounded(t, "udf sparable AD bomb: extraction reports LIMIT, not NOMEM", rss, dt,
            rc == 0 and len(ext) == 5 and st == [15], "statuses=%s" % st)
    shutil.rmtree(outdir, ignore_errors=True)

    # hard links share the first FID's runs; mapping through every partition kind stays exact
    payload = bytes((i * 7 + i // 2048) & 0xff for i in range(300000))
    for layout, rev, kw in (("type1", 0x201, {}), ("sparable", 0x150, {"remap": True, "efe": False}),
                            ("sparable", 0x201, {"remap": True}), ("vat", 0x201, {}), ("meta", 0x250, {})):
        u = U.Udf(layout=layout, rev=rev, **kw)
        sub = u.dir(u.root, "sub")
        f = u.file(u.root, "data.bin", payload)
        u.file(u.root, "split.bin", payload[:70000], split=9000)
        u.ref(u.root, "link1", target=f, is_dir=False)
        u.ref(sub, "link2", target=f, is_dir=False)
        name = "links_%s_%x.udf" % (layout, rev)
        p = os.path.join(W, name)
        open(p, "wb").write(u.build())
        t.check_extract(p, {"data.bin": payload, "link1": payload, "sub/link2": payload, "sub": None,
                            "split.bin": payload[:70000]}, expect_type="UDF", label="udf hard links " + name)


# ---------------------------------------------------------------------------
# VMDK / VHD referenced files

def vhd_footer(vsize, dtype, data_off, uid):
    f = bytearray(512)
    f[0:8] = b"conectix"
    struct.pack_into(">IIQI", f, 8, 2, 0x10000, data_off, 0x2a2a2a2a)
    f[28:32] = b"gzt "
    struct.pack_into(">I", f, 32, 0x10000)
    f[36:40] = b"Wi2k"
    struct.pack_into(">QQII", f, 40, vsize, vsize, 0, dtype)
    f[68:84] = uid
    struct.pack_into(">I", f, 64, (~sum(f)) & 0xFFFFFFFF)
    return bytes(f)


def vhd_fixed(path, data, uid):
    open(path, "wb").write(data + vhd_footer(len(data), 2, 0xFFFFFFFFFFFFFFFF, uid))
    return uid


def vhd_diff(path, vsize, bs, blocks, parent_uid, parent_name, locators=()):
    """Differencing disk: blocks {index: data (full block, bitmap all set)};
    locators: [(b"W2ru" | b"W2ku" | b"MacX", bytes)]"""
    uid = uuid.uuid4().bytes
    nbat = (vsize + bs - 1) // bs
    bmp = (((bs // 512) + 7) // 8 + 511) // 512 * 512
    bat_off = 1536
    pos = bat_off + (nbat * 4 + 511) // 512 * 512
    locs = []
    for code, data in locators:
        locs.append((code, pos, data))
        pos += (len(data) + 511) // 512 * 512
    bat = [0xFFFFFFFF] * nbat
    body = bytearray()
    for i in sorted(blocks):
        bat[i] = (pos + len(body)) // 512
        body += b"\xff" * (bs // 512 // 8) + b"\0" * (bmp - bs // 512 // 8) + blocks[i]
    h = bytearray(1024)
    h[0:8] = b"cxsparse"
    struct.pack_into(">QQIII", h, 8, 0xFFFFFFFFFFFFFFFF, bat_off, 0x10000, nbat, bs)
    h[40:56] = parent_uid
    nm = parent_name.encode("utf-16-be")
    h[64:64 + len(nm)] = nm
    for k, (code, off, data) in enumerate(locs):
        struct.pack_into(">4sIIIQ", h, 576 + 24 * k, code, (len(data) + 511) // 512 * 512, len(data), 0, off)
    struct.pack_into(">I", h, 36, (~sum(h)) & 0xFFFFFFFF)
    foot = vhd_footer(vsize, 4, 512, uid)
    with open(path, "wb") as f:
        f.write(foot)
        f.write(h)
        f.write(struct.pack(">%dI" % nbat, *bat).ljust((nbat * 4 + 511) // 512 * 512, b"\xff"))
        for code, off, data in locs:
            f.write(data.ljust((len(data) + 511) // 512 * 512, b"\0"))
        f.write(body)
        f.write(foot)
    return uid


def w2(s):
    return s.encode("utf-16-le")


class Paths:
    """tests/drivers/vd_paths.c: the paths a reader asks open_volume for"""

    def __init__(self, t):
        self.t = t
        self.exe = t.build_driver("tests/drivers/vd_paths.c")

    def run(self, *args, cwd=None):
        r = subprocess.run([self.exe] + list(args), capture_output=True, timeout=120, cwd=cwd)
        out = r.stdout.decode("utf-8", "replace")
        vols = [l[4:] for l in out.splitlines() if l.startswith("VOL ")]
        rc = [int(l.split()[1]) for l in out.splitlines() if l.startswith("OPEN ")]
        return (rc[0] if rc else None), vols, out

    def check(self, label, img, folder, want_rc):
        rc, vols, out = self.run("open", img)
        folder = os.path.realpath(folder)
        bad = [v for v in vols if v.startswith("//") or v.startswith("\\") or ".." in v.replace("\\", "/").split("/")
               or os.path.commonpath([os.path.realpath(v), folder]) != folder]
        return self.t.record(rc == want_rc and not bad, label, "rc=%s outside=%s vols=%s" % (rc, bad, vols[:6]))


VMDK_HEAD = '# Disk DescriptorFile\nversion=1\nCID=12345678\nparentCID=ffffffff\ncreateType="monolithicFlat"\n'


def vmdk_cases(t, d):
    W = t.path("vmdk")
    shutil.rmtree(W, ignore_errors=True)
    img = os.path.join(W, "img")
    os.makedirs(os.path.join(img, "sub"))
    secret = b"SECRET!!" * 64
    local = b"local extent" + b"\0" * 500
    open(os.path.join(W, "secret.bin"), "wb").write(secret)
    open(os.path.join(img, "local.bin"), "wb").write(local)
    open(os.path.join(img, "sub", "deep.bin"), "wb").write(b"D" * 512)

    def desc(name, extent):
        p = os.path.join(img, name)
        open(p, "w").write(VMDK_HEAD + 'RW 1 FLAT "%s" 0\n' % extent)
        return p

    # outside the image's folder: refused (only the base name next to the image is looked up)
    for name, extent in (("abs.vmdk", os.path.join(W, "secret.bin")), ("rel.vmdk", "../secret.bin"),
                         ("rel2.vmdk", "sub/../../secret.bin"), ("unc.vmdk", r"\\attacker\share\secret.bin"),
                         ("dev.vmdk", r"\\.\PhysicalDrive0"), ("drive.vmdk", "C:secret.bin"),
                         ("con.vmdk", "con.txt"), ("dots.vmdk", "sub/.../secret.bin")):
        p = desc(name, extent)
        d.check("vmdk extent %r stays in the folder" % extent, p, img, 14)
        rc, ext, outdir, rss, dt = gzt_extract(t, p)
        leaked = any(os.path.exists(os.path.join(outdir, f)) and open(os.path.join(outdir, f), "rb").read() == secret
                     for f in (os.listdir(outdir) if os.path.isdir(outdir) else []))
        t.record(not leaked and rc != 0, "vmdk %s: secret not extracted" % name, "rc=%d" % rc)
        shutil.rmtree(outdir, ignore_errors=True)
    # inside: subfolders, "x/.." and absolute names whose base name is next to the image
    for name, extent, data in (("down.vmdk", "sub/deep.bin", b"D" * 512), ("updown.vmdk", "sub/../local.bin", local),
                               ("absnear.vmdk", "/no/such/dir/local.bin", local),
                               ("winabs.vmdk", r"D:\VMs\local.bin", local)):
        p = desc(name, extent)
        d.check("vmdk extent %r opens inside the folder" % extent, p, img, 0)
        t.check_extract(p, {name[:-5] + ".img": data}, label="vmdk %s data" % name)
    # an image inside another archive has no folder: nothing is opened (not even relative to
    # the current directory, which is where the extent would be found here)
    inner = os.path.join(W, "inner.vmdk")
    open(inner, "w").write(VMDK_HEAD + 'RW 1 FLAT "local.bin" 0\n')
    tp = os.path.join(img, "nested.tar")
    with tarfile.open(tp, "w", format=tarfile.USTAR_FORMAT) as tf:
        tf.add(inner, "inner.vmdk")
    rc, vols, out = d.run("child", tp, "0", "inner.vmdk", cwd=img)
    t.record(rc == 14 and not vols, "vmdk nested in an archive opens no extent", "rc=%s vols=%s" % (rc, vols))


def vhd_cases(t, d):
    W = t.path("vhd")
    shutil.rmtree(W, ignore_errors=True)
    bs, vsize = 4096, 16 * 4096

    # chain across folders: top -> sub/mid -> sub/base; mid's locator is relative to sub/
    C = os.path.join(W, "chain")
    os.makedirs(os.path.join(C, "sub"))
    base_uid = vhd_fixed(os.path.join(C, "sub", "base.vhd"), b"B" * vsize, uuid.uuid4().bytes)
    mid_uid = vhd_diff(os.path.join(C, "sub", "mid.vhd"), vsize, bs, {1: b"M" * bs}, base_uid, "base.vhd",
                       [(b"W2ru", w2(".\\base.vhd"))])
    vhd_diff(os.path.join(C, "top.vhd"), vsize, bs, {2: b"T" * bs}, mid_uid, "mid.vhd", [(b"W2ru", w2(".\\sub\\mid.vhd"))])
    expect = b"B" * bs + b"M" * bs + b"T" * bs + b"B" * (13 * bs)
    t.check_extract(os.path.join(C, "top.vhd"), {"top.img": expect}, label="vhd chain across folders")
    d.check("vhd chain across folders: opens inside", os.path.join(C, "top.vhd"), C, 0)

    # a parent's ".." stays allowed while it remains inside the opened image's folder
    G = os.path.join(W, "tree")
    os.makedirs(os.path.join(G, "snap"))
    gb = vhd_fixed(os.path.join(G, "base.vhd"), b"G" * vsize, uuid.uuid4().bytes)
    gm = vhd_diff(os.path.join(G, "snap", "mid.vhd"), vsize, bs, {0: b"m" * bs}, gb, "nonexistent.vhd",
                  [(b"W2ru", w2("..\\base.vhd"))])
    vhd_diff(os.path.join(G, "top.vhd"), vsize, bs, {3: b"t" * bs}, gm, "nonexistent.vhd",
             [(b"W2ru", w2(".\\snap\\mid.vhd"))])
    t.check_extract(os.path.join(G, "top.vhd"), {"top.img": b"m" * bs + b"G" * (2 * bs) + b"t" * bs + b"G" * (12 * bs)},
                    label="vhd parent '..' inside the opened folder")

    # parents outside the folder (absolute, "..", file:// URL) are never opened, even when valid
    O = os.path.join(W, "out")
    os.makedirs(os.path.join(O, "img"))
    puid = vhd_fixed(os.path.join(O, "parent.vhd"), b"P" * vsize, uuid.uuid4().bytes)
    child = os.path.join(O, "img", "child.vhd")
    vhd_diff(child, vsize, bs, {}, puid, "elsewhere.vhd",
             [(b"W2ku", w2(os.path.join(O, "parent.vhd"))), (b"W2ru", w2("..\\parent.vhd")),
              (b"MacX", ("file://localhost" + os.path.join(O, "parent.vhd")).encode()),
              (b"W2ru", w2("\\\\attacker\\share\\parent.vhd"))])
    d.check("vhd parent outside the folder is not opened", child, os.path.join(O, "img"), 5)
    rc, typ, rows, rss, dt, out = gzt_list(t, child)
    t.record(rc == 1 and "OPEN_ERROR 5" in out, "vhd parent outside the folder -> METHOD", out.strip()[:200])

    # an absolute locator still finds the parent by its base name next to the child
    N = os.path.join(W, "near")
    os.makedirs(N)
    nuid = vhd_fixed(os.path.join(N, "p.vhd"), b"N" * vsize, uuid.uuid4().bytes)
    vhd_diff(os.path.join(N, "c.vhd"), vsize, bs, {5: b"c" * bs}, nuid, "zzz.vhd",
             [(b"W2ku", w2("C:\\Hyper-V\\far\\p.vhd"))])
    t.check_extract(os.path.join(N, "c.vhd"), {"c.img": b"N" * (5 * bs) + b"c" * bs + b"N" * (10 * bs)},
                    label="vhd absolute locator -> base name next to the child")


# ---------------------------------------------------------------------------
# MBR

def mbr_cases(t):
    W = t.path("mbr")
    os.makedirs(W, exist_ok=True)
    d = bytearray(64 * 1024)

    def part(i, typ, lba, n):
        o = 446 + 16 * i
        d[o + 4] = typ
        struct.pack_into("<II", d, o + 8, lba, n)

    # partition 1: LVM physical volume (label in its sector 1); partition 2: one sector whose
    # following sector also says LABELONE - neither may make the 1-sector partition "lvm"
    part(0, 0x8E, 8, 16)
    part(1, 0x83, 32, 1)
    d[510:512] = b"\x55\xaa"
    d[9 * 512:9 * 512 + 8] = b"LABELONE"
    d[32 * 512:33 * 512] = b"\xA5" * 512
    d[33 * 512:33 * 512 + 8] = b"LABELONE"
    p = os.path.join(W, "one_sector.raw")
    open(p, "wb").write(d)
    rc, typ, rows, rss, dt, out = gzt_list(t, p)
    t.record([n for n, _ in rows] == ["1.lvm", "2.linux"], "mbr one-sector partition not sniffed past its end",
             str(rows))
    # valgrind (when present and the driver is not sanitizer-instrumented): no uninitialised read
    if shutil.which("valgrind") and b"__asan_init" not in open(t.gzt, "rb").read():
        r = subprocess.run(["valgrind", "-q", "--error-exitcode=99", t.gzt, "l", p], capture_output=True, timeout=300)
        err = r.stderr.decode(errors="replace")
        t.record(not ("uninitialised" in err and "mbr.c" in err), "mbr one-sector partition under valgrind",
                 err[-300:] if "mbr.c" in err else "rc=%d" % r.returncode)


def run(t):
    iso_cases(t)
    udf_cases(t)
    d = Paths(t)
    vmdk_cases(t, d)
    vhd_cases(t, d)
    mbr_cases(t)
