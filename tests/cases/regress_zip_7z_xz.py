"""Regression cases for the zip-7z-xz slice (review findings zip-7z-xz-1 .. 5).

1. ZIP: the ZIP64 end record's entry count must not size the entry array beyond
   what the central directory can hold (189-byte file asked for 2 GiB).
   Checked with tests/drivers/alloc_peak.c (largest calloc while opening).
2. TAR: GNU sparse members (old GNU type 'S' with extension blocks, pax 0.0,
   0.1 and 1.0) are listed with their real name/size and extracted expanded,
   from plain .tar (random access) and .tar.gz (stream); broken maps fail the
   member instead of writing the raw map. Archives are generated here and the
   generator is checked against GNU tar; GNU tar's own sparse archives too.
3. TAR / LZOP: absurd mtimes (base-256, pax, lzop high word) must not overflow
   in gz_unix_to_filetime: they are left unknown (unixfmt dump shows "-").
4. ZIP: a wrong password that passes the ZipCrypto check byte gives
   GZ_E_PASSWORD, not GZ_E_DATA; AES entries whose decoding fails verify the
   HMAC (tampered -> GZ_E_AUTH, authentic but corrupt -> the decoder error).
5. 7z: archives whose coders have no properties (Copy, BCJ+Copy) must not form
   `NULL + offset` (UBSan "applying zero offset to null pointer").

6. (found by the fuzz run) a TAR whose only names are empty (empty header name,
   empty pax path / GNU.sparse.name) left a->raw NULL, and the core formed
   a->raw + raw_off while choosing the code page (src/core/arc.c).

Items 3, 5 and 6 are undefined behaviour: besides the functional checks, a gzt is
linked with the touched sources built by clang -fsanitize=undefined
(-fno-sanitize-recover) and must stay silent (skipped without clang, or when
HOST_CFLAGS already carries sanitizers built by another compiler).
"""
import os, io, gzip, hashlib, hmac, random, shutil, struct, subprocess, sys, zlib

E_FORMAT, E_DATA, E_CRC, E_METHOD, E_PASSWORD, E_TRUNC, E_AUTH, E_LIMIT = 2, 3, 4, 5, 6, 9, 12, 15

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ------------------------------------------------------------------ ZIP helpers

def zip64_count_zip(count=0xFFFFFF, plain_count=None):
    """One stored entry a.txt = b"hello". plain_count: classic end record only
    (with that 16-bit count), else ZIP64 end record + locator carrying count."""
    name, data = b"a.txt", b"hello"
    crc = zlib.crc32(data)
    lh = struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0, 0, 0, 0x21, crc, 5, 5, len(name), 0) + name + data
    cd = struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 0, 0, 0, 0x21, crc, 5, 5, len(name),
                     0, 0, 0, 0, 0x20, 0) + name
    cdo = len(lh)
    out = lh + cd
    if plain_count is not None:
        return out + struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, plain_count, plain_count, len(cd), cdo, 0)
    z64 = len(out)
    out += struct.pack("<IQHHIIQQQQ", 0x06064B50, 44, 45, 45, 0, 0, count, count, len(cd), cdo)
    out += struct.pack("<IIQI", 0x07064B50, 0, z64, 1)
    out += struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0)
    return out

def _crc_byte(c, b):
    c ^= b
    for _ in range(8):
        c = (c >> 1) ^ (0xEDB88320 if c & 1 else 0)
    return c

_TAB = [_crc_byte(0, i) for i in range(256)]

class ZipCrypto:
    def __init__(self, pw):
        self.k = [0x12345678, 0x23456789, 0x34567890]
        for b in pw:
            self.upd(b)

    def upd(self, b):
        k = self.k
        k[0] = (k[0] >> 8) ^ _TAB[(k[0] ^ b) & 0xFF]
        k[1] = ((k[1] + (k[0] & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        k[2] = (k[2] >> 8) ^ _TAB[(k[2] ^ (k[1] >> 24)) & 0xFF]

    def ks(self):
        t = (self.k[2] | 2) & 0xFFFF
        return ((t * (t ^ 1)) >> 8) & 0xFF

    def encrypt(self, data):
        out = bytearray()
        for b in data:
            out.append(b ^ self.ks())
            self.upd(b)
        return bytes(out)

    def decrypt(self, data):
        out = bytearray()
        for c in data:
            b = c ^ self.ks()
            self.upd(b)
            out.append(b)
        return bytes(out)

def zip_one(name, method, flags, crc, usize, payload, extra=b""):
    """single-entry ZIP with the given (already encrypted) payload"""
    name = name.encode()
    lh = struct.pack("<IHHHHHIIIHH", 0x04034B50, 51, flags, method, 0x6000, 0x5021, crc, len(payload), usize,
                     len(name), len(extra)) + name + extra + payload
    cd = struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 51, 51, flags, method, 0x6000, 0x5021, crc, len(payload),
                     usize, len(name), len(extra), 0, 0, 0, 0x20, 0) + name + extra
    return lh + cd + struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(cd), len(lh), 0)

def zipcrypto_zip(data, pw):
    crc = zlib.crc32(data)
    co = zlib.compressobj(6, zlib.DEFLATED, -15)
    comp = co.compress(data) + co.flush()
    hdr = random.Random(5).randbytes(11) + bytes([crc >> 24])
    return zip_one("data.txt", 8, 1, crc, len(data), ZipCrypto(pw).encrypt(hdr + comp)), crc

def passes_check(arc_payload, pw, crc):
    return ZipCrypto(pw).decrypt(arc_payload[:12])[11] == crc >> 24

def aes_ecb(key):
    try:
        from Cryptodome.Cipher import AES
        return AES.new(key, AES.MODE_ECB).encrypt
    except ImportError:
        pass
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        return Cipher(algorithms.AES(key), modes.ECB()).encryptor().update
    except ImportError:
        return None

def winzip_aes_zip(plain_comp, usize, pw, tamper=None):
    """AE-2 AES-256 entry (real method Deflate) holding plain_comp; tamper(ct) may
    change the ciphertext after the HMAC was computed. None without an AES module."""
    salt = bytes(range(1, 17))
    dk = hashlib.pbkdf2_hmac("sha1", pw, salt, 1000, 66)
    ecb = aes_ecb(dk[:32])
    if not ecb:
        return None
    ks = bytearray()
    ctr = 1
    while len(ks) < len(plain_comp):
        ks += ecb(ctr.to_bytes(16, "little"))
        ctr += 1
    ct = bytes(a ^ b for a, b in zip(plain_comp, ks))
    mac = hmac.new(dk[32:64], ct, hashlib.sha1).digest()[:10]
    if tamper:
        ct = tamper(ct)
    extra = struct.pack("<HHH2sBH", 0x9901, 7, 2, b"AE", 3, 8)
    return zip_one("data.txt", 99, 1, 0, usize, salt + dk[64:66] + ct + mac, extra)

# ------------------------------------------------------------------ TAR helpers

def oct_field(v, n):
    s = b"%0*o" % (n - 1, v)
    if len(s) > n - 1:
        raise ValueError("octal field overflow")
    return s + b"\0"

def b256(v, n):
    """GNU base-256 (two's complement, 0x80 marker)"""
    if v < 0:
        v += 1 << (8 * n)
    b = v.to_bytes(n, "big")
    return bytes([b[0] | 0x80]) + b[1:]

def tar_hdr(name, size, typeflag=b"0", mtime=1600000000, gnu=False, extra=()):
    h = bytearray(512)
    name = name.encode() if isinstance(name, str) else name
    h[0:len(name)] = name
    h[100:108] = oct_field(0o644, 8)
    h[108:116] = oct_field(0, 8)
    h[116:124] = oct_field(0, 8)
    h[124:136] = size if isinstance(size, bytes) else oct_field(size, 12)
    h[136:148] = mtime if isinstance(mtime, bytes) else oct_field(mtime, 12)
    h[156:157] = typeflag
    if gnu:
        h[257:265] = b"ustar  \0"
    else:
        h[257:263] = b"ustar\0"
        h[263:265] = b"00"
    for off, b in extra:
        h[off:off + len(b)] = b
    h[148:156] = b" " * 8
    h[148:156] = b"%06o\0 " % sum(h)
    return bytes(h)

def pad512(b):
    return b + bytes(-len(b) % 512)

def pax_rec(k, v):
    body = (" %s=%s\n" % (k, v)).encode()
    n = len(body) + 1
    while len(str(n)) + len(body) != n:
        n = len(str(n)) + len(body)
    return str(n).encode() + body

def pax_hdr(recs, name="pax"):
    meta = b"".join(pax_rec(k, v) for k, v in recs)
    return tar_hdr("PaxHeaders.0/" + name, len(meta), b"x") + pad512(meta)

def plain_member(name, data):
    return tar_hdr(name, len(data)) + pad512(data)

END = bytes(1024)

def sparse_model(real, chunks, seed=1):
    """file content and the stored bytes (chunk data in map order)"""
    rnd = random.Random(seed)
    buf = bytearray(real)
    stored = bytearray()
    for o, l in chunks:
        d = bytes(rnd.randrange(1, 256) for _ in range(l))
        buf[o:o + l] = d
        stored += d
    return bytes(buf), bytes(stored)

def gnu_old_sparse(name, real, chunks, stored, size=None, ext_cut=False):
    """old GNU 'S' member: 4 slots in the header, 21 per extension block"""
    slots = list(chunks)
    head, rest = slots[:4], slots[4:]
    extra = []
    for i, (o, l) in enumerate(head):
        extra.append((386 + 24 * i, oct_field(o, 12)))
        extra.append((386 + 24 * i + 12, oct_field(l, 12)))
    extra.append((482, b"\1" if rest else b"\0"))
    extra.append((483, oct_field(real, 12)))
    out = tar_hdr(name, len(stored) if size is None else size, b"S", gnu=True, extra=extra)
    if ext_cut:
        return out
    while rest:
        part, rest = rest[:21], rest[21:]
        b = bytearray(512)
        for i, (o, l) in enumerate(part):
            b[24 * i:24 * i + 12] = oct_field(o, 12)
            b[24 * i + 12:24 * i + 24] = oct_field(l, 12)
        b[504] = 1 if rest else 0
        out += bytes(b)
    return out + pad512(stored)

def pax00_sparse(name, real, chunks, stored):
    recs = [("GNU.sparse.size", real), ("GNU.sparse.numblocks", len(chunks))]
    for o, l in chunks:
        recs += [("GNU.sparse.offset", o), ("GNU.sparse.numbytes", l)]
    return pax_hdr(recs, name) + tar_hdr(name, len(stored)) + pad512(stored)

def pax01_sparse(name, real, chunks, stored, map_text=None):
    m = map_text if map_text is not None else ",".join("%d,%d" % c for c in chunks)
    recs = [("GNU.sparse.size", real), ("GNU.sparse.numblocks", len(chunks)), ("GNU.sparse.map", m)]
    return pax_hdr(recs, name) + tar_hdr(name, len(stored)) + pad512(stored)

def pax10_sparse(name, real, chunks, stored, map_text=None, major=1, minor=0):
    m = map_text if map_text is not None else \
        ("%d\n" % len(chunks)).encode() + b"".join(b"%d\n%d\n" % c for c in chunks)
    data = pad512(m) + stored
    recs = [("GNU.sparse.major", major), ("GNU.sparse.minor", minor), ("GNU.sparse.name", name),
            ("GNU.sparse.realsize", real)]
    return pax_hdr(recs, name) + tar_hdr("GNUSparseFile.0/" + name, len(data)) + pad512(data)

# GNU tar writes every chunk but the last as whole 512-byte blocks (its hole
# scan works on blocks) and ends the map with (realsize, 0) when the file ends
# in a hole; its reader relies on both. libarchive, Python's tarfile and 7-Zip
# read the chunks back to back and extend the file to the real size, as 고깃ZIP
# does. They agree on maps GNU tar writes ("aligned"), so GNU tar checks those
# and tarfile checks all.
LAYOUTS = {
    # name: (real size, chunks, aligned)
    "gnulike": (1 << 20, [(0, 4096), (897024, 4096), (1 << 20, 0)], True),
    "many": (29 * 8192 + 812, [(i * 8192 + 512, 512 * (1 + i % 3)) for i in range(29)] + [(29 * 8192 + 512, 300)],
             True),                                                     # 4 slots + 2 extension blocks
    "ext1": (24 * 1024 + 7, [(i * 1024, 512) for i in range(24)] + [(24 * 1024, 7)], True),   # 4 + one block of 21
    "four": (3 * 1024 + 100, [(i * 1024, 512) for i in range(3)] + [(3 * 1024, 100)], True),  # header slots only
    "endhole": (9000, [(0, 512), (4096, 512), (9000, 0)], True),
    "hole": (100000, [(100000, 0)], True),                              # nothing stored
    "tail": (3000, [(0, 0), (2990, 10)], True),
    "odd": (2000, [(1, 1), (513, 700)], False),
    "short": (30 * 1000, [(i * 1000 + 7, 11 + i) for i in range(30)], False),   # trailing hole, no (size, 0)
}

def tarfile_extract(p, name):
    """reference: Python's tarfile reads all four GNU sparse variants"""
    import tarfile
    with tarfile.open(p) as tf:
        for m in tf.getmembers():
            if m.name == name:
                return tf.extractfile(m).read()
    return None

WRITERS = {"S": gnu_old_sparse, "pax00": pax00_sparse, "pax01": pax01_sparse, "pax10": pax10_sparse}

def is_gnu_tar(t):
    if not t.tool("tar"):
        return False
    r = subprocess.run(["tar", "--version"], capture_output=True)
    return b"GNU tar" in r.stdout

# ------------------------------------------------------------------ UBSan gzt

def ubsan_gzt(t):
    """gzt with the touched sources (and str.c, where the time conversion is)
    built by clang -fsanitize=undefined; None when not possible here."""
    if "sanitize" in os.environ.get("HOST_CFLAGS", "") or not t.tool("clang") or sys.platform == "darwin":
        return None
    host = os.path.join(os.path.dirname(t.gzt), "host")
    inst = ["core/str", "core/arc", "fmt/tar", "fmt/lzop", "fmt/streamfmt", "fmt/sevenz", "fmt/zip"]
    objs = []
    for dp, dns, fns in os.walk(host):
        for f in fns:
            if not f.endswith(".o"):
                continue
            rel = os.path.relpath(os.path.join(dp, f), host)[:-2].replace(os.sep, "/")
            if rel.startswith("app/") or rel in inst:
                continue
            objs.append(os.path.join(dp, f))
    out = t.path("ubsan", "gzt")
    flags = ["-std=gnu11", "-O1", "-g", "-fsanitize=undefined", "-fno-sanitize-recover=undefined", "-pthread",
             "-finput-charset=UTF-8"] + ["-I" + os.path.join(ROOT, d) for d in ("src/core", "src/codec", "src/fmt",
                                                                                 "src/app", "src/posix")]
    mine = []
    for rel in inst:
        o = t.path("ubsan", rel.replace("/", "_") + ".o")
        t.sh(["clang"] + flags + ["-c", os.path.join(ROOT, "src", rel + ".c"), "-o", o])
        mine.append(o)
    t.sh(["clang"] + flags + ["-o", out, os.path.join(ROOT, "tests", "gzt.c")] + sorted(objs) + mine + ["-pthread"])
    return out

def ubsan_clean(t, ub, label, args):
    r = subprocess.run([ub] + args, capture_output=True, timeout=120)
    err = r.stderr.decode(errors="replace")
    bad = "runtime error" in err or r.returncode not in (0, 1)
    return t.record(not bad, "ubsan " + label, "rc=%d %s" % (r.returncode, err[-400:] if bad else ""))

# ------------------------------------------------------------------ cases

def case_zip_count(t):
    if not sys.platform.startswith("linux"):
        t.record(True, "zip64 count alloc", "skipped: needs GNU ld --wrap")
        return
    drv = t.build_driver("tests/drivers/alloc_peak.c", extra=["-Wl,--wrap=calloc"])
    ref = t.path("zip", "normal.zip")
    with open(ref, "wb") as f:
        f.write(zip64_count_zip(plain_count=1))
    cases = [("zip64_count.zip", zip64_count_zip()),                    # the reviewer's 189-byte file
             ("zip64_count_max.zip", zip64_count_zip(count=(1 << 24) - 1)),
             ("eocd_count_ffff.zip", zip64_count_zip(plain_count=0xFFFF))]
    r = subprocess.run([drv, ref], capture_output=True, timeout=60)
    base = int(r.stdout.split(b"PEAK ")[1]) if b"PEAK " in r.stdout else 0
    for name, data in cases:
        p = t.path("zip", name)
        with open(p, "wb") as f:
            f.write(data)
        if name == "zip64_count.zip":
            t.record(len(data) == 189, name + " is the reviewer's 189-byte layout", str(len(data)))
        r = subprocess.run([drv, p], capture_output=True, timeout=60)
        out = r.stdout.decode(errors="replace")
        peak = int(out.split("PEAK ")[1]) if "PEAK " in out else -1
        lines = out.splitlines()
        t.record(r.returncode == 0 and "N 1" in lines and "E a.txt" in lines, name + " lists a.txt", out[:200])
        # the entry array may not exceed what the directory can hold: no request
        # above the plain archive's peak + a few entries
        t.record(0 <= peak <= max(base, 1 << 16) + 4096, name + " no header-sized allocation",
                 "peak=%d (plain archive %d)" % (peak, base))
        t.check_extract(p, {"a.txt": b"hello"}, label=name + " extract")

def case_tar_sparse(t):
    gnu = is_gnu_tar(t)
    plain = b"plain after the sparse member\n" * 3
    for kind, writer in WRITERS.items():
        for lname, (real, chunks, aligned) in LAYOUTS.items():
            content, stored = sparse_model(real, chunks, seed=len(lname) * 7 + len(kind))
            arc = writer("sparse.bin", real, chunks, stored) + plain_member("plain.txt", plain) + END
            p = t.path("sparse", "%s_%s.tar" % (kind, lname))
            with open(p, "wb") as f:
                f.write(arc)
            label = "sparse %s %s" % (kind, lname)
            # the generator itself must be right
            ref = tarfile_extract(p, "sparse.bin")
            t.record(ref == content, label + " (Python tarfile agrees with the generator)",
                     "" if ref == content else "tarfile: %s bytes" % (None if ref is None else len(ref)))
            if gnu and aligned:
                ref = t.path("sparse", "ref_%s_%s" % (kind, lname))
                shutil.rmtree(ref, ignore_errors=True)
                os.makedirs(ref)
                rr = subprocess.run(["tar", "-xf", p, "-C", ref], capture_output=True)
                got = t.read_tree(ref)
                t.record(rr.returncode == 0 and got.get("sparse.bin") == content and got.get("plain.txt") == plain,
                         label + " (GNU tar agrees with the generator)", rr.stderr.decode(errors="replace")[-200:])
            r, typ, rows = t.listing(p)
            names = [(x["name"], x["usize"]) for x in rows]
            t.record(names == [("sparse.bin", real), ("plain.txt", len(plain))], label + " listing", str(names))
            exp = [("sparse.bin", content), ("plain.txt", plain)]
            t.check_extract(p, exp, label=label + " extract")
            pg = p + ".gz"
            with open(pg, "wb") as f:
                f.write(gzip.compress(arc, 6, mtime=0))
            t.check_extract(pg, exp, label=label + " .tar.gz extract")

    # GNU tar's own sparse archives (all formats it writes)
    if gnu:
        src = os.path.dirname(t.path("gnusrc", "x"))
        shutil.rmtree(src, ignore_errors=True)
        os.makedirs(src)
        real = 3 << 20
        content = bytearray(real)
        rnd = random.Random(9)
        for off in (0, 70000, 1 << 20, real - 5000):
            d = bytes(rnd.randrange(1, 256) for _ in range(4000))
            content[off:off + len(d)] = d
        with open(os.path.join(src, "sparse.bin"), "wb") as f:
            f.truncate(real)
            for off in (0, 70000, 1 << 20, real - 5000):
                f.seek(off)
                f.write(content[off:off + 4000])
        with open(os.path.join(src, "plain.txt"), "wb") as f:
            f.write(plain)
        for tag, opts in (("gnu", ["--format=gnu"]), ("oldgnu", ["--format=oldgnu"]),
                          ("pax00", ["--format=posix", "--sparse-version=0.0"]),
                          ("pax01", ["--format=posix", "--sparse-version=0.1"]),
                          ("pax10", ["--format=posix", "--sparse-version=1.0"])):
            p = t.path("gnutar", tag + ".tar")
            if os.path.exists(p):
                os.remove(p)
            t.sh(["tar"] + opts + ["-cSf", p, "sparse.bin", "plain.txt"], cwd=src)
            exp = {"sparse.bin": bytes(content), "plain.txt": plain}
            r, typ, rows = t.listing(p)
            names = sorted((x["name"], x["usize"]) for x in rows)
            t.record(names == sorted([("sparse.bin", real), ("plain.txt", len(plain))]),
                     "GNU tar %s sparse listing" % tag, str(names))
            t.check_extract(p, exp, label="GNU tar %s sparse" % tag)
            with open(p, "rb") as f:
                raw = f.read()
            with open(p + ".gz", "wb") as f:
                f.write(gzip.compress(raw, 1, mtime=0))
            t.check_extract(p + ".gz", exp, label="GNU tar %s sparse .tar.gz" % tag)

    # broken maps: the member fails, nothing crashes, the next member is intact
    def bad(name, member, want):
        arc = member + plain_member("plain.txt", plain) + END
        for ext, blob in (("tar", arc), ("tar.gz", gzip.compress(arc, 6, mtime=0))):
            p = t.path("bad", "%s.%s" % (name, ext))
            with open(p, "wb") as f:
                f.write(blob)
            t.check_hostile(p)
            r, rows, out = t.extract(p)
            st = {nm: s for s, isdir, size, nm in rows.values()}
            okp = st.get("plain.txt") == 0 and os.path.exists(os.path.join(out, "1.bin")) and \
                open(os.path.join(out, "1.bin"), "rb").read() == plain
            t.record(okp and st.get("sparse.bin") in want, "broken sparse %s.%s" % (name, ext),
                     "status %s" % st)

    c, s = sparse_model(1000, [(0, 100), (50, 100)])
    bad("S_overlap", gnu_old_sparse("sparse.bin", 1000, [(0, 100), (50, 100)], s), (E_FORMAT,))
    c, s = sparse_model(1000, [(950, 100)])
    bad("S_past_end", gnu_old_sparse("sparse.bin", 1000, [(950, 100)], s), (E_FORMAT,))
    c, s = sparse_model(1000, [(0, 100)])
    bad("S_size_mismatch", gnu_old_sparse("sparse.bin", 1000, [(0, 100)], s + bytes(700), size=800), (E_FORMAT,))
    bad("S_unsorted", gnu_old_sparse("sparse.bin", 1000, [(500, 10), (0, 10)], bytes(20)), (E_FORMAT,))
    bad("S_huge_offset", gnu_old_sparse("sparse.bin", 1000, [((1 << 33) - 1, 10)], bytes(10)), (E_FORMAT,))
    bad("pax01_odd", pax01_sparse("sparse.bin", 1000, [(0, 10)], bytes(10), map_text="0,10,20"), (E_FORMAT,))
    bad("pax01_junk", pax01_sparse("sparse.bin", 1000, [(0, 10)], bytes(10), map_text="0,1x"), (E_FORMAT,))
    bad("pax10_junk", pax10_sparse("sparse.bin", 1000, [(0, 10)], bytes(10), map_text=b"1\n0\nten\n"), (E_FORMAT,))
    bad("pax10_count", pax10_sparse("sparse.bin", 1000, [(0, 10)], bytes(10), map_text=b"99999999999\n"),
        (E_LIMIT,))
    bad("pax10_digits", pax10_sparse("sparse.bin", 1000, [(0, 10)], bytes(10), map_text=b"1" * 600),
        (E_FORMAT,))
    # map text longer than the member's data
    m = b"200\n" + b"".join(b"%d\n1\n" % (i * 3) for i in range(200))
    bad("pax10_past_data", pax_hdr([("GNU.sparse.major", 1), ("GNU.sparse.minor", 0), ("GNU.sparse.name", "sparse.bin"),
                                    ("GNU.sparse.realsize", 1000)]) + tar_hdr("GNUSparseFile.0/sparse.bin", 512) +
        pad512(m[:512]), (E_FORMAT,))
    bad("pax_version2", pax10_sparse("sparse.bin", 1000, [(0, 10)], bytes(10), major=2), (E_METHOD,))
    bad("pax00_lonely_numbytes", pax_hdr([("GNU.sparse.size", 100), ("GNU.sparse.numbytes", 10)]) +
        tar_hdr("sparse.bin", 10) + pad512(bytes(10)), (E_FORMAT,))
    # extension block missing: the archive ends right after the 'S' header
    p = t.path("bad", "S_ext_cut.tar")
    with open(p, "wb") as f:
        f.write(gnu_old_sparse("sparse.bin", 50000, [(i * 1000, 10) for i in range(30)], bytes(300), ext_cut=True))
    t.check_hostile(p)
    r, rows, out = t.extract(p)
    t.record(all(s != 0 for s, isdir, size, nm in rows.values()), "S_ext_cut not reported as complete", str(rows))

def mtime_tar(field=None, pax=None):
    out = b""
    if pax is not None:
        out += pax_hdr([("mtime", pax)], "a.txt")
    out += tar_hdr("a.txt", 3, mtime=field if field is not None else 1600000000) + pad512(b"abc")
    return out + END

def lzop_file(mtime_lo, mtime_hi, data=b"hello lzop\n"):
    """lzop 1.04 style file: stored-uncompressed block (csize == usize)"""
    magic = b"\x89LZO\x00\r\n\x1a\n"
    h = struct.pack(">HHHBBI", 0x1040, 0x2080, 0x0940, 1, 5, 0x03000001)   # flags: OS unix, adler32 data
    h += struct.pack(">III", 0o100644, mtime_lo, mtime_hi)
    name = b"x.txt"
    h += bytes([len(name)]) + name
    h += struct.pack(">I", zlib.adler32(h))
    blk = struct.pack(">III", len(data), len(data), zlib.adler32(data)) + data
    return magic + h + blk + struct.pack(">I", 0)

def case_mtime(t):
    drv = t.build_driver("tests/drivers/unixfmt.c")
    cases = [
        ("b256_huge", mtime_tar(field=b"\x80" + b"\x7f" * 11), "-"),            # reviewer's file
        ("b256_neg_huge", mtime_tar(field=b"\xff\x80" + bytes(10)), "-"),
        ("b256_min", mtime_tar(field=b"\xff" + bytes(11)), "-"),
        ("b256_neg100", mtime_tar(field=b256(-100, 12)), "-100"),               # GNU tar's pre-1970 times
        ("b256_2pow36", mtime_tar(field=b256(1 << 36, 12)), str(1 << 36)),
        ("b256_max_ok", mtime_tar(field=b256(910692730085, 12)), "910692730085"),
        ("b256_too_big", mtime_tar(field=b256(910692730086, 12)), "-"),
        ("pax_huge", mtime_tar(pax="99999999999999999999"), "-"),               # reviewer's file
        ("pax_int64_min", mtime_tar(pax="-9223372036854775808"), "-"),
        ("pax_int64_max", mtime_tar(pax="9223372036854775807"), "-"),
        ("pax_neg", mtime_tar(pax="-86400.5"), "-86400"),
        ("pax_frac", mtime_tar(pax="1700000000.123456789"), "1700000000"),
        ("pax_before_1601", mtime_tar(pax="-11644473601"), "-"),
    ]
    ub = ubsan_gzt(t)
    if ub is None:
        t.record(True, "ubsan gzt", "skipped (no clang, macOS, or HOST_CFLAGS already sanitized)")
    for name, blob, want in cases:
        p = t.path("mtime", name + ".tar")
        with open(p, "wb") as f:
            f.write(blob)
        r = subprocess.run([drv, "dump", p], capture_output=True, timeout=60)
        rows = [l.split("\t") for l in r.stdout.decode(errors="replace").splitlines() if l[:1].isdigit()]
        got = rows[0][3] if rows and len(rows[0]) > 3 else None
        t.record(r.returncode == 0 and got == want and rows[0][5] == "a.txt", "tar mtime " + name,
                 "got %s want %s" % (got, want))
        t.check_extract(p, {"a.txt": b"abc"}, label="tar mtime %s extract" % name)
        if ub:
            ubsan_clean(t, ub, "tar mtime " + name, ["l", p])
            pg = p + ".gz"
            with open(pg, "wb") as f:
                f.write(gzip.compress(blob, 6, mtime=0))
            ubsan_clean(t, ub, "tar.gz mtime " + name, ["l", pg])
    # lzop: the 64-bit time (low, high words) reaches gz_unix_to_filetime too
    for name, lo, hi, want in (("lzop_ok", 1600000000, 0, "1600000000"), ("lzop_high", 0xFFFFFFFF, 0x7FFFFFFF, "-"),
                               ("lzop_neg_high", 0, 0x80000000, "-"), ("lzop_neg", 0xFFFFFF9C, 0xFFFFFFFF, "-100")):
        p = t.path("mtime", name + ".lzo")
        with open(p, "wb") as f:
            f.write(lzop_file(lo, hi))
        r = subprocess.run([drv, "dump", p], capture_output=True, timeout=60)
        rows = [l.split("\t") for l in r.stdout.decode(errors="replace").splitlines() if l[:1].isdigit()]
        got = rows[0][3] if rows and len(rows[0]) > 3 else None
        t.record(r.returncode == 0 and got == want, "lzop mtime " + name, "got %s want %s %s" % (got, want, r.stdout[:200]))
        if ub:
            ubsan_clean(t, ub, "lzop mtime " + name, ["l", p])
    return ub

def case_zip_password(t):
    data = bytes(random.Random(7).choice(b"abcdefghij klmnop\n") for _ in range(200000))
    arc, crc = zipcrypto_zip(data, b"secret")
    p = t.path("zc", "zc.zip")
    with open(p, "wb") as f:
        f.write(arc)
    payload = arc[30 + len("data.txt"):]
    wrong = None
    for i in range(100000):
        cand = b"wrong%d" % i
        if passes_check(payload, cand, crc):
            wrong = cand.decode()
            break
    t.check_extract(p, {"data.txt": data}, pw="secret", label="ZipCrypto right password")
    failing = next(b"nope%d" % i for i in range(1000) if not passes_check(payload, b"nope%d" % i, crc))
    r, rows, out = t.extract(p, pw=failing.decode())
    t.record(rows.get(0, (None,))[0] == E_PASSWORD, "ZipCrypto wrong password (check byte fails)", str(rows))
    r, rows, out = t.extract(p, pw=wrong)
    t.record(wrong is not None and rows.get(0, (None,))[0] == E_PASSWORD,
             "ZipCrypto wrong password %r passing the check byte -> GZ_E_PASSWORD" % wrong, str(rows))
    # the same file through Info-ZIP, when present (the reviewer's setup)
    if t.tool("zip"):
        src = t.path("zc", "src", "data.txt")
        with open(src, "wb") as f:
            f.write(data)
        p2 = t.path("zc", "infozip.zip")
        if os.path.exists(p2):
            os.remove(p2)
        t.sh(["zip", "-q", "-P", "secret", p2, "data.txt"], cwd=os.path.dirname(src))
        with open(p2, "rb") as f:
            raw = f.read()
        nlen, xlen = struct.unpack("<HH", raw[26:30])
        crc2 = struct.unpack("<I", raw[14:18])[0]
        flags = struct.unpack("<H", raw[6:8])[0]
        check = (struct.unpack("<H", raw[10:12])[0] >> 8) if flags & 8 else crc2 >> 24
        pl = raw[30 + nlen + xlen:]
        w2 = None
        for i in range(100000):
            cand = b"wrong%d" % i
            if ZipCrypto(cand).decrypt(pl[:12])[11] == check:
                w2 = cand.decode()
                break
        r, rows, out = t.extract(p2, pw=w2)
        t.record(w2 is not None and rows.get(0, (None,))[0] == E_PASSWORD,
                 "Info-ZIP ZipCrypto wrong password %r passing the check byte" % w2, str(rows))

    # WinZip AES: tampered ciphertext that breaks the Deflate stream -> GZ_E_AUTH
    co = zlib.compressobj(6, zlib.DEFLATED, -15)
    comp = co.compress(data) + co.flush()
    def make_btype3(ct):
        b = bytearray(ct)
        b[0] ^= comp[0] ^ (comp[0] | 6)        # plaintext BTYPE bits -> 11 (invalid)
        return bytes(b)
    good = winzip_aes_zip(comp, len(data), b"secret")
    if good is None:
        t.record(True, "WinZip AES cases", "skipped: no AES module (pycryptodome / cryptography)")
        return
    p = t.path("aes", "aes_ok.zip")
    with open(p, "wb") as f:
        f.write(good)
    t.check_extract(p, {"data.txt": data}, pw="secret", label="AES-256 generator sanity")
    p = t.path("aes", "aes_tampered.zip")
    with open(p, "wb") as f:
        f.write(winzip_aes_zip(comp, len(data), b"secret", tamper=make_btype3))
    r, rows, out = t.extract(p, pw="secret")
    t.record(rows.get(0, (None,))[0] == E_AUTH, "AES tampered data that fails to decode -> GZ_E_AUTH", str(rows))
    # authentic (HMAC right) but the compressed data itself is broken: decoder error stays
    broken = bytes([comp[0] | 6]) + comp[1:]
    p = t.path("aes", "aes_authentic_corrupt.zip")
    with open(p, "wb") as f:
        f.write(winzip_aes_zip(broken, len(data), b"secret"))
    r, rows, out = t.extract(p, pw="secret")
    t.record(rows.get(0, (None,))[0] == E_DATA, "AES authentic but corrupt stream -> GZ_E_DATA", str(rows))
    # last ciphertext byte flipped: the Deflate end is cut (GZ_E_TRUNC before): GZ_E_AUTH
    def flip_last(ct):
        return ct[:-1] + bytes([ct[-1] ^ 1])
    p = t.path("aes", "aes_tampered_late.zip")
    with open(p, "wb") as f:
        f.write(winzip_aes_zip(comp, len(data), b"secret", tamper=flip_last))
    r, rows, out = t.extract(p, pw="secret")
    t.record(rows.get(0, (None,))[0] in (E_AUTH,), "AES tampered tail -> GZ_E_AUTH", str(rows))

def case_7z_noprops(t, ub):
    if not t.tool("7z"):
        t.record(True, "7z Copy cases", "skipped: no 7z")
        return
    src = t.write_tree(os.path.dirname(t.path("7zsrc", "x")), {
        "plain.txt": b"plain\n",
        "prog.bin": bytes(random.Random(3).randrange(256) for _ in range(30000)),
    })
    for tag, opts in (("copy", ["-m0=Copy"]), ("bcj_copy", ["-m0=BCJ", "-m1=Copy"]),
                      ("swap_copy", ["-m0=Swap4", "-m1=Copy"])):
        p = t.path("7z", tag + ".7z")
        if os.path.exists(p):
            os.remove(p)
        r = t.sh(["7z", "a", "-mx=0" if tag == "copy" else "-mx=5"] + opts + [p, "plain.txt", "prog.bin"],
                 cwd=src, check=False)
        if r.returncode:
            t.record(True, "7z " + tag, "skipped: 7z cannot write it")
            continue
        t.check_vs_7z(p, label="7z %s extract" % tag)
        if ub:
            ubsan_clean(t, ub, "7z %s list" % tag, ["l", p])
            ubsan_clean(t, ub, "7z %s extract" % tag, ["x", p, t.path("7z", "ubout_" + tag)])

def case_empty_names(t, ub):
    """entries whose names are all empty: listed, extracted, no NULL + offset"""
    cases = {
        "empty_header_name": tar_hdr("", 3) + pad512(b"abc") + END,
        "empty_pax_path": pax_hdr([("path", "")]) + tar_hdr("", 3) + pad512(b"abc") + END,
        "empty_sparse_name": pax10_sparse("", 10, [(0, 10)], b"0123456789") + END,
    }
    for name, blob in cases.items():
        p = t.path("empty", name + ".tar")
        with open(p, "wb") as f:
            f.write(blob)
        t.check_hostile(p)
        r, typ, rows = t.listing(p)
        t.record(r.returncode == 0 and len(rows) == 1, "empty name %s listed" % name, str(rows))
        if ub:
            ubsan_clean(t, ub, "empty name %s list" % name, ["l", p])
            ubsan_clean(t, ub, "empty name %s extract" % name, ["x", p, t.path("empty", "out_" + name)])

def run(t):
    case_zip_count(t)
    case_tar_sparse(t)
    ub = case_mtime(t)
    case_zip_password(t)
    case_7z_noprops(t, ub)
    case_empty_names(t, ub)
