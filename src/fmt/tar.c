/*
 * 고깃ZIP - TAR (ustar / GNU / pax / v7)
 *
 * The parser is a push-style state machine so the same code lists and
 * extracts plain .tar files (random access, data skipped with seeks) and
 * tarballs inside any compressed stream (see streamfmt.c).
 *
 * GNU sparse members are expanded on extraction: old GNU type 'S' (map in the
 * header at offset 386 plus extension blocks) and pax sparse 0.0 / 0.1
 * (GNU.sparse.offset/numbytes or GNU.sparse.map) and 1.0 (map text at the
 * start of the data), with the real name and size from GNU.sparse.name /
 * GNU.sparse.realsize / GNU.sparse.size. The stored data is the concatenation
 * of the map's chunks; holes are written as zeros.
 */
#include "tar.h"
#include "crc32.h"

#define TARF_SPARSE   1u                 /* gz_entry.flags: GNU sparse member      */
#define TAR_SP_MAX    (1u << 21)         /* sparse map entries per member (32 MiB) */
#define TAR_ZBUF      (128u << 10)       /* zeros written per call for holes       */
/* seconds since 1970 that a FILETIME (0 .. INT64_MAX) can hold */
#define TAR_T_MIN     (-11644473600LL)
#define TAR_T_MAX     910692730085LL

/* ---------------- header helpers ---------------- */

static u64 tar_num(const u8 *p, u32 n)
{
    if (p[0] & 0x80) {                       /* GNU base-256 */
        u64 v = p[0] & 0x3f;
        for (u32 i = 1; i < n; i++) v = (v << 8) | p[i];
        return v;
    }
    u64 v = 0;
    u32 i = 0;
    while (i < n && (p[i] == ' ' || p[i] == 0)) i++;
    for (; i < n && p[i] >= '0' && p[i] <= '7'; i++) v = (v << 3) | (u64)(p[i] - '0');
    return v;
}

/* Signed field (mtime): octal, or GNU base-256 two's complement whose first byte
 * carries the 0x80 marker and the sign in 0x40. 0 when it needs more than 63 bits. */
static int tar_snum(const u8 *p, u32 n, i64 *out)
{
    if (!(p[0] & 0x80)) { *out = (i64)tar_num(p, n); return 1; }    /* <= 12 octal digits: 36 bits */
    u8 inv = (p[0] & 0x40) ? 0xff : 0;          /* negative: read the one's complement */
    u64 v = (u8)(p[0] ^ inv) & 0x3f;
    for (u32 i = 1; i < n; i++) {
        if (v >> 55) return 0;
        v = v << 8 | (u8)(p[i] ^ inv);
    }
    *out = inv ? -(i64)v - 1 : (i64)v;
    return 1;
}

static int tar_cksum_ok(const u8 *h)
{
    u32 s = 0;
    i32 ss = 0;
    for (int i = 0; i < 512; i++) {
        u8 c = (i >= 148 && i < 156) ? ' ' : h[i];
        s += c;
        ss += (i8)c;
    }
    u64 want = tar_num(h + 148, 8);
    return want == s || (i64)want == ss;
}

static int is_zero_block(const u8 *h)
{
    for (int i = 0; i < 512; i++) if (h[i]) return 0;
    return 1;
}

int gz_tar_header_ok(const u8 *h)
{
    return !is_zero_block(h) && tar_cksum_ok(h);
}

static u32 cstr_len(const u8 *p, u32 max)
{
    u32 n = 0;
    while (n < max && p[n]) n++;
    return n;
}

static u8 *dup_bytes(const u8 *p, u32 n)
{
    u8 *d = (u8 *)gz_alloc(n + 1);
    if (d) __builtin_memcpy(d, p, n);
    return d;
}

/* ---------------- parser ---------------- */

struct gz_tar_parser {
    gz_archive *a;
    gz_ctx *c;
    u8 hdr[512];
    u32 hpos;
    int mode;                /* 0 header, 1 entry data, 2 meta data (L/K/x), 3 skip data,
                                4 old GNU sparse extension blocks */
    u64 left, pad;
    u64 pos;                 /* stream offset */
    u64 grp;                 /* offset of the first header of the current entry (L/K/x ...) */
    int grp_open;
    u8 *meta; u32 meta_len, meta_cap;
    int meta_kind;           /* 'L', 'K' or 'x' */
    u8 *lname; u32 lname_len;           /* GNU long name for the next header  */
    u8 *llink; u32 llink_len;           /* GNU long link name                 */
    u8 *pname; u32 pname_len;           /* pax path                           */
    u8 *plink; u32 plink_len;           /* pax linkpath                       */
    u64 pax_size; int has_pax_size;
    i64 pax_mtime; int has_pax_mtime;
    /* pending pax GNU.sparse.* keys for the next header */
    int sp_seen;
    u8 *sname; u32 sname_len;           /* GNU.sparse.name: the real name     */
    u64 sp_real; int has_sp_real;       /* GNU.sparse.size / realsize          */
    u64 sp_major, sp_minor; int has_sp_ver;
    u64 sp_poff; int has_sp_poff;       /* 0.0: offset waiting for its numbytes */
    /* sparse map of the current member: (offset, length) pairs */
    u64 *map; u32 nmap, cap_map;
    int map_err;                        /* first error met while building it  */
    int map_fin;                        /* old GNU: an empty slot ended the map */
    /* old GNU 'S': the data follows the extension blocks */
    u64 ext_size, ext_pad;
    int done;
    /* extraction */
    int extracting;
    const u8 *sel;
    gz_out *out;
    u32 next_idx;
    i32 cur;                 /* entry being written, -1 none */
    int cur_status;
    int sparse;              /* current entry: 0 plain, 1 sparse (map known), 2 pax 1.0 map being read */
    u64 sp_size;             /* expanded size */
    u32 sp_i;                /* map entry being filled */
    u64 sp_in, sp_out;       /* bytes of that entry written, output position */
    u64 m_num, m_used, m_want, m_off; u32 m_digits; int m_count;   /* pax 1.0 map text */
    u8 *zero;                /* TAR_ZBUF zero bytes for holes */
    /* single entry extraction (random access, see tar_extract) */
    u32 one;                 /* idx + 1 of the only entry to extract, 0 = use sel */
    int one_seen, one_st;
};

static void set_bytes(u8 **dst, u32 *dn, const u8 *p, u32 n)
{
    gz_free(*dst);
    *dst = dup_bytes(p, n);
    *dn = *dst ? n : 0;
}

static void clear_pending(gz_tar_parser *t)
{
    gz_free(t->lname); t->lname = 0; t->lname_len = 0;
    gz_free(t->llink); t->llink = 0; t->llink_len = 0;
    gz_free(t->pname); t->pname = 0; t->pname_len = 0;
    gz_free(t->plink); t->plink = 0; t->plink_len = 0;
    gz_free(t->sname); t->sname = 0; t->sname_len = 0;
    t->has_pax_size = t->has_pax_mtime = 0;
    t->sp_seen = t->has_sp_real = t->has_sp_ver = t->has_sp_poff = 0;
    t->grp_open = 0;
}

void gz_tar_parser_free(gz_tar_parser *t)
{
    if (!t) return;
    clear_pending(t);
    gz_free(t->meta);
    gz_free(t->map);
    gz_free(t->zero);
    gz_free(t);
}

gz_tar_parser *gz_tar_parser_new(gz_archive *a, const u8 *sel, gz_out *out, gz_ctx *c)
{
    gz_tar_parser *t = (gz_tar_parser *)gz_alloc(sizeof(gz_tar_parser));
    if (!t) return 0;
    t->a = a;
    t->c = c;
    t->extracting = out != 0;
    t->sel = sel;
    t->out = out;
    t->cur = -1;
    return t;
}

int gz_tar_done(const gz_tar_parser *t) { return t->done; }

/* decimal number, saturating (absurd values do not wrap) */
static u64 pax_uint(const u8 *v, u32 vn)
{
    u64 s = 0;
    for (u32 k = 0; k < vn && v[k] >= '0' && v[k] <= '9'; k++) {
        u32 d = (u32)(v[k] - '0');
        s = s > (~(u64)0 - d) / 10 ? ~(u64)0 : s * 10 + d;
    }
    return s;
}

/* ---------------- GNU sparse members ---------------- */

static void map_reset(gz_tar_parser *t)
{
    t->nmap = 0;
    t->map_err = GZ_OK;
    t->map_fin = 0;
}

static void map_add(gz_tar_parser *t, u64 off, u64 len)
{
    if (!t->extracting || t->map_err) return;      /* listing needs no map */
    if (t->nmap >= TAR_SP_MAX) { t->map_err = GZ_E_LIMIT; return; }
    if (t->nmap == t->cap_map) {
        u32 nc = t->cap_map ? t->cap_map * 2 : 64;
        u64 *m = (u64 *)gz_realloc(t->map, (size_t)nc * 2 * sizeof(u64));
        if (!m) { t->map_err = GZ_E_NOMEM; return; }
        t->map = m;
        t->cap_map = nc;
    }
    t->map[2 * t->nmap] = off;
    t->map[2 * t->nmap + 1] = len;
    t->nmap++;
}

/* chunks in order, inside the expanded size, holding exactly the stored bytes */
static int map_check(gz_tar_parser *t, u64 stored)
{
    if (t->map_err) return t->map_err;
    u64 end = 0, sum = 0;
    for (u32 i = 0; i < t->nmap; i++) {
        u64 o = t->map[2 * i], l = t->map[2 * i + 1];
        if (o < end || l > t->sp_size || o > t->sp_size - l) return GZ_E_FORMAT;
        end = o + l;
        sum += l;                       /* chunks do not overlap: sum <= sp_size */
    }
    return sum == stored ? GZ_OK : GZ_E_FORMAT;
}

/* old GNU sparse slot: offset[12] numbytes[12]; an empty numbytes ends the map */
static void old_slot(gz_tar_parser *t, const u8 *p)
{
    if (t->map_fin) return;
    if (!p[12]) { t->map_fin = 1; return; }
    map_add(t, tar_num(p, 12), tar_num(p + 12, 12));
}

static void map_fail(gz_tar_parser *t, int err)
{
    if (!t->map_err) t->map_err = err;
}

/* pax record GNU.sparse.<k>=<v> */
static void pax_sparse(gz_tar_parser *t, const u8 *k, u32 kn, const u8 *v, u32 vn)
{
#define KEY(s) (kn == sizeof(s) - 1 && !__builtin_memcmp(k, s, kn))
    if (!t->sp_seen) { t->sp_seen = 1; map_reset(t); }
    if (KEY("name")) set_bytes(&t->sname, &t->sname_len, v, vn);
    else if (KEY("size") || KEY("realsize")) { t->sp_real = pax_uint(v, vn); t->has_sp_real = 1; }
    else if (KEY("major")) { t->sp_major = pax_uint(v, vn); t->has_sp_ver = 1; }
    else if (KEY("minor")) { t->sp_minor = pax_uint(v, vn); t->has_sp_ver = 1; }
    else if (KEY("offset")) {                                    /* 0.0: offset, numbytes, ... */
        if (t->has_sp_poff) map_fail(t, GZ_E_FORMAT);
        t->sp_poff = pax_uint(v, vn);
        t->has_sp_poff = 1;
    } else if (KEY("numbytes")) {
        if (t->has_sp_poff) map_add(t, t->sp_poff, pax_uint(v, vn));
        else map_fail(t, GZ_E_FORMAT);
        t->has_sp_poff = 0;
    } else if (KEY("map")) {                                     /* 0.1: "off,len,off,len..." */
        u64 first = 0;
        u32 i = 0, n = 0;
        while (i < vn) {
            u32 j = i;
            while (j < vn && v[j] >= '0' && v[j] <= '9') j++;
            if (j == i || (j < vn && v[j] != ',')) { map_fail(t, GZ_E_FORMAT); return; }
            u64 num = pax_uint(v + i, j - i);
            if (n++ & 1) map_add(t, first, num);
            else first = num;
            i = j + 1;
        }
        if (n & 1) map_fail(t, GZ_E_FORMAT);
    }
#undef KEY
}

static int write_zeros(gz_tar_parser *t, u64 n)
{
    if (!t->zero && !(t->zero = (u8 *)gz_alloc(TAR_ZBUF))) return GZ_E_NOMEM;
    while (n) {
        u32 k = n < TAR_ZBUF ? (u32)n : TAR_ZBUF;
        int r = t->out->write(t->out, t->zero, k);
        if (r) return r;
        n -= k;
        if (gz_cancelled(t->c)) return GZ_E_CANCEL;
    }
    return GZ_OK;
}

/* stored bytes of a sparse member: place them at the map's offsets */
static int sp_write(gz_tar_parser *t, const u8 *p, size_t n)
{
    while (n) {
        if (t->sp_i >= t->nmap) return GZ_E_DATA;      /* map_check rules this out */
        u64 o = t->map[2 * t->sp_i], l = t->map[2 * t->sp_i + 1];
        int r;
        if (t->sp_out < o) {
            if ((r = write_zeros(t, o - t->sp_out))) return r;
            t->sp_out = o;
        }
        u64 k = l - t->sp_in;
        if (k > n) k = n;
        if (k && (r = t->out->write(t->out, p, (size_t)k))) return r;
        p += k; n -= (size_t)k;
        t->sp_in += k; t->sp_out += k;
        if (t->sp_in == l) { t->sp_i++; t->sp_in = 0; }
    }
    return GZ_OK;
}

/* pax 1.0: "<count>\n" then count "<offset>\n<numbytes>\n" pairs, padded with
 * zeros to a 512-byte block; the chunks follow. Takes map bytes from p.
 * rest = stored bytes left including these n. */
static int map10(gz_tar_parser *t, const u8 *p, size_t n, u64 rest, size_t *used)
{
    size_t i = 0;
    *used = 0;
    while (i < n) {
        if (t->m_count && !t->m_want) {                 /* map read: skip to the block end */
            u64 pad = (512 - (t->m_used & 511)) & 511;
            size_t k = n - i < pad ? n - i : (size_t)pad;
            i += k;
            t->m_used += k;
            if (t->m_used & 511) break;
            t->sparse = 1;
            *used = i;
            return map_check(t, rest - i);
        }
        u8 ch = p[i++];
        t->m_used++;
        if (ch >= '0' && ch <= '9') {
            if (++t->m_digits > 19) return GZ_E_FORMAT;
            t->m_num = t->m_num * 10 + (u64)(ch - '0');
            continue;
        }
        if (ch != '\n' || !t->m_digits) return GZ_E_FORMAT;
        u64 v = t->m_num;
        t->m_num = 0;
        t->m_digits = 0;
        if (!t->m_count) {
            if (v > TAR_SP_MAX) return GZ_E_LIMIT;
            t->m_count = 1;
            t->m_want = v * 2;
        } else if (--t->m_want & 1) {
            t->m_off = v;                               /* offset; numbytes follows */
        } else {
            map_add(t, t->m_off, v);
            if (t->map_err) return t->map_err;
        }
    }
    *used = i;
    return GZ_OK;
}

static int sp_feed(gz_tar_parser *t, const u8 *p, size_t n, u64 rest)
{
    if (t->sparse == 2) {
        size_t used;
        int r = map10(t, p, n, rest, &used);
        if (r || t->sparse == 2) return r;              /* error, or still inside the map */
        p += used;
        n -= used;
    }
    return sp_write(t, p, n);
}

/* all stored bytes seen: write the trailing hole */
static int sp_end(gz_tar_parser *t)
{
    if (t->sparse == 2) return GZ_E_FORMAT;             /* the map ran past the data */
    if (t->sp_in || (t->sp_i < t->nmap && t->map[2 * t->sp_i + 1])) return GZ_E_DATA;
    return t->sp_out < t->sp_size ? write_zeros(t, t->sp_size - t->sp_out) : GZ_OK;
}

/* ---------------- headers ---------------- */

static void tp_close(gz_tar_parser *t, u32 idx, int st)
{
    int cr = t->out->close(t->out, idx, st);
    t->cur = -1;
    if (t->one) { t->one_st = st ? st : cr; t->done = 1; }
}

static void pax_parse(gz_tar_parser *t)
{
    u32 i = 0, n = t->meta_len;
    const u8 *m = t->meta;
    while (i < n) {
        u32 len = 0, j = i;
        while (j < n && m[j] >= '0' && m[j] <= '9') {
            len = len * 10 + (u32)(m[j++] - '0');
            if (len > n) break;                         /* cannot overflow u32 */
        }
        /* the record "<len> <key>=<value>\n" must cover its own length field */
        if (j >= n || m[j] != ' ' || len <= j + 1 - i || len > n - i) break;
        const u8 *kv = m + j + 1;
        u32 kvn = i + len - (j + 1);
        if (kvn && kv[kvn - 1] == '\n') kvn--;
        u32 eq = 0;
        while (eq < kvn && kv[eq] != '=') eq++;
        if (eq < kvn) {
            const u8 *v = kv + eq + 1;
            u32 vn = kvn - eq - 1;
            if (eq == 4 && !__builtin_memcmp(kv, "path", 4)) set_bytes(&t->pname, &t->pname_len, v, vn);
            else if (eq == 8 && !__builtin_memcmp(kv, "linkpath", 8)) set_bytes(&t->plink, &t->plink_len, v, vn);
            else if (eq == 4 && !__builtin_memcmp(kv, "size", 4)) { t->pax_size = pax_uint(v, vn); t->has_pax_size = 1; }
            else if (eq == 5 && !__builtin_memcmp(kv, "mtime", 5)) {
                int neg = vn && v[0] == '-';
                u64 s = pax_uint(v + neg, vn - (u32)neg);
                if (s > (u64)1 << 62) s = (u64)1 << 62;     /* far out of range anyway: no overflow */
                t->pax_mtime = neg ? -(i64)s : (i64)s;
                t->has_pax_mtime = 1;
            } else if (eq > 11 && !__builtin_memcmp(kv, "GNU.sparse.", 11)) {
                pax_sparse(t, kv + 11, eq - 11, v, vn);
            }
        }
        i += len;
    }
}

/* The entry's data starts (after its header, or after old GNU extension blocks). */
static void data_start(gz_tar_parser *t, int is_file, int is_dir, u64 size, u64 pad)
{
    if (t->extracting && t->cur >= 0 && t->sparse) {
        if (t->sparse == 1 && t->cur_status == GZ_OK) t->cur_status = map_check(t, size);
        if (!size) {                                    /* nothing stored: all hole */
            int st = t->cur_status;
            if (!st) st = sp_end(t);
            tp_close(t, (u32)t->cur, st);
        }
    }
    if (is_file && size) { t->mode = 1; t->left = size; t->pad = pad; }
    else if (size && !is_dir) { t->mode = 3; t->left = size; t->pad = pad; }
    else { t->mode = 0; t->left = 0; t->pad = 0; }
}

/* Process a complete 512-byte header. */
static int tp_header(gz_tar_parser *t)
{
    const u8 *h = t->hdr;
    if (is_zero_block(h)) { t->done = 1; return GZ_OK; }
    if (!tar_cksum_ok(h)) return GZ_E_FORMAT;
    if (!t->grp_open) { t->grp = t->pos - 512; t->grp_open = 1; }   /* t->pos points past the header */

    u8 type = h[156];
    u64 size = tar_num(h + 124, 12);
    if (t->has_pax_size && type != 'x' && type != 'g') size = t->pax_size;
    u64 pad = (512 - (size & 511)) & 511;
    u64 data_pos = t->pos;

    if (type == 'L' || type == 'K' || type == 'x') {
        if (size > (16u << 20)) return GZ_E_FORMAT;
        t->meta_kind = type;
        t->meta_len = 0;
        if (t->meta_cap < size + 1) {
            gz_free(t->meta);
            t->meta = (u8 *)gz_alloc((size_t)size + 1);
            if (!t->meta) { t->meta_cap = 0; return GZ_E_NOMEM; }
            t->meta_cap = (u32)size + 1;
        }
        t->mode = 2; t->left = size; t->pad = pad;
        return GZ_OK;
    }
    if (type == 'g' || type == 'V' || type == 'M' || type == 'N') {
        t->mode = 3; t->left = size; t->pad = pad;
        return GZ_OK;
    }

    /* an actual entry */
    int is_file = (type == '0' || type == 0 || type == '7' || type == 'S');
    int is_dir = (type == '5');
    int is_link = type == '2' ? 1 : type == '1' ? 2 : 0;

    /* GNU sparse member: 1 = map known (old GNU 'S', pax 0.x), 2 = pax 1.0 (map in
     * the data), 3 = unsupported version */
    int sparse = 0, ext = 0;
    u64 sp_size = size;
    if (type == 'S') {
        sparse = 1;
        sp_size = tar_num(h + 483, 12);                 /* realsize */
        map_reset(t);
        for (u32 i = 0; i < 4; i++) old_slot(t, h + 386 + 24 * i);
        ext = h[482] != 0;                              /* isextended */
    } else if (is_file && t->sp_seen) {
        sparse = !t->has_sp_ver ? 1 : (t->sp_major == 1 && t->sp_minor == 0) ? 2 : t->sp_major == 0 ? 1 : 3;
        if (t->has_sp_real) sp_size = t->sp_real;
        else if (sparse == 2) sparse = 3;               /* 1.0 always gives the real size */
        if (t->has_sp_poff) map_fail(t, GZ_E_FORMAT);   /* offset without numbytes */
    }

    const u8 *nm;
    u32 nlen;
    u8 full[256 + 2];
    int ne = GZ_NE_LEGACY;
    if (sparse && t->sname) { nm = t->sname; nlen = t->sname_len; ne = GZ_NE_UTF8; }
    else if (t->pname) { nm = t->pname; nlen = t->pname_len; ne = GZ_NE_UTF8; }
    else if (t->lname) { nm = t->lname; nlen = cstr_len(t->lname, t->lname_len); }
    else {
        u32 n1 = cstr_len(h, 100);
        if (!__builtin_memcmp(h + 257, "ustar", 5) && h[345] && type != 'S') {
            u32 n0 = cstr_len(h + 345, 155);
            __builtin_memcpy(full, h + 345, n0);
            full[n0] = '/';
            __builtin_memcpy(full + n0 + 1, h, n1);
            nlen = n0 + 1 + n1;
        } else {
            __builtin_memcpy(full, h, n1);
            nlen = n1;
        }
        nm = full;
    }

    u32 mode = (u32)tar_num(h + 100, 8);
    i64 mt = t->pax_mtime;
    int mt_ok = t->has_pax_mtime || tar_snum(h + 136, 12, &mt);
    if (mt < TAR_T_MIN || mt > TAR_T_MAX) mt_ok = 0;       /* no FILETIME for it: leave unknown */

    if (is_file || is_dir || is_link) {
        if (!t->extracting) {
            gz_entry *e;
            int r = gz_arc_add_named(t->a, nm, nlen, ne, &e);
            if (r) return r;
            e->is_dir = (u8)(is_dir || (nlen && nm[nlen - 1] == '/'));
            e->is_link = (u8)is_link;
            e->usize = is_file ? sp_size : 0;
            e->csize = is_file ? size : 0;
            e->off = data_pos;
            if (sparse && !e->is_dir) {
                e->flags |= TARF_SPARSE;
                e->aux = t->grp;                        /* extraction parses the headers again */
            }
            if (mt_ok) {
                e->mtime = gz_unix_to_filetime(mt);
                e->mtime_kind = GZ_MT_FILETIME;
            }
            e->unix_mode = (mode & 07777) | (e->is_dir ? 0040000u : is_link == 1 ? 0120000u : 0100000u);
            if (mode && !(mode & 0200)) e->attr |= 1;
            if (e->is_dir) e->attr |= 0x10;
            if (is_link) {
                const u8 *lk = t->plink ? t->plink : t->llink;
                u32 ln = t->plink ? t->plink_len : t->llink ? cstr_len(t->llink, t->llink_len) : 0;
                if (!lk) { lk = h + 157; ln = cstr_len(h + 157, 100); }
                u32 lo;
                if (ln && !gz_arc_raw_append(t->a, lk, ln, &lo)) {
                    e = &t->a->e[t->a->n - 1];
                    e->link_off = lo;
                    e->link_len = ln;
                }
            }
        } else {
            u32 idx = t->next_idx;
            int want = idx < t->a->n && (t->one ? idx + 1 == t->one : t->sel[idx]);
            t->cur = -1;
            if (want) {
                /* links go through open() too, so the engine can report or create them */
                int r = t->out->open(t->out, idx);
                if (t->one) { t->one_seen = 1; t->one_st = r; }
                if (r == GZ_OK) {
                    if (is_file && (size || sparse)) {
                        t->cur = (i32)idx;
                        t->cur_status = sparse == 3 ? GZ_E_METHOD : GZ_OK;
                        t->sparse = sparse == 3 ? 1 : sparse;
                        t->sp_size = sp_size;
                        t->sp_i = 0;
                        t->sp_in = t->sp_out = 0;
                        t->m_num = t->m_used = t->m_want = t->m_off = 0;
                        t->m_digits = 0;
                        t->m_count = 0;
                        if (sparse == 2) map_reset(t);
                    } else {
                        tp_close(t, idx, GZ_OK);
                    }
                } else if (r == GZ_E_CANCEL) {
                    return GZ_E_CANCEL;
                } else if (t->one) {
                    t->done = 1;                        /* not opened: nothing to close */
                }   /* other errors were already reported by the engine */
            }
        }
        t->next_idx++;
    }
    clear_pending(t);

    if (ext) {                                          /* old GNU extension blocks come first */
        t->ext_size = size;
        t->ext_pad = pad;
        t->mode = 4; t->left = 0; t->pad = 0;
        return GZ_OK;
    }
    data_start(t, is_file, is_dir, size, pad);
    return GZ_OK;
}

/* old GNU sparse extension block: 21 slots, isextended at 504 */
static int tp_ext(gz_tar_parser *t)
{
    const u8 *h = t->hdr;
    for (u32 i = 0; i < 21; i++) old_slot(t, h + 24 * i);
    if (!h[504]) data_start(t, 1, 0, t->ext_size, t->ext_pad);
    return GZ_OK;
}

static void meta_done(gz_tar_parser *t)
{
    t->meta[t->meta_len] = 0;
    if (t->meta_kind == 'L') set_bytes(&t->lname, &t->lname_len, t->meta, cstr_len(t->meta, t->meta_len));
    else if (t->meta_kind == 'K') set_bytes(&t->llink, &t->llink_len, t->meta, cstr_len(t->meta, t->meta_len));
    else pax_parse(t);
}

int gz_tar_feed(void *parser, const u8 *p, size_t n)
{
    gz_tar_parser *t = (gz_tar_parser *)parser;
    while (n && !t->done) {
        if (t->mode == 0 || t->mode == 4) {
            u32 take = 512 - t->hpos;
            if (take > n) take = (u32)n;
            __builtin_memcpy(t->hdr + t->hpos, p, take);
            t->hpos += take; p += take; n -= take; t->pos += take;
            if (t->hpos == 512) {
                t->hpos = 0;
                int r = t->mode == 0 ? tp_header(t) : tp_ext(t);
                if (r) return r;
            }
            continue;
        }
        if (t->left) {
            size_t take = n < t->left ? n : (size_t)t->left;
            if (t->mode == 1 && t->extracting && t->cur >= 0 && t->cur_status == GZ_OK) {
                int r = t->sparse ? sp_feed(t, p, take, t->left) : t->out->write(t->out, p, take);
                if (r) {
                    t->cur_status = r;
                    if (r == GZ_E_CANCEL) return r;
                }
            } else if (t->mode == 2) {
                __builtin_memcpy(t->meta + t->meta_len, p, take);
                t->meta_len += (u32)take;
            }
            t->left -= take; p += take; n -= take; t->pos += take;
            if (!t->left) {
                if (t->mode == 1 && t->extracting && t->cur >= 0) {
                    int st = t->cur_status;
                    if (!st && t->sparse) st = sp_end(t);
                    tp_close(t, (u32)t->cur, st);
                    if (st == GZ_E_CANCEL) return st;
                }
                if (t->mode == 2) meta_done(t);
            }
            continue;
        }
        if (t->pad) {
            size_t take = n < t->pad ? n : (size_t)t->pad;
            t->pad -= take; p += take; n -= take; t->pos += take;
            continue;
        }
        t->mode = 0;
    }
    if (t->c && gz_cancelled(t->c)) return GZ_E_CANCEL;
    return GZ_OK;
}

int gz_tar_finish(gz_tar_parser *t, int status)
{
    if (t->extracting && t->cur >= 0) {
        tp_close(t, (u32)t->cur, status ? status : GZ_E_TRUNC);
        return status ? status : GZ_E_TRUNC;
    }
    return status;
}

/* ---------------- plain TAR (random access) ---------------- */

static int tar_probe(gz_src *s, const u8 *head, u32 n)
{
    (void)s;
    if (n < 512 || !gz_tar_header_ok(head)) return 0;
    return !__builtin_memcmp(head + 257, "ustar", 5) ? 95 : 70;
}

static int tar_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    (void)o;
    gz_tar_parser *t = gz_tar_parser_new(a, 0, 0, c);
    if (!t) return GZ_E_NOMEM;
    u64 off = 0;
    u8 *buf = (u8 *)gz_alloc(65536);
    if (!buf) { gz_tar_parser_free(t); return GZ_E_NOMEM; }
    int r = GZ_OK;
    while (!t->done && off + 512 <= s->size) {
        if (gz_cancelled(c)) { r = GZ_E_CANCEL; break; }
        if (t->mode == 0 || t->mode == 4) {             /* header or old GNU sparse extension */
            r = gz_src_read_exact(s, off, t->hdr, 512);
            if (r) break;
            off += 512;
            t->pos = off;
            r = t->mode == 0 ? tp_header(t) : tp_ext(t);
            if (r) break;
        } else if (t->mode == 1 || t->mode == 3) {     /* skip data */
            u64 rem = s->size - off;                    /* off <= size here */
            if (t->left > rem || t->pad > rem - t->left) { r = GZ_E_TRUNC; break; }
            off += t->left + t->pad;
            t->pos = off;
            t->left = t->pad = 0;
            t->mode = 0;
        } else {                                       /* read meta data */
            u32 n = t->left > 65536 ? 65536 : (u32)t->left;
            r = gz_src_read_exact(s, off, buf, n);
            if (r) break;
            off += n;
            r = gz_tar_feed(t, buf, n);
            if (r) break;
            if (!t->left) { off += t->pad; t->pad = 0; t->mode = 0; }
        }
    }
    gz_free(buf);
    gz_tar_parser_free(t);
    if (r == GZ_E_CANCEL || r == GZ_E_NOMEM) return r;
    if (r && a->n == 0) return r;
    return GZ_OK;      /* tolerate a damaged tail: entries found so far */
}

/* A sparse member: run the parser again from its first header (e->aux) and let
 * it expand the map. */
static int tar_extract_sparse(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    gz_tar_parser *t = gz_tar_parser_new(a, 0, out, c);
    u8 *buf = (u8 *)gz_alloc(65536);
    if (!t || !buf) { gz_tar_parser_free(t); gz_free(buf); return GZ_E_NOMEM; }
    t->one = idx + 1;
    t->next_idx = idx;
    u64 off = a->e[idx].aux;
    t->pos = off;
    int r = GZ_OK;
    while (!t->done && off < s->size) {
        u32 n = s->size - off < 65536 ? (u32)(s->size - off) : 65536;
        if ((r = gz_src_read_exact(s, off, buf, n))) break;
        off += n;
        if ((r = gz_tar_feed(t, buf, n))) break;
    }
    if (t->one_seen) {
        gz_tar_finish(t, r);                            /* closes an entry cut short */
        r = t->one_st;
    } else if (!r) {
        r = GZ_E_FORMAT;                                /* its header is not there any more */
    }
    gz_tar_parser_free(t);
    gz_free(buf);
    return r;
}

static int tar_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    if (a->e[idx].flags & TARF_SPARSE) return tar_extract_sparse(a, s, idx, out, c);
    return gz_extract_stored(a, s, idx, a->e[idx].off, out, c);
}

static void tar_method(const gz_archive *a, const gz_entry *e, char *buf, u32 cap)
{
    (void)a; (void)e;
    if (cap >= 6) __builtin_memcpy(buf, "Store", 6);
}

static gz_src *tar_view(gz_archive *a, gz_src *s, u32 idx)
{
    gz_entry *e = &a->e[idx];
    if (e->is_dir || e->is_link || (e->flags & TARF_SPARSE)) return 0;
    return gz_src_sub(s, e->off, e->usize);
}

GZ_FORMAT(gz_fmt_tar)
const gz_format gz_fmt_tar = {
    "TAR", "tar", 0, tar_probe, tar_open, 0, tar_extract, 0, 0, tar_method, tar_view, 0
};
