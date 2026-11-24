/*
 * 고깃ZIP - shared plumbing for virtual disk images (see vdisk.h)
 */
#include "vdisk.h"

/* ---------------- view ---------------- */

static void fill_pattern(u8 *p, u32 n, u32 fill, u64 off)
{
    u8 pat[64];
    for (u32 i = 0; i < 64; i++) pat[i] = (u8)(fill >> (8 * ((off + i) & 3)));
    while (n >= 64) { __builtin_memcpy(p, pat, 64); p += 64; n -= 64; }
    if (n) __builtin_memcpy(p, pat, n);
}

static int vd_read(gz_src *s, u64 off, void *buf, u32 n, u32 *got)
{
    gz_vd_view *v = (gz_vd_view *)s;
    *got = 0;
    if (off >= s->size) return GZ_OK;
    if (n > s->size - off) n = (u32)(s->size - off);
    u8 *p = (u8 *)buf;
    u32 left = n;
    /* pending raw run, flushed when the next raw extent is not contiguous */
    gz_src *rs = 0;
    u64 rpos = 0;
    u8 *rdst = 0;
    u32 rlen = 0;
    int r;
    while (left) {
        gz_vd_ext x;
        x.kind = GZ_VD_ZERO; x.fill = 0; x.len = 0; x.src = 0; x.pos = 0; x.mem = 0;
        r = v->map(v, off, &x);
        if (r) return r;
        if (!x.len) return GZ_E_FORMAT;              /* a map must make progress */
        u32 take = x.len < left ? (u32)x.len : left;
        if (x.kind == GZ_VD_RAW) {
            gz_src *src = x.src ? x.src : v->file;
            if (x.pos > src->size || take > src->size - x.pos) return GZ_E_TRUNC;
            if (rlen && src == rs && x.pos == rpos + rlen && p == rdst + rlen) {
                rlen += take;
            } else {
                if (rlen && (r = gz_src_read_exact(rs, rpos, rdst, rlen))) return r;
                rs = src; rpos = x.pos; rdst = p; rlen = take;
            }
        } else if (x.kind == GZ_VD_ZERO || (x.kind == GZ_VD_PARENT && !v->parent)) {
            __builtin_memset(p, 0, take);
        } else if (x.kind == GZ_VD_MEM) {
            __builtin_memcpy(p, x.mem, take);
        } else if (x.kind == GZ_VD_FILL) {
            fill_pattern(p, take, x.fill, off);
        } else if (x.kind == GZ_VD_PARENT) {
            if (off >= v->parent->size) __builtin_memset(p, 0, take);
            else {
                u32 in = v->parent->size - off < take ? (u32)(v->parent->size - off) : take;
                if ((r = gz_src_read_exact(v->parent, off, p, in))) return r;
                if (in < take) __builtin_memset(p + in, 0, take - in);
            }
        } else {
            return GZ_E_FORMAT;
        }
        p += take;
        off += take;
        left -= take;
    }
    if (rlen && (r = gz_src_read_exact(rs, rpos, rdst, rlen))) return r;
    *got = n;
    return GZ_OK;
}

static void vd_free(gz_src *s)
{
    gz_vd_view *v = (gz_vd_view *)s;
    if (v->fini) v->fini(v);
    if (v->z) gz_inflater_free(v->z);
    gz_src_free(v->parent);
    gz_free(v);
}

gz_vd_view *gz_vd_view_new(size_t sz, gz_src *file, const void *img, u64 size, gz_vd_map_fn map)
{
    if (sz < sizeof(gz_vd_view)) sz = sizeof(gz_vd_view);
    gz_vd_view *v = (gz_vd_view *)gz_alloc(sz);
    if (!v) return 0;
    v->s.read_at = vd_read;
    v->s.size = size;
    v->s.free = vd_free;
    v->file = file;
    v->img = img;
    v->map = map;
    return v;
}

/* ---------------- deflate helper ---------------- */

typedef struct { u8 *dst; u32 cap, n; } buf_sink;

static int buf_write(void *user, const u8 *p, size_t n)
{
    buf_sink *k = (buf_sink *)user;
    if (n > (size_t)(k->cap - k->n)) return GZ_E_DATA;
    __builtin_memcpy(k->dst + k->n, p, n);
    k->n += (u32)n;
    return GZ_OK;
}

int gz_vd_inflate(gz_vd_view *v, gz_src *src, u64 pos, u64 len, int zlib, u8 *dst, u32 cap, u32 *outn)
{
    *outn = 0;
    if (pos > src->size || len > src->size - pos) return GZ_E_TRUNC;
    if (zlib) {
        u8 h[2];
        if (len < 2) return GZ_E_DATA;
        int r = gz_src_read_exact(src, pos, h, 2);
        if (r) return r;
        /* CM 8, window <= 32K, check bits, no preset dictionary */
        if ((h[0] & 15) != 8 || (h[0] >> 4) > 7 || ((h[0] << 8) | h[1]) % 31 || (h[1] & 0x20))
            return GZ_E_DATA;
        pos += 2;
        len -= 2;
    }
    if (!v->z && !(v->z = gz_inflater_new())) return GZ_E_NOMEM;
    buf_sink k = { dst, cap, 0 };
    gz_pipe pp = { { src, pos, pos + len, 0 }, buf_write, &k };
    gz_stream_io io = { gz_range_read, gz_pipe_write, &pp };
    int r = gz_inflate_run(v->z, &io, 0);
    *outn = k.n;
    return r;
}

/* ---------------- entries ---------------- */

static int is_sep(gzch c) { return c == '/' || c == '\\'; }

int gz_vd_add_disk(gz_archive *a, const gz_open_opts *o, u64 vsize, u64 csize, gz_entry **pe)
{
    gzch nm[208];
    u32 n = 0;
    const gzch *fn = o ? o->file_name : 0;
    if (fn) {
        const gzch *b = fn;
        for (const gzch *p = fn; *p; p++) if (is_sep(*p)) b = p + 1;
        u32 len = 0, dot = 0;
        while (b[len] && len < 4096) { if (b[len] == '.' && len) dot = len; len++; }
        if (dot) len = dot;
        if (len > 192) len = 192;
        for (; n < len; n++) nm[n] = b[n];
    }
    if (!n) { nm[0] = 'd'; nm[1] = 'i'; nm[2] = 's'; nm[3] = 'k'; n = 4; }
    int has_img = n > 4 && nm[n - 4] == '.' && (nm[n - 3] | 32) == 'i' && (nm[n - 2] | 32) == 'm' &&
                  (nm[n - 1] | 32) == 'g';
    if (!has_img) { nm[n++] = '.'; nm[n++] = 'i'; nm[n++] = 'm'; nm[n++] = 'g'; }
    gz_entry *e;
    int r = gz_arc_add_named(a, nm, n * 2, GZ_NE_UTF16LE, &e);   /* gzch is UTF-16LE in memory */
    if (r) return r;
    e->usize = vsize;
    e->csize = csize;
    e->attr = 0x20;
    if (pe) *pe = e;
    return GZ_OK;
}

int gz_vd_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    gz_entry *e = &a->e[idx];
    gz_src *v = a->fmt->view ? a->fmt->view(a, s, idx) : 0;
    if (!v) return GZ_E_NOMEM;
    int r = out->open(out, idx);
    if (r) { gz_src_free(v); return r; }
    u64 n = e->usize == GZ_SIZE_UNKNOWN ? v->size : e->usize;
    int st = gz_copy_range(v, 0, n, out, c, 0);
    gz_src_free(v);
    int cr = out->close(out, idx, st);
    return st ? st : cr;
}

/* ---------------- referenced files ---------------- */

/* Names inside images are hostile: a descriptor or a parent locator may name any file the
 * user can read ("/etc/passwd", "..\..\secret") or, on Windows, a UNC path that makes the
 * machine authenticate to a remote server as soon as the image is listed. Referenced files
 * are therefore only opened inside the folder of the image the user opened (its subfolders
 * included): names are resolved lexically against the folder of the image that holds the
 * reference, and anything absolute or climbing out of that tree is reduced to its base name
 * next to the referencing image. */

/* CON, PRN, AUX, NUL, COM0-9, LPT0-9 (also with superscript digits), CONIN$, CONOUT$,
 * CLOCK$, with any extension: Windows opens the device whatever the folder. */
static int is_dos_device(const gzch *c, u32 n)
{
    u32 k = 0;
    while (k < n && c[k] != '.') k++;
    while (k && c[k - 1] == ' ') k--;
    if (k < 3 || k > 7) return 0;
    char w[8];
    for (u32 i = 0; i < k; i++) {
        u32 ch = c[i];
        if (ch == 0xB9) ch = '1';
        else if (ch == 0xB2 || ch == 0xB3) ch = '2' + (ch - 0xB2);
        if (ch >= 'a' && ch <= 'z') ch -= 32;
        if (ch >= 0x80) return 0;
        w[i] = (char)ch;
    }
    if (k == 3)
        return !__builtin_memcmp(w, "CON", 3) || !__builtin_memcmp(w, "PRN", 3) || !__builtin_memcmp(w, "AUX", 3) ||
               !__builtin_memcmp(w, "NUL", 3);
    if (k == 4)
        return (!__builtin_memcmp(w, "COM", 3) || !__builtin_memcmp(w, "LPT", 3)) && w[3] >= '0' && w[3] <= '9';
    if (k == 6) return !__builtin_memcmp(w, "CONIN$", 6) || !__builtin_memcmp(w, "CLOCK$", 6);
    return k == 7 && !__builtin_memcmp(w, "CONOUT$", 7);
}

/* Append the components of name (len units) to the path p[root..*pos) (components joined by
 * sep, no leading or trailing separator), resolving "." and "..". 0 when name is absolute
 * (a separator first also covers UNC and \\?\ or \\.\ device paths), when ".." climbs above
 * root, or when a component holds ':' (drive letters, drive-relative paths, NTFS streams) or
 * NUL, is made only of dots and spaces (Windows trims those) or names a DOS device. */
static int join_inside(gzch *p, u32 root, u32 *pos, const gzch *name, u32 len, gzch sep)
{
    if (len && is_sep(name[0])) return 0;
    for (u32 i = 0; i < len; i++) {
        u32 s = i, dots = 0, spaces = 0;
        for (; i < len && !is_sep(name[i]); i++) {
            if (name[i] == ':' || !name[i]) return 0;
            dots += name[i] == '.';
            spaces += name[i] == ' ';
        }
        u32 n = i - s;
        if (!n || (n == 1 && dots == 1)) continue;                 /* "a//b", "./a" */
        if (n == 2 && dots == 2) {                                 /* drop the last component */
            if (*pos == root) return 0;
            while (*pos > root && p[*pos - 1] != sep) (*pos)--;
            if (*pos > root) (*pos)--;
            continue;
        }
        if (dots + spaces == n || is_dos_device(name + s, n)) return 0;
        if (*pos > root) p[(*pos)++] = sep;
        for (u32 k = s; k < i; k++) p[(*pos)++] = name[k];
    }
    return 1;
}

/* The last component of name is a file name (not empty, "." or ".."). */
static int last_regular(const gzch *name, u32 len)
{
    u32 s = len;
    while (s && !is_sep(name[s - 1])) s--;
    u32 n = len - s;
    return n && !(n == 1 && name[s] == '.') && !(n == 2 && name[s] == '.' && name[s + 1] == '.');
}

int gz_vd_open_file16_at(gz_archive *a, const gz_open_opts *o, const gzch *base, const gzch *name, u32 len,
                         gz_src **out, gzch **opened)
{
    *out = 0;
    if (opened) *opened = 0;
    /* no image path, or an image inside another archive: no folder to resolve names in */
    const gzch *top = o ? o->file_name : 0;
    if (!o || !o->open_volume || !top || !top[0] || a->parent || !len || len > 32768) return GZ_E_VOLUME;
    if (a->nvols >= GZ_VD_MAX_FILES) return GZ_E_LIMIT;
    gz_src **nv = (gz_src **)gz_realloc(a->vols, ((size_t)a->nvols + 1) * sizeof(gz_src *));
    if (!nv) return GZ_E_NOMEM;
    a->vols = nv;
    /* root = folder of the opened image; separators of the result follow its style */
    u32 root = 0, tn = 0;
    int fwd = 0, back = 0;
    for (; top[tn] && tn < 32768; tn++) {
        if (is_sep(top[tn])) root = tn + 1;
        fwd |= top[tn] == '/';
        back |= top[tn] == '\\';
    }
    gzch sep = back && !fwd ? '\\' : '/';
    /* folder of the referencing image relative to root (base: a path returned in *opened) */
    const gzch *rel = 0;
    u32 rn = 0;
    if (base) {
        u32 bn = 0;
        while (base[bn] && bn < 65536) bn++;
        for (u32 i = 0; i < root; i++) if (bn <= root || base[i] != top[i]) return GZ_E_VOLUME;
        rel = base + root;
        for (u32 i = root; i < bn; i++) if (is_sep(base[i])) rn = i + 1 - root;
    }
    gzch *p = (gzch *)gz_alloc(((size_t)root + rn + len + 2) * sizeof(gzch));
    if (!p) return GZ_E_NOMEM;
    for (u32 i = 0; i < root; i++) p[i] = top[i];
    u32 pos = root;
    join_inside(p, root, &pos, rel, rn, sep);              /* built by us: always inside */
    u32 at = pos;
    if (!last_regular(name, len) || !join_inside(p, root, &pos, name, len, sep)) {
        /* absolute, UNC, drive or escaping name: only its base name next to the image */
        u32 b = 0;
        for (u32 i = 0; i < len; i++) if (is_sep(name[i]) || name[i] == ':') b = i + 1;
        pos = at;
        if (!last_regular(name + b, len - b) || !join_inside(p, root, &pos, name + b, len - b, sep)) {
            gz_free(p);
            return GZ_E_VOLUME;
        }
    }
    p[pos] = 0;
    gz_src *s = 0;
    int r = o->open_volume(o->user, p, &s);
    if (!r && !s) r = GZ_E_VOLUME;
    if (!r && opened) *opened = p;
    else gz_free(p);
    if (r) return (r == GZ_E_CANCEL || r == GZ_E_NOMEM) ? r : GZ_E_VOLUME;
    a->vols[a->nvols++] = s;
    *out = s;
    return GZ_OK;
}

int gz_vd_open_file16(gz_archive *a, const gz_open_opts *o, const gzch *name, u32 len, gz_src **out)
{
    return gz_vd_open_file16_at(a, o, 0, name, len, out, 0);
}

int gz_vd_open_file(gz_archive *a, const gz_open_opts *o, const u8 *name, u32 len, gz_src **out)
{
    *out = 0;
    if (!len || len > 4096) return GZ_E_VOLUME;
    gzch *w = (gzch *)gz_alloc(((size_t)len + 1) * sizeof(gzch));
    if (!w) return GZ_E_NOMEM;
    u32 n;
    if (gz_utf8_valid(name, len)) n = (u32)gz_utf8_to_utf16(name, len, w);
    else for (n = 0; n < len; n++) w[n] = name[n];
    int r = gz_vd_open_file16(a, o, w, n, out);
    gz_free(w);
    return r;
}

void gz_vd_note(gz_archive *a, const char *text, u32 n)
{
    u8 *p = (u8 *)gz_alloc(n + 1);
    if (!p) return;
    __builtin_memcpy(p, text, n);
    gz_free(a->comment_raw);
    a->comment_raw = p;
    a->comment_len = n;
    a->comment_enc = GZ_NE_UTF8;
}

void gz_vd_method_str(char *buf, u32 cap, const char *s)
{
    u32 i = 0;
    if (!cap) return;
    for (; s[i] && i + 1 < cap; i++) buf[i] = s[i];
    buf[i] = 0;
}
