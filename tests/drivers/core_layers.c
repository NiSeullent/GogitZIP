/*
 * Archives nested in archives, as the GUIs open them (gz_handle_open_child): every level
 * of a tar-in-tar chain is opened in turn and its first member ('P' x 1000) is read
 * through the layered views; the innermost "secret.txt" must hold the payload.
 * Levels within GZ_MAX_LAYERS are read in place (views); deeper ones must not be read
 * from the wrong place: gz_arc_open_child says GZ_E_METHOD and the engine falls back to
 * a temporary copy.
 *   usage: core_layers <outer.tar> <levels>      prints "ok ..." / "FAIL ..." lines
 */
#include "engine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails;
#define CHECK(cond, ...) do { int c_ = (cond); printf(c_ ? "ok " : "FAIL "); printf(__VA_ARGS__); \
                              printf("\n"); fflush(stdout); if (!c_) fails++; } while (0)

typedef struct { gz_out o; u8 buf[2048]; size_t n; } mem_out;
static int m_open(gz_out *o, u32 i) { (void)o; (void)i; return GZ_OK; }
static int m_write(gz_out *o, const u8 *p, size_t n)
{
    mem_out *m = (mem_out *)o;
    for (size_t i = 0; i < n && m->n < sizeof m->buf; i++) m->buf[m->n++] = p[i];
    return GZ_OK;
}
static int m_close(gz_out *o, u32 i, int st) { (void)o; (void)i; return st; }

static int name_is(const gzch *w, const char *s)
{
    for (; *s; s++, w++) if (*w != (gzch)(u8)*s) return 0;
    return *w == 0;
}

static int name_starts(const gzch *w, const char *s)
{
    for (; *s; s++, w++) if (*w != (gzch)(u8)*s) return 0;
    return 1;
}

/* entry idx of h read through gz_arc_extract (layered views for nested handles) */
static int read_entry(gz_handle *h, u32 idx, mem_out *m)
{
    gz_ctx *c = gz_ctx_new();
    m->o.open = m_open;
    m->o.write = m_write;
    m->o.close = m_close;
    m->n = 0;
    int r = c ? gz_arc_extract(h->arc, h->src, idx, &m->o, c) : GZ_E_NOMEM;
    gz_ctx_free(c);
    return r;
}

int main(int argc, char **argv)
{
    if (argc < 3) { fprintf(stderr, "usage: core_layers <outer.tar> <levels>\n"); return 2; }
    int levels = atoi(argv[2]);
    gz_engine_init(-1);
    gzch *path = gz_os_path_wide(argv[1]);
    gz_handle *hs[256];
    int nh = 0;
    int r = gz_handle_open(&hs[nh], path, 0, 0);
    gz_free(path);
    if (r) { CHECK(0, "open %s: %d", argv[1], r); return 1; }
    nh++;
    int views = 0, copies = 0, pad_bad = -1, refused = -1, done = 0;
    for (int lv = 0; lv < 250; lv++) {
        gz_handle *h = hs[nh - 1];
        gz_archive *a = h->arc;
        int pad = -1, next = -1, secret = -1;
        for (u32 i = 0; i < a->n; i++) {
            if (name_starts(a->e[i].name, "pad")) pad = (int)i;
            else if (name_is(a->e[i].name, "secret.txt")) secret = (int)i;
            else next = (int)i;
        }
        mem_out m;
        if (pad < 0 || read_entry(h, (u32)pad, &m) || m.n != 1000 || m.buf[0] != 'P' || m.buf[999] != 'P') {
            if (pad_bad < 0) pad_bad = lv;
        }
        if (secret >= 0) {
            int er = read_entry(h, (u32)secret, &m);
            CHECK(!er && m.n == 17 && !memcmp(m.buf, "INNER-PAYLOAD-OK\n", 17),
                  "level %d: secret.txt read in place (status %d, %u bytes)", lv, er, (unsigned)m.n);
            done = lv;
            break;
        }
        if (next < 0) { CHECK(0, "level %d: no member to open", lv); break; }
        /* the core itself: a view chain longer than GZ_MAX_LAYERS is refused, never misread */
        gz_archive *child = 0;
        gz_ctx *c = gz_ctx_new();
        int cr = gz_arc_open_child(&child, a, h->src, (u32)next, 0, c);
        gz_ctx_free(c);
        if (child) gz_arc_close(child);
        if (cr && refused < 0) refused = lv;
        r = gz_handle_open_child(&hs[nh], h, (u32)next, 0, 0);
        if (r) { CHECK(0, "level %d: open child: %d", lv, r); break; }
        if (hs[nh]->temp) copies++; else views++;
        nh++;
    }
    int deep = levels - 1;
    CHECK(done == deep, "reached the innermost level %d (wanted %d)", done, deep);
    CHECK(pad_bad < 0, "first member of every level read correctly (first bad level %d)", pad_bad);
    int want_refused = deep > GZ_MAX_LAYERS ? GZ_MAX_LAYERS : -1;
    CHECK(refused == want_refused, "gz_arc_open_child refused from level %d (wanted %d)", refused, want_refused);
    /* a temporary copy starts a new chain of views */
    int want_copies = deep / (GZ_MAX_LAYERS + 1);
    CHECK(copies == want_copies && views == deep - want_copies,
          "%d levels through views, %d through temporary copies (wanted %d)", views, copies, want_copies);
    while (nh) gz_handle_close(hs[--nh]);
    return fails ? 1 : 0;
}
