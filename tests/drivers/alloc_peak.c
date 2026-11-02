/*
 * alloc_peak - largest single allocation while an archive is opened and listed
 *
 *   alloc_peak <file>      prints  "N <entries>", one "E <name>" line per entry
 *                          and "PEAK <bytes>" (largest gz_alloc request)
 *
 * Link with -Wl,--wrap=calloc (GNU ld): gz_alloc (src/posix/plat_posix.c) calls
 * calloc, so every zeroed allocation of the core goes through __wrap_calloc.
 * A forged header count must not drive a huge request even when the system
 * would hand out the (lazily committed) memory.
 */
#include "arc.h"
#include "cpu.h"
#include "crc32.h"
#include "plat_posix.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void *__real_calloc(size_t n, size_t m);
static size_t g_peak;

void *__wrap_calloc(size_t n, size_t m)
{
    size_t t = n * m;
    if (m && t / m != n) t = (size_t)-1;
    if (t > g_peak) g_peak = t;
    return __real_calloc(n, m);
}

int main(int argc, char **argv)
{
    if (argc < 2) return 2;
    gz_cpu_detect();
    gz_crc32_init();
    gz_inflate_init();
    gz_aes_init();
    gz_dispatch_init(-1);
    gz_src *s = gz_posix_open_src(argv[1]);
    if (!s) { perror(argv[1]); return 2; }
    gzch *wname = gz_posix_wide(argv[1]);
    gz_open_opts o;
    memset(&o, 0, sizeof o);
    o.file_name = wname;
    o.open_volume = gz_posix_open_volume;
    gz_ctx *c = gz_ctx_new();
    gz_archive *a;
    int r = gz_arc_open(&a, s, &o, c);
    if (r) {
        printf("OPEN_ERROR %d\nPEAK %zu\n", r, g_peak);
    } else {
        printf("N %u\n", a->n);
        static char nm[65536 * 3];
        for (u32 i = 0; i < a->n; i++) {
            size_t n = gz_wcslen(a->e[i].name);
            if (n * 3 + 1 > sizeof nm) n = (sizeof nm - 1) / 3;
            nm[gz_utf16_to_utf8(a->e[i].name, n, (u8 *)nm)] = 0;
            printf("E %s\n", nm);
        }
        printf("PEAK %zu\n", g_peak);
        gz_arc_close(a);
    }
    gz_ctx_free(c);
    gz_src_free(s);
    free(wname);
    return 0;
}
