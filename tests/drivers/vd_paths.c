/*
 * vd_paths - which files a disk image makes the reader open (VMDK extents, VHD parents)
 *
 *   vd_paths open  <image>                    open the image (no descent into the disk)
 *   vd_paths child <archive> <idx> <name>     open entry idx of <archive> as a nested image
 *                                             (gz_arc_open_child, file_name = <name>)
 *
 * Every path the reader asks open_volume for is printed as "VOL <utf-8 path>" before it is
 * opened with gz_posix_open_volume; then "OPEN <rc>" and, when it opened, one
 * "ENTRY <n> <usize> <name>" line per entry. Exit code 0 unless the arguments are wrong.
 */
#include "arc.h"
#include "cpu.h"
#include "crc32.h"
#include "plat_posix.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int rec_volume(void *user, const gzch *name, gz_src **out)
{
    char *p = gz_posix_utf8(name);
    printf("VOL %s\n", p ? p : "?");
    fflush(stdout);
    free(p);
    return gz_posix_open_volume(user, name, out);
}

static void list(gz_archive *a)
{
    char nm[8192];
    for (u32 i = 0; i < a->n; i++) {
        size_t n = gz_wcslen(a->e[i].name);
        if (n * 3 + 1 > sizeof nm) n = (sizeof nm - 1) / 3;
        nm[gz_utf16_to_utf8(a->e[i].name, n, (u8 *)nm)] = 0;
        printf("ENTRY %u %llu %s\n", i, (unsigned long long)a->e[i].usize, nm);
    }
}

int main(int argc, char **argv)
{
    if (argc < 3) return 2;
    gz_cpu_detect();
    gz_crc32_init();
    gz_inflate_init();
    gz_aes_init();
    gz_dispatch_init(-1);
    gz_src *src = gz_posix_open_src(argv[2]);
    if (!src) { perror(argv[2]); return 2; }
    gz_ctx *c = gz_ctx_new();
    gzch *wname = gz_posix_wide(argv[2]);
    gz_open_opts oo;
    memset(&oo, 0, sizeof oo);
    oo.file_name = wname;
    oo.open_volume = rec_volume;
    oo.flags = GZ_OPEN_NO_DESCEND;
    gz_archive *a = 0;
    int r = gz_arc_open(&a, src, &oo, c);
    if (!strcmp(argv[1], "child")) {
        if (argc < 5) return 2;
        if (r) { printf("PARENT %d\n", r); return 0; }
        gz_archive *ch = 0;
        gzch *cname = gz_posix_wide(argv[4]);
        oo.file_name = cname;                 /* what the engine passes: the entry's name */
        r = gz_arc_open_child(&ch, a, src, (u32)atoi(argv[3]), &oo, c);
        printf("OPEN %d\n", r);
        if (!r) { list(ch); gz_arc_close(ch); }
        free(cname);
    } else {
        printf("OPEN %d\n", r);
        if (!r) list(a);
    }
    if (a) gz_arc_close(a);
    gz_src_free(src);
    gz_ctx_free(c);
    free(wname);
    return 0;
}
