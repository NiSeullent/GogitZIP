/*
 * LD_PRELOAD shim (Linux, glibc) that makes the file system behave like others the
 * engine meets, for tests/cases/regress_core_engine.py:
 *   GZ_SHIM_CI=1      below any path component named "cisim" every ASCII letter is
 *                     lower-cased before the real call, so "A.txt" and "a.txt" name the
 *                     same file (a case-insensitive file system like APFS, HFS+, NTFS)
 *   GZ_SHIM_NOLINK=1  link()/linkat() fail with EPERM (FAT/exFAT: no hard links)
 *   cc -shared -fPIC -O1 -o fs_shim.so fs_shim.c -ldl
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>

static const char *fold(const char *p, char *buf)
{
    static int on = -1;
    if (on < 0) on = getenv("GZ_SHIM_CI") != 0;
    if (!on || !p) return p;
    const char *m = strstr(p, "/cisim/");
    if (!m) return p;
    size_t n = strlen(p);
    if (n >= 4096) return p;
    memcpy(buf, p, n + 1);
    for (size_t i = (size_t)(m - p) + 7; i < n; i++)
        if (buf[i] >= 'A' && buf[i] <= 'Z') buf[i] += 32;
    return buf;
}

static int nolink(void)
{
    static int on = -1;
    if (on < 0) on = getenv("GZ_SHIM_NOLINK") != 0;
    return on;
}

#define REAL(name, ret, ...) static ret (*r_##name)(__VA_ARGS__); \
    if (!r_##name) r_##name = (ret (*)(__VA_ARGS__))dlsym(RTLD_NEXT, #name)

int open(const char *p, int fl, ...)
{
    REAL(open, int, const char *, int, ...);
    mode_t m = 0;
    if (fl & (O_CREAT | O_TMPFILE)) { va_list ap; va_start(ap, fl); m = (mode_t)va_arg(ap, int); va_end(ap); }
    char b[4096];
    return r_open(fold(p, b), fl, m);
}
int open64(const char *p, int fl, ...)
{
    REAL(open64, int, const char *, int, ...);
    mode_t m = 0;
    if (fl & (O_CREAT | O_TMPFILE)) { va_list ap; va_start(ap, fl); m = (mode_t)va_arg(ap, int); va_end(ap); }
    char b[4096];
    return r_open64(fold(p, b), fl, m);
}
int stat(const char *p, struct stat *s) { REAL(stat, int, const char *, struct stat *); char b[4096]; return r_stat(fold(p, b), s); }
int lstat(const char *p, struct stat *s) { REAL(lstat, int, const char *, struct stat *); char b[4096]; return r_lstat(fold(p, b), s); }
int mkdir(const char *p, mode_t m) { REAL(mkdir, int, const char *, mode_t); char b[4096]; return r_mkdir(fold(p, b), m); }
int unlink(const char *p) { REAL(unlink, int, const char *); char b[4096]; return r_unlink(fold(p, b)); }
int rmdir(const char *p) { REAL(rmdir, int, const char *); char b[4096]; return r_rmdir(fold(p, b)); }
int chmod(const char *p, mode_t m) { REAL(chmod, int, const char *, mode_t); char b[4096]; return r_chmod(fold(p, b), m); }
int symlink(const char *t, const char *p) { REAL(symlink, int, const char *, const char *); char b[4096]; return r_symlink(t, fold(p, b)); }
ssize_t readlink(const char *p, char *o, size_t n) { REAL(readlink, ssize_t, const char *, char *, size_t); char b[4096]; return r_readlink(fold(p, b), o, n); }
int rename(const char *x, const char *y) { REAL(rename, int, const char *, const char *); char b1[4096], b2[4096]; return r_rename(fold(x, b1), fold(y, b2)); }
int link(const char *x, const char *y)
{
    REAL(link, int, const char *, const char *);
    if (nolink()) { errno = EPERM; return -1; }
    char b1[4096], b2[4096];
    return r_link(fold(x, b1), fold(y, b2));
}
int linkat(int d1, const char *x, int d2, const char *y, int f)
{
    REAL(linkat, int, int, const char *, int, const char *, int);
    if (nolink()) { errno = EPERM; return -1; }
    char b1[4096], b2[4096];
    return r_linkat(d1, fold(x, b1), d2, fold(y, b2), f);
}
int utimensat(int d, const char *p, const struct timespec t[2], int f)
{
    REAL(utimensat, int, int, const char *, const struct timespec *, int);
    char b[4096];
    return r_utimensat(d, fold(p, b), t, f);
}
long pathconf(const char *p, int n) { REAL(pathconf, long, const char *, int); char b[4096]; return r_pathconf(fold(p, b), n); }
DIR *opendir(const char *p) { REAL(opendir, DIR *, const char *); char b[4096]; return r_opendir(fold(p, b)); }
