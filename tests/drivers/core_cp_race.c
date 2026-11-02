/*
 * The system code pages are looked up on first use, which may be on any thread (the
 * first archive opened by a worker, several opened at once). Several threads ask at the
 * same moment; each must see the final values. Built with -fsanitize=thread when the
 * compiler can, so the lookup itself is checked for races.
 *   usage: core_cp_race          (LANG=ko_KR.UTF-8 -> 949/949)
 *   prints "ok ..." / "FAIL ..."
 */
#include "arc.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#define NT 4
static pthread_barrier_t bar;
static int seen_acp[NT], seen_oem[NT];

static void *run(void *p)
{
    int i = (int)(long)p;
    pthread_barrier_wait(&bar);
    if (i & 1) { seen_oem[i] = gz_plat_oemcp(); seen_acp[i] = gz_plat_acp(); }
    else { seen_acp[i] = gz_plat_acp(); seen_oem[i] = gz_plat_oemcp(); }
    return 0;
}

int main(void)
{
    unsetenv("GZ_TEST_ACP");
    unsetenv("GOGITZIP_CODEPAGE");
    unsetenv("LC_ALL");
    unsetenv("LC_CTYPE");
    setenv("LANG", "ko_KR.UTF-8", 1);
    pthread_t t[NT];
    pthread_barrier_init(&bar, 0, NT);
    for (long i = 0; i < NT; i++) pthread_create(&t[i], 0, run, (void *)i);
    for (int i = 0; i < NT; i++) pthread_join(t[i], 0);
    int bad = 0;
    for (int i = 0; i < NT; i++) bad |= seen_acp[i] != 949 || seen_oem[i] != 949;
    printf("%s code pages seen by %d threads:", bad ? "FAIL" : "ok", NT);
    for (int i = 0; i < NT; i++) printf(" %d/%d", seen_acp[i], seen_oem[i]);
    printf("\n");
    return bad;
}
