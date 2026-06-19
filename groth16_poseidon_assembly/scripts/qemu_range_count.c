/* QEMU TCG plugin: counts retired guest instructions, bucketed by up to 4
 * named guest-address ranges (plus a grand total). Used to attribute the
 * verify instruction count to specific field-arithmetic kernels.
 *
 * Args (passed via -plugin librange.so,name0=...,lo0=...,hi0=...,...):
 *   nameK=<label>  loK=<vaddr>  hiK=<vaddr>   for K in 0..3  (hi exclusive)
 *
 * Build (same flags as count_insns.sh's plugin build):
 *   cc -shared -fPIC -I"$(brew --prefix glib)/include/glib-2.0" \
 *      -I"$(brew --prefix glib)/lib/glib-2.0/include" -I"$(brew --prefix)/include" \
 *      -Wl,-undefined,dynamic_lookup qemu_range_count.c -o librange.so
 * Run (ranges are build-specific; derive with arm-none-eabi-nm on the ELF):
 *   qemu-system-arm ... -plugin librange.so,name0=muln,lo0=...,hi0=...,... -d plugin
 */
#include <inttypes.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define MAX_R 4

static char     names[MAX_R][32];
static uint64_t lo[MAX_R], hi[MAX_R];
static int      nranges;
static _Atomic uint64_t hits[MAX_R];
static _Atomic uint64_t total;

static void vcpu_insn_exec(unsigned int cpu_index, void *udata) {
    atomic_fetch_add_explicit(&total, 1, memory_order_relaxed);
    intptr_t idx = (intptr_t)udata;
    if (idx >= 0)
        atomic_fetch_add_explicit(&hits[idx], 1, memory_order_relaxed);
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb) {
    size_t n = qemu_plugin_tb_n_insns(tb);
    for (size_t i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t va = qemu_plugin_insn_vaddr(insn);
        intptr_t idx = -1;
        for (int k = 0; k < nranges; k++) {
            if (va >= lo[k] && va < hi[k]) { idx = k; break; }
        }
        qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec,
                                               QEMU_PLUGIN_CB_NO_REGS,
                                               (void *)idx);
    }
}

static void plugin_exit(qemu_plugin_id_t id, void *p) {
    char buf[128];
    uint64_t t = atomic_load_explicit(&total, memory_order_relaxed);
    snprintf(buf, sizeof(buf), "total: %" PRIu64 "\n", t);
    qemu_plugin_outs(buf);
    for (int k = 0; k < nranges; k++) {
        uint64_t h = atomic_load_explicit(&hits[k], memory_order_relaxed);
        double pct = t ? (100.0 * (double)h / (double)t) : 0.0;
        snprintf(buf, sizeof(buf), "range %s: %" PRIu64 " (%.2f%%)\n",
                 names[k], h, pct);
        qemu_plugin_outs(buf);
    }
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv) {
    for (int i = 0; i < argc; i++) {
        char *eq = strchr(argv[i], '=');
        if (!eq) continue;
        *eq = '\0';
        const char *key = argv[i], *val = eq + 1;
        int k = key[strlen(key) - 1] - '0';
        if (k < 0 || k >= MAX_R) continue;
        if (k + 1 > nranges) nranges = k + 1;
        if (!strncmp(key, "name", 4)) {
            strncpy(names[k], val, sizeof(names[k]) - 1);
        } else if (!strncmp(key, "lo", 2)) {
            lo[k] = strtoull(val, NULL, 0);
        } else if (!strncmp(key, "hi", 2)) {
            hi[k] = strtoull(val, NULL, 0);
        }
    }
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
