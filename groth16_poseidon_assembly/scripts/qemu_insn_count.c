/* Minimal QEMU TCG plugin: counts guest instructions executed and prints the
 * total at exit. Equivalent to the "insns:" line from QEMU's contrib libinsn,
 * which Homebrew does not ship prebuilt.
 *
 * Build (see count_insns.sh):
 *   cc -shared -fPIC $(pkg-config --cflags glib-2.0) \
 *      -I$(brew --prefix)/include qemu_insn_count.c -o libinsn.so
 */
#include <inttypes.h>
#include <stdatomic.h>
#include <stdio.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static _Atomic uint64_t insn_count;

static void vcpu_insn_exec(unsigned int cpu_index, void *udata) {
    atomic_fetch_add_explicit(&insn_count, 1, memory_order_relaxed);
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb) {
    size_t n = qemu_plugin_tb_n_insns(tb);
    for (size_t i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec,
                                               QEMU_PLUGIN_CB_NO_REGS, NULL);
    }
}

static void plugin_exit(qemu_plugin_id_t id, void *p) {
    char buf[64];
    snprintf(buf, sizeof(buf), "insns: %" PRIu64 "\n",
             atomic_load_explicit(&insn_count, memory_order_relaxed));
    qemu_plugin_outs(buf);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv) {
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
