#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/export-internal.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

#ifdef CONFIG_UNWINDER_ORC
#include <asm/orc_header.h>
ORC_HEADER;
#endif

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_MITIGATION_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif



static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x2789431b, "proc_create" },
	{ 0x3f66a26e, "register_kprobe" },
	{ 0xe846bd8d, "proc_remove" },
	{ 0x122c3a7e, "_printk" },
	{ 0xe48ec519, "single_open" },
	{ 0x4f9fd5f5, "seq_printf" },
	{ 0xbb10e61d, "unregister_kprobe" },
	{ 0x3571bf9a, "seq_read" },
	{ 0xae703f49, "seq_lseek" },
	{ 0x933bf13e, "single_release" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0xba8fbd64, "_raw_spin_lock" },
	{ 0xb5b54b34, "_raw_spin_unlock" },
	{ 0x87a21cb3, "__ubsan_handle_out_of_bounds" },
	{ 0x9533612c, "module_layout" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "08F6E887154552E309B0D1C");
