#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xf8cdfa2e, "module_layout" },
	{ 0xb382ed86, "kmem_cache_destroy" },
	{ 0x45d14bdf, "hypercall_page" },
	{ 0x5a34a45c, "__kmalloc" },
	{ 0x96f15a29, "put_pid" },
	{ 0xf0943c4d, "gnttab_map_refs" },
	{ 0xedbc6f67, "gnttab_end_foreign_access" },
	{ 0xc8b57c27, "autoremove_wake_function" },
	{ 0xfe727411, "get_phys_to_machine" },
	{ 0x19062ef3, "gnttab_unmap_refs" },
	{ 0x55526907, "xen_features" },
	{ 0xb6230f1f, "gnttab_grant_foreign_access" },
	{ 0xc60264d8, "mmu_notifier_register" },
	{ 0x630f715c, "mutex_unlock" },
	{ 0x359dfeab, "mmput" },
	{ 0x91715312, "sprintf" },
	{ 0x7eba1a76, "kthread_create_on_node" },
	{ 0x86623fd7, "notify_remote_via_irq" },
	{ 0x48eb0c0d, "__init_waitqueue_head" },
	{ 0xdafa0a80, "sys_unlink" },
	{ 0x62dedc68, "misc_register" },
	{ 0x2731d7e6, "free_vm_area" },
	{ 0xf97456ea, "_raw_spin_unlock_irqrestore" },
	{ 0xf9a64146, "current_task" },
	{ 0x1de85c0a, "__mutex_init" },
	{ 0x27e1a049, "printk" },
	{ 0xc5b01b08, "kthread_stop" },
	{ 0x74b25692, "get_task_mm" },
	{ 0x56dd0534, "mmu_notifier_unregister" },
	{ 0xa8accafb, "apply_to_page_range" },
	{ 0xc44a7f87, "kmem_cache_free" },
	{ 0xbbf8cac9, "alloc_xenballooned_pages" },
	{ 0x16305289, "warn_slowpath_null" },
	{ 0x40494075, "mutex_lock" },
	{ 0xa3815ca5, "syscall_notify" },
	{ 0xb307038a, "alloc_vm_area" },
	{ 0xdd1a2871, "down" },
	{ 0xc0c4b56e, "fput" },
	{ 0x8cbde59a, "free_xenballooned_pages" },
	{ 0xd6b38e53, "kmem_cache_alloc" },
	{ 0x136d1d0f, "syscall_notify_stub" },
	{ 0x93fca811, "__get_free_pages" },
	{ 0x1000e51, "schedule" },
	{ 0xddd0e902, "fget_task" },
	{ 0x2bd4f120, "wake_up_process" },
	{ 0x8b04668e, "bind_interdomain_evtchn_to_irqhandler" },
	{ 0x67f7403e, "_raw_spin_lock" },
	{ 0x21fb443e, "_raw_spin_lock_irqsave" },
	{ 0x4d63a4de, "kmem_cache_create" },
	{ 0xe45f60d8, "__wake_up" },
	{ 0xd2965f6f, "kthread_should_stop" },
	{ 0x8b9200fd, "lookup_address" },
	{ 0x36dd5e7c, "find_get_pid" },
	{ 0x37a0cba, "kfree" },
	{ 0x23fa2532, "remap_pfn_range" },
	{ 0x622fa02a, "prepare_to_wait" },
	{ 0x731dba7a, "xen_domain_type" },
	{ 0xc4554217, "up" },
	{ 0x821dbb63, "__put_task_struct" },
	{ 0x75bb675a, "finish_wait" },
	{ 0x41489c48, "get_pid_task" },
	{ 0x15010e1f, "arbitrary_virt_to_machine" },
	{ 0x413e68a5, "misc_deregister" },
	{ 0x760a0f4f, "yield" },
	{ 0x83d24611, "vfs_write" },
	{ 0x7712771a, "unbind_from_irqhandler" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";

