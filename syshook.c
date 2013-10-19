#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/unistd.h>
#include <asm/pgtable.h>
#include <linux/syscalls.h>

static pte_t *pte;
unsigned long *sys_call_table;
long (*orig_exit_group)(int);

static char *sys_call_table_addr = "0x0";
module_param(sys_call_table_addr, charp, 0);
MODULE_PARM_DESC(sys_call_table_addr, "The sys_call_table address in System.map");

/* sys_exit_group hook */
static long my_exit_group(int exit_code) {
	printk(KERN_INFO "Hooked sys_exit_group (%u)\n", exit_code);

	return orig_exit_group(exit_code);
}

static inline void protect_memory(void) {
	/* Restore kernel memory page protection */
	set_pte_atomic(pte, pte_clear_flags(*pte, _PAGE_RW));
}

static inline void unprotect_memory(void) {
	/* Unprotected kernel memory page containing for writing */
	set_pte_atomic(pte, pte_mkwrite(*pte));
}

static int __init syshook_init(void) {
	unsigned long addr;
	unsigned int level;

	if (!memcmp(sys_call_table_addr, "0x0", sizeof("0x0"))) {
		printk(KERN_INFO "You must suply the sys_call_table addr as parameter\n");
		return -1;
	}

	sscanf(sys_call_table_addr, "%lx", &addr);

	/* Lookup the page table entry for supplied virtual address */
	pte = lookup_address(addr, &level);
	if (!pte)
		return -1;

	sys_call_table = (unsigned long*)addr;

	/* Checking if it is really sys_call_table */
	if (sys_close != (long (*)(unsigned int))sys_call_table[__NR_close]) {
		printk(KERN_INFO "sys_call_table can not be found (%p)\n",
			sys_call_table);
		return -1;
	}

	printk(KERN_INFO "sys_exit found at %lx\n", sys_call_table[__NR_exit_group]);

	orig_exit_group = (long (*)(int))sys_call_table[__NR_exit_group];

	unprotect_memory();
	sys_call_table[__NR_exit_group] = (unsigned long)my_exit_group;
	protect_memory();

	printk(KERN_INFO "sys_exit is %lx now!\n", sys_call_table[__NR_exit]);

    return 0;
}

static void __exit syshook_cleanup(void) {
	printk(KERN_INFO "Cleaning up module.\n");

	if (orig_exit_group) {
		unprotect_memory();
		sys_call_table[__NR_exit_group] = (unsigned long)orig_exit_group;
		protect_memory();
	}
}

module_init(syshook_init);
module_exit(syshook_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kernel BR team");
MODULE_DESCRIPTION("A sys_call_table hooking example");
