#include <asm-generic/errno-base.h>

#include <linux/moduleloader.h>
#include <linux/printk.h>

#include <symbol_extractor.h>
#include <frogprobe.h>
#include <encoder.h>

#define NOP_SIZE 5
static const char big_nop[NOP_SIZE] = { 0x0f, 0x1f, 0x44, 0x00, 0x00 };

void *module_alloc_around_call(void *addr, int size)
{
    unsigned long call_range = 0x7fffffff; // ±31bit offset
    unsigned long start = (unsigned long)addr - call_range;
    unsigned long end = max((unsigned long)addr + call_range, -1UL);
    return __vmalloc_node_range_p(size, MODULE_ALIGN, start, end, GFP_KERNEL,
                                  PAGE_KERNEL, VM_FLUSH_RESET_PERMS | VM_DEFER_KMEMLEAK,
                                   NUMA_NO_NODE, __builtin_return_address(0));
}

/*
 * Create the stub:
 *  push rdi, rsi, rdx, rcx, r8, r9, r10
 *  call [rip + pre_handler_offset]
 *  pop r10, r9, r8, rcx, rdx, rsi, rdi
 *  ret
 *  int 3
 * pre_handler_offset:
 *  [fp->pre_handler]
 */
bool create_trampoline(frogprobe_t *fp)
{
    int stub_size = PUSH_CALL_CONVENTIONS_REGS_SIZE + RIP_REL_CALL_SIZE +
                    POP_CALL_CONVENTIONS_REGS_SIZE + RETQ_SIZE + 8;
    char *trampoline = module_alloc_around_call(fp->address, stub_size);
    if (!trampoline) {
        return false;
    }

    int offset = 0;
    encode_push_calling_conventions_regs(trampoline, &offset);
    encode_relative_call(trampoline, &offset,
                         (uint64_t)(trampoline + stub_size - 8));
    encode_pop_calling_conventions_regs(trampoline, &offset);
    encode_retq(trampoline, &offset);

    *(uint64_t *)(trampoline + stub_size - 8) = (uint64_t)fp->pre_handler;

    int npages = DIV_ROUND_UP(stub_size, PAGE_SIZE);
    set_memory_rox_p((unsigned long)trampoline, npages);

    fp->trampoline = trampoline;
    fp->npages = npages;
    return true;
}

void disable_WP(void)
{
    unsigned long cr0 = read_cr0() & ~(X86_CR0_WP);
    __asm__ volatile("mov %0,%%cr0": "+r" (cr0) : : "memory");
}

void enable_WP(void)
{
    unsigned long cr0 = read_cr0() | X86_CR0_WP;
    __asm__ volatile("mov %0,%%cr0": "+r" (cr0) : : "memory");
}

static int apply_trampoline(void *arg)
{
    frogprobe_t *fp = (frogprobe_t *)arg;
    char opcode[5] = { 0xe8, 0x00, 0x00, 0x00, 0x00 }; // call prefix
    *(uint32_t *)(opcode + 1) = (unsigned long)fp->trampoline - (unsigned long)fp->address - 5;

    disable_WP();
    memcpy(fp->address, opcode, 5);
    enable_WP();

	return 0;
}

/*
 * Register hook (frogprobe) on address for symbol given (fp->symbol) only if
 * the symbol is kprobeable using ftrace (meaning starts with 1 big nop)
 *
 * Before:
 *
 *      symbol:
 *          -------------------------------------
 *         |  nop dword ptr [rax + rax * 1 + 0]  |
 *         |                 ...                 |
 *          -------------------------------------
 *
 * After:
 *      symbol:
 *          -------------------------------------
 *         |         call fp->trampoline         |------
 *         |                 ...                 |      |
 *          -------------------------------------       |
 *                                                      |
 *    --------------------------------------------------
 *   |  fp->trampoline:
 *   |                  -----------------------------------
 *    ---------------->|             push regs             |
 *                     |  call [rip + pre_handler_offset]  |
 *                     |             pop regs              |
 *                     |             ret; int3             |
 * pre_handler_offset: |         fp->post_handler          |
 *                      -----------------------------------
 *
 */
int register_frogprobe(frogprobe_t *fp)
{
    if (!fp || !fp->symbol_name || !fp->pre_handler) {
        return -EINVAL;
    }

    fp->address = (void *)kallsyms_lookup_name_p(fp->symbol_name);
    if (!fp->address) {
        return -EINVAL;
    }

    // validate if there is enough space for our trampoline (as done in kprobe + ftrace)
    // if already kprobed won't support now
    if (memcmp(fp->address, big_nop, NOP_SIZE)) {
        return -EFAULT;
    }

    if (!create_trampoline(fp)) {
        return -ENOMEM;
    }

    stop_machine_p(apply_trampoline, (void *)fp, cpu_online_mask);
    return 0;
}


static int revert_trampoline(void *arg)
{
    frogprobe_t *fp = (frogprobe_t *)arg;

    disable_WP();
    memcpy(fp->address, big_nop, NOP_SIZE);
    enable_WP();

	return 0;
}

void unregister_frogprobe(frogprobe_t *fp)
{
    stop_machine_p(revert_trampoline, (void *)fp, cpu_online_mask);
    vfree(fp->trampoline);

    fp->trampoline = 0;
    fp->npages = 0;
    fp->address = NULL;
}