#include <asm-generic/errno-base.h>

#include <linux/moduleloader.h>
#include <linux/printk.h>

#include <symbol_extractor.h>
#include <frogprobe.h>
#include <encoder.h>

#define FROGPROBE_HASH_BITS 6
#define FROGPROBE_TABLE_SIZE (1 << FROGPROBE_HASH_BITS)

struct frogprobe_context_s {
    struct hlist_head table[FROGPROBE_TABLE_SIZE];
    struct mutex lock;
} fp_context = {
    .lock = __MUTEX_INITIALIZER(fp_context.lock),
};

void add_frogprobe_to_table(frogprobe_t *fp)
{
    int hash_idx = hash_ptr(fp->address, FROGPROBE_HASH_BITS);
    INIT_HLIST_NODE(&fp->hlist);

    mutex_lock(&fp_context.lock);
    hlist_add_head_rcu(&fp->hlist, &fp_context.table[hash_idx]);
    mutex_unlock(&fp_context.lock);
}

void remove_frogprobe_from_table(frogprobe_t *fp)
{
    mutex_lock(&fp_context.lock);
    hlist_del_rcu(&fp->hlist);
    mutex_unlock(&fp_context.lock);
}

bool is_symbol_frogprobed_unsafe(frogprobe_t *fp)
{
    int hash_idx = hash_ptr(fp->address, FROGPROBE_HASH_BITS);
    struct hlist_head *head = &fp_context.table[hash_idx];
    frogprobe_t *curr;

    hlist_for_each_entry_rcu(curr, head, hlist) {
        if (fp->address == curr->address) {
            return true;
        }
    }
    return false;
}

bool is_symbol_frogprobed(frogprobe_t *fp)
{
    // no symbol address -> not in table
    if (!fp->address)
        return false;

    mutex_lock(&fp_context.lock);
    bool rc = is_symbol_frogprobed_unsafe(fp);
    mutex_unlock(&fp_context.lock);
    return rc;
}

bool is_fp_in_list(frogprobe_t *new, frogprobe_t *head)
{
    if (list_empty(&head->list)) {
            return head == new;
    } else {
        frogprobe_t *tmp;
        list_for_each_entry(tmp, &head->list, list) {
            if (new == tmp) {
                return true;
            }
        }
    }
    return false;
}

bool is_rereg_probe_unsafe(frogprobe_t *fp)
{
    int hash_idx = hash_ptr(fp->address, FROGPROBE_HASH_BITS);
    struct hlist_head *head = &fp_context.table[hash_idx];
    frogprobe_t *curr;

    hlist_for_each_entry_rcu(curr, head, hlist) {
        if (fp->address == curr->address) {
            return is_fp_in_list(fp, curr);
        }
    }
    return false;

}

bool is_rereg_probe(frogprobe_t *fp)
{
    mutex_lock(&fp_context.lock);
    bool rc = is_rereg_probe_unsafe(fp);
    mutex_unlock(&fp_context.lock);
    return rc;
}

void *module_alloc_around_call(void *addr, int size)
{
    unsigned long call_range = 0x7fffffff; // ±31bit offset
    unsigned long start = (unsigned long)addr - call_range;
    unsigned long end = max((unsigned long)addr + call_range, -1UL);
    return __vmalloc_node_range_p(size, MODULE_ALIGN, start, end, GFP_KERNEL,
                                  PAGE_KERNEL, VM_FLUSH_RESET_PERMS | VM_DEFER_KMEMLEAK,
                                   NUMA_NO_NODE, __builtin_return_address(0));
}

extern void frogprobe_post_handler_ex(void);
__asm__(
"frogprobe_post_handler_ex:"
".intel_syntax;"
    "pop %r11;"
    "pop %r10;"
    "pop %r9;"
    "pop %r8;"
    "pop %rcx;"
    "pop %rdx;"
    "pop %rsi;"
    "pop %rdi;"
    "push %rax;" // save original return value
    "call %r11;"
    "pop %rax;"
    "ret; int3;"
".att_syntax;"
);

/*
 * The stub change the functions stack return address to be able call post_handler
 * without affect the normal flow
 * rax + r11 are free to use (https://en.wikipedia.org/wiki/X86_calling_conventions#System_V_AMD64_ABI)
 * Stub post_handler logic is:
 *  movabs rax, post_handler
 *  pop r11
 *  push rdi, rsi, rdx, rcx, r8, r9, r10 (instead of the pushes in the base trampoline)
 *  push rax
 *  movabs rax, frogprobe_post_handler_ex
 *  push rax
 *  push r11
 *
 * Stack before logic:
 *          -------------------------------------
 *         |       original return address       |
 *         |             fp->addr + 5            |
 *          -------------------------------------
 *
 * Stack after logic:
 *          -------------------------------------
 *         |       original return address       |
 *         |       calling conventions regs      |
 *         |           fp->post_handler          |
 *         |       frogprobe_post_handler_ex     |
 *         |             fp->addr + 5            |
 *          -------------------------------------
 *
 * The idea is to save the calling-conventions registers for later use (post_handler)
 * after the function probed runs, it will return to frogprobe_post_handler_ex
 * which will restore the registers and call post_handler.
 */
#define POST_HANDLER_PREP_SIZE (MOVABS_RAX_SIZE + POP_R11_SIZE + PUSH_RAX_SIZE +    \
                                MOVABS_RAX_SIZE + PUSH_CALL_CONVENTIONS_REGS_SIZE + \
                                PUSH_RAX_SIZE + PUSH_R11_SIZE)
void prepare_post_handler_trampoline(char *tramp, int *offset, uint64_t post_handler)
{
    encode_movabs_rax(tramp, offset, post_handler);
    encode_pop_r11(tramp, offset);
    encode_push_calling_conventions_regs(tramp, offset);
    encode_push_rax(tramp, offset);
    encode_movabs_rax(tramp, offset, (uint64_t)&frogprobe_post_handler_ex);
    encode_push_rax(tramp, offset);
    encode_push_r11(tramp, offset);
}

/*
 * Create the stub:
 * (post_handler logic if needed)
 *  push rdi, rsi, rdx, rcx, r8, r9, r10 (remove if post hanlder)
 *  call [rip + pre_handler_offset]
 *  pop r10, r9, r8, rcx, rdx, rsi, rdi (switch with mov if post_handler)
 *  cmp rax, 0x0
 *  ja exit
 *  mov [rsp], rax // override function with new function
 * exit:
 *  ret
 *  int 3
 * pre_handler_offset:
 *  [fp->pre_handler]
 */
bool create_trampoline(frogprobe_t *fp)
{
    bool is_post_handler = fp->post_handler ? true : false;
    int stub_size = PUSH_CALL_CONVENTIONS_REGS_SIZE + RIP_REL_CALL_SIZE +
                    POP_CALL_CONVENTIONS_REGS_SIZE +  CMP_RAX_IMM +
                    BYTE_REL_JUMP_SIZE + MOV_RAX_TO_RSP_BASE_SIZE + RETQ_SIZE + 8 +
                    (is_post_handler ? (POST_HANDLER_PREP_SIZE -
                                        PUSH_CALL_CONVENTIONS_REGS_SIZE -
                                        POP_CALL_CONVENTIONS_REGS_SIZE +
                                        MOV_CC_REGS_FROM_STACK): 0);
    char *trampoline = module_alloc_around_call(fp->address, stub_size);
    if (!trampoline) {
        return false;
    }

    int offset = 0;
    if (is_post_handler) {
        prepare_post_handler_trampoline(trampoline, &offset, (uint64_t)fp->post_handler);
        encode_relative_call(trampoline, &offset,
                             (uint64_t)(trampoline + stub_size - 8));
        // 0x18 -> see @prepare_post_handler_trampoline draw to see rsp offset from cc-regs
        encode_mov_from_stack_offset_calling_conventions_regs(trampoline, &offset, 0x18);
    } else {
        encode_push_calling_conventions_regs(trampoline, &offset);
        encode_relative_call(trampoline, &offset,
                             (uint64_t)(trampoline + stub_size - 8));
        encode_pop_calling_conventions_regs(trampoline, &offset);
    }

    // override trampoline return address (func + 5) to override the hooked symbol
    encode_cmp_rax_imm(trampoline, &offset, 0);
    encode_byte_rel_jump(trampoline, &offset, (uint64_t)(trampoline + offset +
                         BYTE_REL_JUMP_SIZE +  MOV_RAX_TO_RSP_BASE_SIZE));
    encode_mov_rax_to_rsp_offset(trampoline, &offset, 0);

    encode_retq(trampoline, &offset);

    *(uint64_t *)(trampoline + offset) = (uint64_t)fp->pre_handler;

    int npages = DIV_ROUND_UP(stub_size, PAGE_SIZE);
    set_memory_rox_p((unsigned long)trampoline, npages);

    fp->trampoline = trampoline;
    fp->npages = npages;
    return true;
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
 *   |                  --------------------------------------
 *    ---------------->| prepare post handler logic (if need) |
 *                     |              push regs               |
 *                     |    call [rip + pre_handler_offset]   |
 *                     |               pop regs               |
 *                     |     logic to change rc (if need)     |
 *                     |               ret; int3              |
 * pre_handler_offset: |           fp->post_handler           |
 *                      --------------------------------------
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

    if (is_rereg_probe(fp)) {
        return -EINVAL;

    } else if (is_symbol_frogprobed(fp)) {
        return -EBUSY;
    }

    // validate if there is enough space for our trampoline (as done in kprobe + ftrace)
    // if already kprobed won't support now
    if (memcmp(fp->address, big_nop, NOP_SIZE)) {
        return -EFAULT;
    }

    if (!create_trampoline(fp)) {
        return -ENOMEM;
    }

    char opcode[CALL_SIZE] = { 0xe8, 0x00, 0x00, 0x00, 0x00 }; // call prefix
    *(uint32_t *)(opcode + 1) = (unsigned long)fp->trampoline - (unsigned long)fp->address - CALL_SIZE;
    text_poke_p(fp->address, opcode, CALL_SIZE);

    INIT_LIST_HEAD(&fp->list);
    add_frogprobe_to_table(fp);
    return 0;
}

void unregister_frogprobe(frogprobe_t *fp)
{
    remove_frogprobe_from_table(fp);

    text_poke_p(fp->address, big_nop, NOP_SIZE);

    vfree(fp->trampoline);
    fp->address = NULL;
    fp->trampoline = 0;
    fp->npages = 0;

}