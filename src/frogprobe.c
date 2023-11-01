#include <asm-generic/errno-base.h>

#include <linux/moduleloader.h>
#include <linux/rculist.h>
#include <linux/srcu.h>

#include <symbol_extractor.h>
#include <frogprobe.h>
#include <encoder.h>

#define FROGPROBE_HASH_BITS 6
#define FROGPROBE_TABLE_SIZE (1 << FROGPROBE_HASH_BITS)
#define ptr_size (sizeof(void *))

typedef struct rereg_fp_work_s {
    struct work_struct work;
    char *tramp_addr;
    unsigned long npages;
} rereg_fp_work_t;

struct frogprobe_context_s {
    struct hlist_head table[FROGPROBE_TABLE_SIZE];
    struct mutex lock; /* lock both table and the frogprobe list */
} fp_context = {
    .lock = __MUTEX_INITIALIZER(fp_context.lock),
};

void add_frogprobe_to_table_unsafe(frogprobe_t *fp)
{
    int hash_idx = hash_ptr(fp->address, FROGPROBE_HASH_BITS);
    INIT_HLIST_NODE(&fp->hlist);

    hlist_add_head_rcu(&fp->hlist, &fp_context.table[hash_idx]);
}

void remove_frogprobe_from_table_unsafe(frogprobe_t *fp)
{
    hlist_del_rcu(&fp->hlist);
}

#ifdef CONFIG_PROVE_RCU_LIST
static int is_fp_srcu_read_lock_held(const frogprobe_t *fp)
{
    return srcu_read_lock_held(&fp->list_srcu);
}
#endif /* CONFIG_PROVE_RCU_LIST */

bool is_fp_in_list(frogprobe_t *new, frogprobe_t *head)
{
    if (head->is_multiprobe_head) {
        bool rc = false;
        int idx = srcu_read_lock(&head->list_srcu);
        frogprobe_t *tmp;
        list_for_each_entry_srcu(tmp, &head->list, list,
                                  is_fp_srcu_read_lock_held(head)) {
            if (new == tmp) {
                rc = true;
                break;
            }
        }
        srcu_read_unlock(&head->list_srcu, idx);
        return rc;
    }

    return (new == head);
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
    rcu_read_lock();
    bool rc = is_rereg_probe_unsafe(fp);
    rcu_read_unlock();
    return rc;
}

frogprobe_t *get_frogprobe_unsafe(void *address)
{
    int hash_idx = hash_ptr(address, FROGPROBE_HASH_BITS);
    struct hlist_head *head = &fp_context.table[hash_idx];
    frogprobe_t *curr;

    hlist_for_each_entry_rcu(curr, head, hlist) {
        if (address == curr->address) {
            return curr;
        }
    }
    return NULL;
}

frogprobe_t *get_frogprobe(void *address)
{
    rcu_read_lock();
    frogprobe_t *fp = get_frogprobe_unsafe(address);
    rcu_read_unlock();
    return fp;
}

bool is_symbol_frogprobed(frogprobe_t *fp)
{
    // no symbol address -> not in table
    if (!fp->address)
        return false;

    return (get_frogprobe(fp->address) != NULL);
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

void call_post_handler(frogprobe_t *fp, frogprobe_regs_t *regs, unsigned long rc)
{
    if (!fp->post_handler || fp->gone) {
        return;
    }

    refcount_inc(&fp->refcnt);
    fp->post_handler(rc, regs->rdi, regs->rsi, regs->rdx, regs->rcx, regs->r8,
                     regs->r9);
    refcount_dec(&fp->refcnt);

}

void frogprobe_post_handler_caller(unsigned long addr, frogprobe_regs_t *regs,
                                   unsigned long rc)
{
    frogprobe_t *fp = get_frogprobe((void *)(addr - CALL_SIZE));
    if (!fp) {
        // last frogprobe at this address removed
        return;
    }

    if (fp->is_multiprobe_head) {
        int idx = srcu_read_lock(&fp->list_srcu);

        frogprobe_t *tmp;
        list_for_each_entry_srcu(tmp, &fp->list, list,
                                 is_fp_srcu_read_lock_held(fp)) {
            call_post_handler(tmp, regs, rc);
        }

        srcu_read_unlock(&fp->list_srcu, idx);
    } else {
        call_post_handler(fp, regs, rc);
    }
}

extern void frogprobe_post_handler_ex(void);
__asm__(
"frogprobe_post_handler_ex:"
".intel_syntax;"
    "pop %rcx;" // current trampoline counter
    "pop %rdi;"
    "mov %rsi, %rsp;"
    "mov %rdx, %rax;"
    "push %rax;" // save original return value
    "push %rcx;"
    "call frogprobe_post_handler_caller;"
    "pop %rcx;"
    "pop %rax;"
    "add %rsp, 0x38;" // clean stack from cc-regs
    "lock dec dword ptr [%rcx];"
    "ret; int3;"
".att_syntax;"
);

/*
 * The stub change the functions stack return address to be able call post_handler
 * without affect the normal flow
 * rax + r11 are free to use (https://en.wikipedia.org/wiki/X86_calling_conventions#System_V_AMD64_ABI)
 * Stub post_handler logic is:
 *  pop r11
 *  push rdi, rsi, rdx, rcx, r8, r9, r10 (instead of the pushes in the base trampoline)
 *  lea rax, [rip + 0xXX] // XX is the offset for the current trampoline_counter
 *  push r11
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
 *         |             fp->addr + 5            |
 *         |         trampoline_counter          |
 *         |       frogprobe_post_handler_ex     |
 *         |             fp->addr + 5            | <-- frogpore_post_handler_ex can't use this
 *          -------------------------------------
 *
 * The idea is to save the calling-conventions registers for later use (post_handler)
 * after the function probed runs, it will return to frogprobe_post_handler_ex
 * which will restore the registers and call post_handler.
 */
#define POST_HANDLER_PREP_SIZE (POP_R11_SIZE + PUSH_CALL_CONVENTIONS_REGS_SIZE  +  \
                                LEA_RAX_RIP_DEST_SIZE + PUSH_R11_SIZE +            \
                                PUSH_RAX_SIZE + MOVABS_RAX_SIZE + PUSH_RAX_SIZE +  \
                                PUSH_R11_SIZE)
void prepare_post_handler_trampoline(char *tramp, int *offset, uint64_t post_handler,
                                     int npages)
{
    encode_pop_r11(tramp, offset);
    encode_push_calling_conventions_regs(tramp, offset);
    encode_lea_rax_rip(tramp, offset, (uint64_t)(tramp + npages * PAGE_SIZE));
    encode_push_r11(tramp, offset);
    encode_push_rax(tramp, offset);
    encode_movabs_rax(tramp, offset, (uint64_t)&frogprobe_post_handler_ex);
    encode_push_rax(tramp, offset);
    encode_push_r11(tramp, offset);
}


unsigned long call_pre_handler(frogprobe_t *fp, frogprobe_regs_t *regs)
{
    if (!fp->pre_handler || fp->gone) {
        return 0;
    }

    refcount_inc(&fp->refcnt);
    unsigned long rc = fp->pre_handler(regs->rdi, regs->rsi, regs->rdx,
                                       regs->rcx, regs->r8, regs->r9);
    refcount_dec(&fp->refcnt);
    return rc;
}

unsigned long frogprobe_pre_handler_ex(unsigned long addr, frogprobe_regs_t *regs)
{
    frogprobe_t *fp = get_frogprobe((void *)(addr - CALL_SIZE));
    if (!fp) {
        // last frogprobe at this address removed
        return 0;
    }

    unsigned long rc;
    if (fp->is_multiprobe_head) {
        int idx = srcu_read_lock(&fp->list_srcu);

        frogprobe_t *tmp;
        list_for_each_entry_rcu(tmp, &fp->list, list) {
            rc = call_pre_handler(tmp, regs);
            if (rc) { /* redirect original (meaning not running original function) */
                srcu_read_unlock(&fp->list_srcu, idx);
                return rc;
            }
        }

        srcu_read_unlock(&fp->list_srcu, idx);
    } else {
        rc = call_pre_handler(fp, regs);
    }

    return rc;
}


/*
 * Create the stub:
 * (post_handler logic if needed)
 *  push rdi, rsi, rdx, rcx, r8, r9, r10 (remove if post hanlder)
 *  mov rdi, [rsp + 7 * ptr_size] (chagned to 0 if post_handler)
 *  lea rsi, [rsp + 0] (changed to 3 * ptr_size if post_handler)
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
    int text_stub_size = LOCK_INC_RIP_REL_OFFSET_SIZE + PUSH_CALL_CONVENTIONS_REGS_SIZE +
                         MOV_RSP_32BIT_OFFSET_TO_RDI_SIZE + LEA_RSI_RSP_OFFSET_SIZE +
                         RIP_REL_CALL_SIZE + POP_CALL_CONVENTIONS_REGS_SIZE +
                         CMP_RAX_IMM + BYTE_REL_JUMP_SIZE + MOV_RAX_TO_RSP_BASE_SIZE +
                         LOCK_DEC_RIP_REL_OFFSET_SIZE + RETQ_SIZE + ptr_size +
                        (is_post_handler ? (POST_HANDLER_PREP_SIZE -
                                            PUSH_CALL_CONVENTIONS_REGS_SIZE -
                                            POP_CALL_CONVENTIONS_REGS_SIZE -
                                            LOCK_DEC_RIP_REL_OFFSET_SIZE +
                                            MOV_CC_REGS_FROM_STACK): 0);
    // trampoline counter is on the next page
    int stub_size = PAGE_ALIGN(text_stub_size) + ptr_size;
    char *trampoline = module_alloc_around_call(fp->address, stub_size);
    if (!trampoline) {
        return false;
    }

    int npages = DIV_ROUND_UP(text_stub_size, PAGE_SIZE);
    int offset = 0;

    encode_lock_inc_rip_rel(trampoline, &offset, (uint64_t)(trampoline + stub_size
                            - ptr_size));

    if (is_post_handler) {
        // for imm -> see @prepare_post_handler_trampoline draw to see rsp offset from cc-regs
        int cc_regs_offset = 4 * ptr_size;
        prepare_post_handler_trampoline(trampoline, &offset,
                                        (uint64_t)fp->post_handler, npages);
        encode_mov_rsp_32bit_offset_to_rdi(trampoline, &offset, 0);
        encode_lea_rsi_rsp_offset(trampoline, &offset, cc_regs_offset);
        encode_relative_call(trampoline, &offset,
                             (uint64_t)(trampoline + text_stub_size - ptr_size));
        encode_mov_from_stack_offset_calling_conventions_regs(trampoline, &offset,
                                                              cc_regs_offset);
    } else {
        encode_push_calling_conventions_regs(trampoline, &offset);
        encode_mov_rsp_32bit_offset_to_rdi(trampoline, &offset, ptr_size * 7);
        encode_lea_rsi_rsp_offset(trampoline, &offset, 0);
        encode_relative_call(trampoline, &offset,
                             (uint64_t)(trampoline + text_stub_size - ptr_size));
        encode_pop_calling_conventions_regs(trampoline, &offset);
    }

    // override trampoline return address (func + 5) to override the hooked symbol
    encode_cmp_rax_imm(trampoline, &offset, 0);
    encode_byte_rel_jump(trampoline, &offset, (uint64_t)(trampoline + offset +
                         BYTE_REL_JUMP_SIZE +  MOV_RAX_TO_RSP_BASE_SIZE));
    encode_mov_rax_to_rsp_offset(trampoline, &offset, 0);

    if (!is_post_handler) {
        encode_lock_dec_rip_rel(trampoline, &offset, (uint64_t)(trampoline + stub_size
                                - ptr_size));
    }
    encode_retq(trampoline, &offset);

    *(uint64_t *)(trampoline + offset) = (uint64_t)frogprobe_pre_handler_ex;

    set_memory_rox_p((unsigned long)trampoline, npages);
    fp->trampoline = trampoline;
    fp->npages = npages;
    return true;
}

bool trampoline_prepared_for_post(frogprobe_t *first)
{
    return !is_insn_pop_r11(first->trampoline + LOCK_INC_RIP_REL_OFFSET_SIZE);
}

void wait_till_trampoline_unused(char *trampoline, int npages)
{
    volatile char *trampoline_counter_p = trampoline + PAGE_SIZE * npages;
    while (*(unsigned long *)trampoline_counter_p != 0) {
        schedule();
    }
}

static void release_trampoline_work_fn(struct work_struct *work)
{
    rereg_fp_work_t *fp_work = container_of(work, rereg_fp_work_t, work);
    wait_till_trampoline_unused(fp_work->tramp_addr, fp_work->npages);
    vfree(fp_work->tramp_addr);
}

void release_trampoline_later(char *tramp_addr, unsigned long npages)
{
    rereg_fp_work_t *fp_work = kmalloc(sizeof(*fp_work), GFP_KERNEL);
    if (fp_work) {
        fp_work->tramp_addr = tramp_addr;
        fp_work->npages = npages;
        INIT_WORK(&fp_work->work, release_trampoline_work_fn);
        schedule_work(&fp_work->work);
    } else {
        // if failed to allocate work, just wait here
        wait_till_trampoline_unused(tramp_addr, npages);
        vfree(tramp_addr);
    }
}

int create_frogprobe_head(frogprobe_t *previous)
{
    frogprobe_t *head = kzalloc(sizeof(*head), GFP_KERNEL);
    if (!head) {
        return -ENOMEM;
    }

    int rc = init_srcu_struct(&head->list_srcu);
    if (rc < 0) {
        kfree(head);
        return rc;
    }

    head->is_multiprobe_head = true;
    head->address = previous->address;
    INIT_LIST_HEAD(&head->list);

    // adding to list now, so will reachable when adding head to the hlist
    list_add_rcu(&previous->list, &head->list);
    synchronize_srcu(&head->list_srcu);

    add_frogprobe_to_table_unsafe(head);
    remove_frogprobe_from_table_unsafe(previous);

    head->trampoline = previous->trampoline;
    head->npages = previous->npages;
    previous->trampoline = NULL;
    previous->npages = 0;
    return 0;
}

int register_another_frogprobe(frogprobe_t *fp)
{
    frogprobe_t *first_fp = get_frogprobe(fp->address);
    // TODO: should never fail?

    int rc = 0;
    if (!first_fp->is_multiprobe_head) {
        rc = create_frogprobe_head(first_fp);
        if (rc < 0) {
            return rc;
        }

        first_fp = get_frogprobe(fp->address);
    }

    // first_fp points to the head_frogprobe

    // first time we encouter a frogprobe on this symbol with post_handler
    // re-create trampoline with post_handler and update list
    // once we ready for post_handler, we will always be
    if (fp->post_handler && !trampoline_prepared_for_post(first_fp)) {
        if (!create_trampoline(fp)) {
            // head will be freed when the last frogprobe on the addr will be removed
            return -ENOMEM;
        }

        char *old_tramp = first_fp->trampoline;
        int old_npages = first_fp->npages;

        first_fp->trampoline = fp->trampoline;
        first_fp->npages = fp->npages;

        char opcode[CALL_SIZE] = {0};
        encode_call(opcode, fp->trampoline, fp->address);
        text_poke_p(fp->address, opcode, CALL_SIZE);
        release_trampoline_later(old_tramp, old_npages);
    }

    fp->trampoline = NULL;
    fp->npages = 0;

    list_add_tail_rcu(&fp->list, &first_fp->list);
    synchronize_srcu(&first_fp->list_srcu);
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
 *   |                  --------------------------------------
 *    ---------------->|     lock inc [trampoline counter]    |
 *                     | prepare post handler logic (if need) |
 *                     |              push regs               |
 *                     |          set rdi fp->addr + 5        |
 *                     |            set rsi fp_regs           |
 *                     |    call [rip + pre_handler_offset]   |
 *                     |               pop regs               |
 *                     |     logic to change rc (if need)     |
 *                     |     lock dec [trampoline counter]    |
 *                     |               ret; int3              |
 * pre_handler_offset: |       frogprobe_pre_handler_ex       |
 *                      --------------------------------------
 * at next page (must be writeable)
 * trampoline_counter:
 *
 */
int register_frogprobe(frogprobe_t *fp)
{
    if (!fp || !fp->symbol_name) {
        return -EINVAL;
    }

    // must be at least one handler
    if (!fp->pre_handler && !fp->post_handler) {
        return -EINVAL;
    }

    fp->address = (void *)kallsyms_lookup_name_p(fp->symbol_name);
    if (!fp->address) {
        return -EINVAL;
    }

    refcount_set(&fp->refcnt, 1);
    fp->is_multiprobe_head = false;
    fp->gone = false;

    int rc = 0;
    mutex_lock(&fp_context.lock);

    if (is_rereg_probe(fp)) {
        rc = -EINVAL;
        goto out;
    } else if (is_symbol_frogprobed(fp)) {
        rc = register_another_frogprobe(fp);
        goto out;
    }

    // validate if there is enough space for our trampoline (as done in kprobe + ftrace)
    // if already kprobed won't support now
    if (memcmp(fp->address, big_nop, NOP_SIZE)) {
        rc = -EFAULT;
        goto out;
    }

    if (!create_trampoline(fp)) {
        rc = -ENOMEM;
        goto out;
    }

    INIT_LIST_HEAD(&fp->list);
    add_frogprobe_to_table_unsafe(fp);

    char opcode[CALL_SIZE] = {0};
    encode_call(opcode, fp->trampoline, fp->address);
    text_poke_p(fp->address, opcode, CALL_SIZE);

out:
    mutex_unlock(&fp_context.lock);
    return rc;
}

void wait_till_fp_unused(frogprobe_t *fp)
{
    while (refcount_read(&fp->refcnt) > 1) {
        schedule();
    }
}

void wait_till_fp_trampoline_unused(frogprobe_t *fp)
{
    wait_till_trampoline_unused(fp->trampoline, fp->npages);
}

void unregister_frogprobe(frogprobe_t *fp)
{
    mutex_lock(&fp_context.lock);

    fp->gone = true;

    frogprobe_t *first_fp = get_frogprobe(fp->address);

    // regular fp
    if (first_fp == fp) {
        text_poke_p(fp->address, big_nop, NOP_SIZE);
        wait_till_fp_trampoline_unused(fp);
        vfree(fp->trampoline);
    } else {
        // part of a multi-probe
        wait_till_fp_unused(fp);
        list_del_rcu(&fp->list);
        synchronize_srcu(&first_fp->list_srcu);

        // if multi-probe is empty, just free it
        if (list_empty(&first_fp->list)) {
            remove_frogprobe_from_table_unsafe(first_fp);

            text_poke_p(first_fp->address, big_nop, NOP_SIZE);
            wait_till_fp_trampoline_unused(first_fp);
            cleanup_srcu_struct(&first_fp->list_srcu);
            vfree(first_fp->trampoline);
            kfree(first_fp);
        }
    }

    mutex_unlock(&fp_context.lock);

    fp->address = NULL;
    fp->trampoline = 0;
    fp->npages = 0;
}