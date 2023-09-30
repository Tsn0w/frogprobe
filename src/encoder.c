#include <encoder.h>

#include <linux/string.h>

#define RET_INSN 0xc3
#define INT3_INSN 0xcc

void encode_relative_call(char *trampoline, int *offset, uint64_t dest)
{
    uint32_t rel_off = (uint32_t)(dest - RIP_REL_CALL_SIZE -
                                  (uint64_t)trampoline - *offset);
    trampoline[*offset + 0] = 0xff;
    trampoline[*offset + 1] = 0x15;
    *(uint32_t *)(trampoline + *offset + 2) = rel_off;
    *offset += RIP_REL_CALL_SIZE;
}

void encode_push_calling_conventions_regs(char *trampoline, int *offset)
{
    static const char push_regs[PUSH_CALL_CONVENTIONS_REGS_SIZE] = { 0x57, 0x56,
                                                                     0x52, 0x51,
                                                                     0x41, 0x50,
                                                                     0x41, 0x51,
                                                                     0x41, 0x52 };
    memcpy(trampoline + *offset, push_regs, PUSH_CALL_CONVENTIONS_REGS_SIZE);
    *offset += PUSH_CALL_CONVENTIONS_REGS_SIZE;
}

void encode_pop_calling_conventions_regs(char *trampoline, int *offset)
{
    static const char pop_regs[POP_CALL_CONVENTIONS_REGS_SIZE] = { 0x41, 0x5a,
                                                                   0x41, 0x59,
                                                                   0x41, 0x58,
                                                                   0x59, 0x5a,
                                                                   0x5e, 0x5f };
    memcpy(trampoline + *offset, pop_regs, POP_CALL_CONVENTIONS_REGS_SIZE);
    *offset += POP_CALL_CONVENTIONS_REGS_SIZE;
}

void encode_retq(char *trampoline, int *offset)
{
    trampoline[*offset] = RET_INSN;
    trampoline[*offset + 1] = INT3_INSN;
    *offset += RETQ_SIZE;
}