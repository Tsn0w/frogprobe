#include <encoder.h>

#include <linux/string.h>

#define RET_INSN 0xc3
#define INT3_INSN 0xcc

void encode_call(char *target, char *base, char *dest)
{
    char opcode[CALL_SIZE] = { 0xe8, 0x00, 0x00, 0x00, 0x00 }; // call prefix
    *(uint32_t *)(opcode + 1) = (unsigned long)base - (unsigned long)dest - CALL_SIZE;
    memcpy(target, opcode, CALL_SIZE);

}
void encode_relative_call(char *trampoline, int *offset, uint64_t dest)
{
    uint32_t rel_off = (uint32_t)(dest - RIP_REL_CALL_SIZE -
                                  (uint64_t)trampoline - *offset);
    trampoline[*offset + 0] = 0xff;
    trampoline[*offset + 1] = 0x15;
    *(uint32_t *)(trampoline + *offset + 2) = rel_off;
    *offset += RIP_REL_CALL_SIZE;
}

void encode_byte_rel_jump(char *trampoline, int *offset, uint64_t dest)
{
    short rel_off = (short)(dest - BYTE_REL_JUMP_SIZE - (uint64_t)trampoline -
                            *offset) & 0xff;
    trampoline[*offset] = 0x74;
    trampoline[*offset + 1] = rel_off;
    *offset += BYTE_REL_JUMP_SIZE;
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

void encode_movabs_rax(char *trampoline, int *offset, uint64_t imm)
{
    trampoline[*offset] = 0x48;
    trampoline[*offset + 1] = 0xb8;
    *(uint64_t *)(trampoline + *offset + 2) = imm;
    *offset += MOVABS_RAX_SIZE;
}

void encode_push_rax(char *trampoline, int *offset)
{
    trampoline[*offset] = 0x50;
    *offset += PUSH_RAX_SIZE;
}

void encode_pop_r11(char *trampoline, int *offset)
{
    trampoline[*offset] = 0x41;
    trampoline[*offset + 1] = 0x5b;
    *offset += POP_R11_SIZE;
}

bool is_insn_pop_r11(char *trampoline)
{
    static const char pop_r11[POP_R11_SIZE] = { 0x41, 0x5b };
    return memcmp(trampoline, pop_r11, POP_R11_SIZE);
}

void encode_push_r11(char *trampoline, int *offset)
{
    trampoline[*offset] = 0x41;
    trampoline[*offset + 1] = 0x53;
    *offset += PUSH_R11_SIZE;
}

void encode_cmp_rax_imm(char *trampoline, int *offset, uint32_t imm)
{
    trampoline[*offset] = 0x48;
    trampoline[*offset + 1] = 0x3d;
    *(uint32_t *)(trampoline + *offset + 2) = imm;
    *offset += CMP_RAX_IMM;
}

void encode_mov_rax_to_rsp_offset(char *trampoline, int *offset, int rsp_offset)
{
    static const char mov_rax_rsp_base[MOV_RAX_TO_RSP_PREFIX_SIZE] = { 0x48, 0x89,
                                                                       0x44, 0x24 };

    memcpy(trampoline + *offset, mov_rax_rsp_base, MOV_RAX_TO_RSP_PREFIX_SIZE);
    trampoline[*offset + MOV_RAX_TO_RSP_PREFIX_SIZE] = (rsp_offset & 0xff);
    *offset += MOV_RAX_TO_RSP_BASE_SIZE;
}

void encode_mov_from_stack_offset_calling_conventions_regs(char *trampoline,
                                                           int *offset,
                                                           int stack_offset)
{
    static const char mov_regs_from_rsp_offset[MOV_CC_REGS_FROM_STACK] = {
        0x4c, 0x8b, 0x54, 0x24, 0x18, // mov r10, [rsp + 0x18]
        0x4c, 0x8b, 0x4c, 0x24, 0x20, // mov r9, [rsp + 0x10]
        0x4c, 0x8b, 0x44, 0x24, 0x28, // mov r8, [rsp + 0x28]
        0x48, 0x8b, 0x4c, 0x24, 0x30, // mov rcx, [rsp + 0x30]
        0x48, 0x8b, 0x54, 0x24, 0x38, // mov rdx, [rsp + 0x38]
        0x48, 0x8b, 0x74, 0x24, 0x40, // mov rsi, [rsp + 0x40]
        0x48, 0x8b, 0x7c, 0x24, 0x48, // mov rdi, [rsp + 0x48]
    };

    memcpy(trampoline + *offset, mov_regs_from_rsp_offset, MOV_CC_REGS_FROM_STACK);
    *offset += MOV_CC_REGS_FROM_STACK;

}

void encode_mov_rsp_32bit_offset_to_rdi(char *trampoline, int *offset,
                                        uint32_t stack_offset)
{
    static const char mov_rsp_32_offset_to_rdi[MOV_RSP_32BIT_OFFSET_TO_RDI_SIZE] = {
        0x48, 0x8b, 0xbc, 0x24, 0x00, 0x00, 0x00, 0x00 /* mov rdi, [rsp + 0x00] */
    };

    memcpy(trampoline + *offset, mov_rsp_32_offset_to_rdi,
           MOV_RSP_32BIT_OFFSET_TO_RDI_SIZE);
    trampoline[*offset + MOV_32BIT_IMM_OFFSET] = stack_offset;
    *offset += MOV_RSP_32BIT_OFFSET_TO_RDI_SIZE;
}

void encode_lea_rsi_rsp_offset(char *trampoline, int *offset, short stack_offset)
{
    static const char lea_rsi_rsp_offset[LEA_RSI_RSP_OFFSET_SIZE] = {
        0x48, 0x8d, 0x74, 0x24, 0x00 /* lea rsi, [rsp + 0x0] */
    };

    memcpy(trampoline + *offset, lea_rsi_rsp_offset, LEA_RSI_RSP_OFFSET_SIZE);
    trampoline[*offset + LES_RSI_RSP_IMM_OFFSET] = stack_offset & 0xff;
    *offset += LEA_RSI_RSP_OFFSET_SIZE;
}