#pragma once

#include <linux/types.h>

#define CALL_SIZE 5

#define NOP_SIZE 5
static const char big_nop[NOP_SIZE] = { 0x0f, 0x1f, 0x44, 0x00, 0x00 };

#define RIP_REL_CALL_SIZE 6
void encode_relative_call(char *trampoline, int *offset, uint64_t dest);

#define BYTE_REL_JUMP_SIZE 2
void encode_byte_rel_jump(char *trampoline, int *offset, uint64_t dest);

#define PUSH_CALL_CONVENTIONS_REGS_SIZE 10
void encode_push_calling_conventions_regs(char *trampoline, int *offset);

#define POP_CALL_CONVENTIONS_REGS_SIZE 10
void encode_pop_calling_conventions_regs(char *trampoline, int *offset);

#define RETQ_SIZE 2
void encode_retq(char *trampoline, int *offset);

#define MOVABS_RAX_SIZE 10
void encode_movabs_rax(char *trampoline, int *offset, uint64_t imm);

#define PUSH_RAX_SIZE 1
void encode_push_rax(char *trampoline, int *offset);

#define POP_R11_SIZE 2
void encode_pop_r11(char *trampoline, int *offset);

#define PUSH_R11_SIZE 2
void encode_push_r11(char *trampoline, int *offset);

#define CMP_RAX_IMM 6
void encode_cmp_rax_imm(char *trampoline, int *offset, uint32_t imm);

#define MOV_RAX_TO_RSP_BASE_SIZE 5
#define MOV_RAX_TO_RSP_PREFIX_SIZE 4
void encode_mov_rax_to_rsp_offset(char *trampoline, int *offset, int rsp_offset);