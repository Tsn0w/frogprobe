#pragma once

#include <linux/types.h>

#define RIP_REL_CALL_SIZE 6
void encode_relative_call(char *trampoline, int *offset, uint64_t dest);

#define PUSH_CALL_CONVENTIONS_REGS_SIZE 10
void encode_push_calling_conventions_regs(char *trampoline, int *offset);

#define POP_CALL_CONVENTIONS_REGS_SIZE 10
void encode_pop_calling_conventions_regs(char *trampoline, int *offset);

#define RETQ_SIZE 2
void encode_retq(char *trampoline, int *offset);