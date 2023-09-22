#pragma once

#include <linux/stop_machine.h>
#include <linux/set_memory.h>
#include <linux/kallsyms.h>
#include <linux/vmalloc.h>

#define EXTERN_SYMBOL(symbol_name)                 \
    typedef typeof(symbol_name) symbol_name ## _t; \
    extern symbol_name ## _t *symbol_name ## _p

EXTERN_SYMBOL(stop_machine);
EXTERN_SYMBOL(set_memory_rox);
EXTERN_SYMBOL(__vmalloc_node_range);
EXTERN_SYMBOL(kallsyms_lookup_name);

int export_symbols(void);
