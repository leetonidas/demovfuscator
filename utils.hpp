#ifndef UTILS_H
#define UTILS_H

#include <cstdint>
#include <capstone/x86.h>

#include "stackMachine.hpp"

char *get_name(unsigned int reg);
void print_func(symbl sym);
void dump_elem(element *e);
uint64_t get_mask(x86_reg reg);
uint8_t* test_patch(x86_reg reg);
x86_reg get_32bit(x86_reg reg);
x86_reg get_16bit(x86_reg reg);
x86_reg get_8h(x86_reg reg);
x86_reg get_8l(x86_reg reg);
x86_reg get_alike(x86_reg reg, x86_reg size);
int get_size(x86_reg reg);
int is_sel_mem(element *e);

#endif
