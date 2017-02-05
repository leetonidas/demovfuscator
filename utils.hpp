#ifndef UTILS_H
#define UTILS_H

static uint8_t tst_pt[4][2] = {{0x85, 0xc0}, {0x85, 0xdb}, {0x85, 0xc9}, {0x85, 0xd2}};
static uint8_t jmp_ins[2] = {0x0f, 0x84};

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
