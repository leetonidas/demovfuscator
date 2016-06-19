
#ifndef DISHLP_H
#define DISHLP_H

#include <string>
#include <unordered_map>
#include <memory>
#include <vector>
#include <stack>
#include <cstring>
#include <iostream>
#include <capstone/capstone.h>
#include "memhlp.hpp"
#include "stackMachine.hpp"
#include "utils.hpp"

#define OP(ins,x) (ins)->detail->x86.operands[x]


int is_dir_mem(cs_x86_op *op, uint64_t addr);
int is_sel_mem(cs_x86_op *op, uint64_t addr);
int is_reg_mem(cs_x86_op *op, x86_reg reg);
bool is_ill_ins(cs_insn *ins);

class dishlp{
	public:
		~dishlp();
		void init(csh);
		void set_mem(std::shared_ptr<memhlp> memory);
		int next();
		int go_to(uint64_t);
		int disasm(uint64_t start, uint64_t length);
		size_t get_cur(cs_insn **);
		void set_disnum(size_t num);
		size_t get_last(cs_insn **);
		cs_insn *trace_mem(cs_insn *, uint64_t addr, uint64_t limit, bool ign_sym = false);
		cs_insn *trace_mem_fwd(cs_insn *, uint64_t addr);
		cs_insn *trace_back(cs_insn *, x86_reg reg, uint64_t limit);
		cs_insn *nxt_insn(cs_insn *);
		template<typename c>
		int trace_back(std::stack<element, c> *st,
		                cs_insn *ins, x86_reg reg, uint64_t limit);
		std::vector<cs_insn *> trace_fwd(cs_insn *, x86_reg reg);
		int is_sel_target(cs_x86_op *op);
		void find_regs(std::vector<uint32_t> *regs, cs_insn* i, uint64_t label);
	private:
		size_t disnum = 768;
		int state = 0;
		cs_insn *cur = NULL;
		size_t ncur = 0;
		cs_insn *last = NULL;
		size_t nlast = 0;
		cs_insn *nxt = NULL;
		size_t nnxt = 0;
		csh han;
		uint64_t pos = 0;
		std::shared_ptr<memhlp> mem;
		size_t get_buf(cs_insn *i, cs_insn **base);
		size_t last_buf(cs_insn **base);
		size_t next_buf(cs_insn **base);
};

template<typename c>
void push_imm(std::stack<element, c> *st, uint64_t val) {
	element e;
	e.type = ELE_CONST;
	e.imm = val;
	st->push(e);
}

template<typename c>
void adjust_mem(std::stack<element, c> *st, int disp, x86_reg reg) {
	element adj;
	if (reg == X86_REG_INVALID) return;
	uint64_t mask = get_mask(reg);
	mask = mask << ((disp&3) * 8);
	if (mask >= 0x100000000)
		std::cerr << "unaligned memory access! - overflow" << std::endl;
	if (mask == 0xFFFFFFFF) return;
	push_imm(st, mask);
	adj.type = ELE_FUNC;
	adj.fun = SYM_IMP_BAND;
	st->push(adj);
}


template<typename c>
int dishlp::trace_back(std::stack<element, c> *st,
                        cs_insn *ins, x86_reg reg, uint64_t limit) {
	reg = get_32bit(reg);
	cs_insn *ori = trace_back(ins, reg, limit);
	cs_insn *tmp;
	uint64_t disp = 0;
	x86_reg mem_reg = X86_REG_INVALID;
	element el;
	if (!ori)
		return -1;
	switch (OP(ori,1).type) {
		case X86_OP_IMM:
			push_imm(st, OP(ori, 1).imm);
			break;
		case X86_OP_MEM:
			el.type = ELE_MEM;
			std::memcpy(&el.mem, &(OP(ori, 1).mem), sizeof(x86_op_mem));
			disp = (uint64_t) OP(ori, 1).mem.disp;
			mem_reg = OP(ori, 0).reg;
			tmp = trace_mem(ori, disp & (~0x3), limit);
			if (is_dir_mem(&OP(ori, 1), 0)){
				if (!tmp || mem->has_sym_to(disp & (~0x3))) {
					st->push(el);
					break;
				}
				if (OP(tmp,1).type == X86_OP_IMM) {
					push_imm(st, OP(tmp, 1).imm);
					break;
				}
				if (trace_back(st, tmp, OP(tmp, 1).reg, limit))
					st->push(el);
				break;
			}
			if (is_sel_mem(&OP(ori, 1), 0)) {
				if (trace_back(st, ori, OP(ori, 1).mem.index, limit))
					st->push(inv_ele);
				st->push(el);
				break;
			}
			if (is_reg_mem(&OP(ori, 1), X86_REG_INVALID)) {
				if (trace_back(st, ori, OP(ori, 1).mem.base, limit))
					st->push(inv_ele);
				st->push(el);
				break;
			}
			tmp = trace_back(ori, OP(ori, 1).mem.base, limit);
			if (!tmp) {
				st->push(inv_ele);
				if (trace_back(st, ori, OP(ori, 1).mem.index, limit))
					st->push(inv_ele);
				st->push(el);
				break;
			}
			if (is_sel_mem(&OP(tmp, 1), 0)) {
				trace_back(st, tmp, OP(tmp, 1).mem.index, limit);
				trace_back(st, ori, OP(ori, 1).mem.index, limit);
				symbl sym = mem->analyse_table((uint64_t) OP(tmp, 1).mem.disp,
												2);
				if (sym == SYM_INVALID) {
					st->push(el);
				} else {
					el.type = ELE_FUNC;
					el.fun = sym;
					st->push(el);
				}
				break;
			}
			if (mem->has_sym_to(disp & (~0x3)) || !tmp) {
				st->push(el);
				break;
			}
			return -1;
		case X86_OP_REG:
			if (trace_back(st, ori, OP(ori, 1).reg, limit))
				return -1;
			break;
		default:
			return -1;
	}
	adjust_mem(st, disp, mem_reg);
	return 0;
}
#endif
