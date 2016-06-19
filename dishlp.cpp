#include <unordered_set>
#include "dishlp.hpp"


int is_dir_mem(cs_x86_op *op, uint64_t addr) {
	if (op->type == X86_OP_MEM && op->mem.base == X86_REG_INVALID &&
	    op->mem.index == X86_REG_INVALID)
		return (addr ? addr == ((uint64_t) op->mem.disp) : 1);
	return 0;
}

int is_sel_mem(cs_x86_op *op, uint64_t addr) {
	if (op->type == X86_OP_MEM && op->mem.base == X86_REG_INVALID &&
	    op->mem.index != X86_REG_INVALID && op->mem.scale == 4)
		return (addr ? addr == ((uint64_t) op->mem.disp) : 1);
	return 0;
}

int is_reg_mem(cs_x86_op *op, x86_reg reg) {
	if (op->type == X86_OP_MEM && op->mem.index == X86_REG_INVALID &&
	    op->mem.disp == 0)
		return (reg != X86_REG_INVALID ? reg == op->mem.base : 1);
	return 0;
}

bool is_ill_ins(cs_insn *i){
	if (OP(i, 0).type == X86_OP_REG &&
	    OP(i, 0).reg == X86_REG_CS &&
	    OP(i, 1).type == X86_OP_REG)
		return true;
	return false;
}

int dishlp::disasm(uint64_t start, uint64_t length) {
	if (!mem->is_X(start)) return -1;

	pos = start;
	if (last) cs_free(last, nlast);
	if (cur) cs_free(cur, ncur);
	if (nxt) cs_free(nxt, nnxt);
	last = NULL;
	cur = NULL;
	nxt = NULL;

	if ((state & 3) != 3) return -2;

	uint8_t *buf = mem->get_ptr(pos);
	if (buf == NULL) return -3;
	if (mem->space(pos) < length) return -4;

	ncur = cs_disasm(han, buf, length, pos, 0, &cur);
	if (ncur) {
		pos = cur[ncur - 1].address + cur[ncur - 1].size;
	} else {
		if (cur) cs_free(cur, ncur);
		cur = NULL;
		return -3;
	}
	return 0;
}

cs_insn *dishlp::nxt_insn(cs_insn *ins) {
	cs_insn *base;
	int num;
	if (0 == (num = get_buf(ins, &base))) return 0;
	if (num - (ins - base) < 1) return 0;
	if (num - (ins - base) > 1) return ins + 1;
	if (0 == next_buf(&base)) return 0;
	return base;
}

void dishlp::find_regs(std::vector<uint32_t> *regs, cs_insn *ins, uint64_t label) {
	cs_insn *base;
	// get the instruction buffer of --ins
	if (0 == get_buf(ins, &base)) return;
	// walk backwards
	while (ins > base) {
		// go back one
		if (ins != base) ins--;
		else {
			// if it was the last instruction in this buffer
			// go back into the last buffer
			size_t num = last_buf(&base);
			ins = base + num - 1;
			if (!num) return;
		}
		// break if label is found
		if (OP(ins, 1).type == X86_OP_IMM && ((uint64_t) OP(ins, 1).imm == label))
			break;

		// either	mov [rega], regb
		// or		mov [rega + 4], b
		if (OP(ins, 0).type == X86_OP_MEM && OP(ins, 0).mem.index == X86_REG_INVALID &&
		    OP(ins, 0).mem.base != X86_REG_INVALID && OP(ins, 1).type == X86_OP_REG &&
			(OP(ins, 0).mem.disp == 0 || OP(ins, 0).mem.disp == 4)) {
			// trace back the target
			cs_insn *ori = trace_back(ins, OP(ins, 0).mem.base, 0);
			if (ori && is_sel_mem(&OP(ori, 1), 0)) {
				// find where the value for true is set
				ori = trace_mem(ins , (uint64_t) OP(ori, 1).mem.disp + 4, 0, true);
				// it should be an immidiate since addresses are known at compilet.
				if (ori && OP(ori, 1).type == X86_OP_IMM)
					regs->push_back((uint32_t) OP(ori, 1).imm);
			}
		}
	}
}

int dishlp::is_sel_target(cs_x86_op *op) {
	if (is_sel_mem(op, 0)) {
		if (mem->get_sym((uint64_t) op->mem.disp) == SYM_SEL_TARGET)
			return 1;
		uint32_t *addr;
		if (0 == mem->get_data((uint64_t) op->mem.disp + 4, &addr)) {
			if (mem->get_sym((uint64_t) (*addr)) == SYM_TARGET) {
				mem->add_sym((uint64_t) op->mem.disp, SYM_SEL_TARGET);
				return 1;
			}
		}
	}
	return 0;
}

void dishlp::init(csh handler){
	han = handler;
	state |= 2;
}

int dishlp::go_to(uint64_t addr) {
	if (mem->is_X(addr)) {
		pos = addr;
		if (last) cs_free(last, nlast);
		if (cur) cs_free(cur, ncur);
		if (nxt) cs_free(nxt, nnxt);
		last = NULL;
		cur = NULL;
		nxt = NULL;
		return 0;
	}
	return -1;
}

int dishlp::next() {
	if ((state & 3) != 3) return -1;
	uint8_t *buf = mem->get_ptr(pos);
	if (buf == NULL) return -2;
	size_t left = mem->space(pos);
	if (last) cs_free(last, nlast);
	last = cur;
	nlast = ncur;
	if (nxt) {
		cur = nxt;
		ncur = nnxt;
	} else {
		ncur = cs_disasm(han, buf, left, pos, disnum, &cur);
		if (ncur) {
			pos = cur[ncur - 1].address + cur[ncur - 1].size;
			buf = mem->get_ptr(pos);
			if (buf == NULL)
				return 0;
			left = mem->space(pos);
		} else {
			if (cur) cs_free(cur, ncur);
			cur = NULL;
			return -3;
		}
	}
	nnxt = cs_disasm(han, buf, left, pos, disnum, &nxt);
	if (nnxt == 0) {
		if (nxt) cs_free(nxt, nnxt);
		return 0;
	}
	pos = nxt[nnxt - 1].address + nxt[nnxt - 1].size;
	return 0;
}

void dishlp::set_mem(std::shared_ptr<memhlp> memory) {
	mem = memory;
	if(mem != NULL)
		state |= 1;
	else
		state &= ~1;
}

size_t dishlp::get_cur(cs_insn **ptr) {
	*ptr = cur;
	return ncur;
}

size_t dishlp::get_last(cs_insn **ptr) {
	*ptr = last;
	return nlast;
}

int is_reg_match(x86_reg hay, x86_reg needle, int strict) {
	if (strict) return hay == needle;
	switch (hay) {
		case X86_REG_AH:
		case X86_REG_AL:
		case X86_REG_AX:
		case X86_REG_EAX:
		case X86_REG_RAX:
			return needle == X86_REG_EAX || needle == X86_REG_RAX;
		case X86_REG_BH:
		case X86_REG_BL:
		case X86_REG_BX:
		case X86_REG_EBX:
		case X86_REG_RBX:
			return needle == X86_REG_EBX || needle == X86_REG_RBX;
		case X86_REG_CH:
		case X86_REG_CL:
		case X86_REG_CX:
		case X86_REG_ECX:
		case X86_REG_RCX:
			return needle == X86_REG_ECX || needle == X86_REG_RCX;
		case X86_REG_DH:
		case X86_REG_DL:
		case X86_REG_DX:
		case X86_REG_EDX:
		case X86_REG_RDX:
			return needle == X86_REG_EDX || needle == X86_REG_RDX;
		default:
			return needle == hay;
	}
}

cs_insn *dishlp::trace_back(cs_insn *ins, x86_reg reg, uint64_t limit) {
	cs_insn *base;
	if (0 == get_buf(ins, &base)) return NULL;

	if (ins != base) ins--;
	else {
		size_t num = last_buf(&base);
		if (!base || num == 0)
			return NULL;
		ins = base + num - 1;
	}

	for (; ins >= base && ins->id == X86_INS_MOV; ins--) {
		if (limit && is_sel_mem(ins->detail->x86.operands + 1, limit)) break;
		if (OP(ins, 0).type == X86_OP_REG &&
		    is_reg_match(OP(ins, 0).reg, reg, 0)) {
			if (OP(ins, 1).type == X86_OP_REG)
				reg = OP(ins, 1).reg;
			else
				return ins;
		}
		if (ins == base) {
			size_t num = last_buf(&base);
			// no off by one here it will be decremented before next loop exec
			ins = last + num;
		}
	}
	std::cerr << "Hit limit looking for " << get_name(reg) << std::endl;
	return NULL;
}

std::vector<cs_insn *> dishlp::trace_fwd(cs_insn *ins, x86_reg reg) {
	std::vector<cs_insn*> ret;
	std::unordered_set<x86_reg, std::hash<unsigned int> > regs;

	size_t num, i;
	cs_insn *base;

	num = get_buf(ins, &base);
	if (num == 0) return ret;

	regs.emplace(reg);
	i = ins - base + 1;
	while (!regs.empty()) {
		if (i == num) {
			num = next_buf(&base);
			i = 0;
			if (num == 0 || !base) return ret;
		}
		if (base[i].id != X86_INS_MOV) return ret;
		if (is_ill_ins(base + i)) return ret;
		if (base[i].detail->x86.operands[0].type == X86_OP_REG) {
			if (base[i].detail->x86.operands[1].type == X86_OP_REG &&
			    regs.count(base[i].detail->x86.operands[1].reg)) {
				regs.emplace(base[i].detail->x86.operands[0].reg);
				ret.push_back(base + i);
			} else
				regs.erase(base[i].detail->x86.operands[0].reg);
		}

		for (int a = 0; a < 2; a++) {
			cs_x86_op *op = base[i].detail->x86.operands + a;
			if (op->type == X86_OP_MEM &&
			    (regs.count((x86_reg) op->mem.index) ||
			    regs.count((x86_reg) op->mem.base))) {
				ret.push_back(base + i);
				continue;
			}
		}
		i++;
	}
	return ret;
}

size_t dishlp::get_buf(cs_insn *ins, cs_insn **base) {
	if (cur && ins >= cur && ins < (cur + ncur)) {
		*base = cur;
		return ncur;
	}
	if (last && ins >= last && ins < (last + nlast)) {
		*base = last;
		return nlast;
	}
	if (nxt && ins >= nxt && ins < (nxt + nnxt)) {
		*base = nxt;
		return nnxt;
	}
	return 0;
}

size_t dishlp::last_buf(cs_insn **base) {
	if (*base == nxt && cur) {
		*base = cur;
		return ncur;
	}
	if (*base == cur && last) {
		*base = last;
		return nlast;
	}
	*base = NULL;
	return 0;
}

size_t dishlp::next_buf(cs_insn **base) {
	if (*base == last && cur) {
		*base = cur;
		return ncur;
	}
	if (*base == cur && nxt) {
		*base = nxt;
		return nnxt;
	}
	*base = NULL;
	return 0;
}

void dishlp::set_disnum(size_t num) {
	disnum = num;
}

cs_insn *dishlp::trace_mem(cs_insn *ins, uint64_t addr, uint64_t limit, bool ign) {
	cs_insn *base;
	size_t num, i;

	if (!ign && mem->has_sym_to(addr)) {
		// std::cout << "trace sym: " << mem->get_sym_name(mem->get_sym(addr)) << std::endl;
		return NULL;
	}

	num = get_buf(ins, &base);
	i = ins - base;

	if (i == 0) {
		num = last_buf(&base);
		i = num - 1;
	}

	while (num && base[i].id == X86_INS_MOV) {
		if (OP(base + i, 0).type == X86_OP_MEM &&
		    ((uint64_t) OP(base + i, 0).mem.disp) == addr)
			return base + i;
		if (limit && OP(base + i, 0).type == X86_OP_MEM &&
		    ((uint64_t) OP(base + i, 0).mem.disp) == limit)
			break;
		if (i == 0) {
			num = last_buf(&base);
			i = num;
		}
		i--;
	}
	std::cerr << std::hex;
	std::cerr << "Hit limit looking for 0x" << addr << std::endl;
	return NULL;
}

cs_insn *dishlp::trace_mem_fwd(cs_insn *ins, uint64_t addr) {
	cs_insn *base;
	size_t num, i;

	num = get_buf(ins, &base);
	i = ins - base + 1;

	if (i == num) {
		num = next_buf(&base);
		i = 0;
	}

	while (num && base[i].id == X86_INS_MOV && !is_ill_ins(base + i)) {
		if (OP(base + i, 1).type == X86_OP_MEM &&
		    (addr == (uint64_t) OP(base + i, 1).mem.disp ||
		    addr - 4 == (uint64_t) OP(base + i, 1).mem.disp))
			return base + i;
		if (OP(base + i, 0).type == X86_OP_MEM &&
		    (addr == (uint64_t) OP(base + i, 0).mem.disp ||
		    addr - 4 == (uint64_t) OP(base + i, 0).mem.disp))
			return base + i;
		if (i == num - 1) {
			num = next_buf(&base);
			i = 0;
		} else
			i++;
	}
	return NULL;
}

dishlp::~dishlp() {
	if (last) cs_free(last, nlast);
	if (cur) cs_free(cur, ncur);
}
