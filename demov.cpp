#include <elf.h>
#include <sstream>
#include <iostream>
#include <cstring>
#include <vector>
#include <algorithm>
#include <iterator>
#include "demov.hpp"

uint8_t p[5] = {0x90, 0x90, 0x90, 0x90, 0x90};

void dump_ins(cs_insn *ins) {
	std::cout << ins->mnemonic << " " << ins->op_str << std::endl;
}

std::string demov::dump_syms() {
	return mem->dump_syms();
}

demov::demov(void) 
{
	mem = std::make_shared<memhlp>();
}

demov::~demov(void) {
	if (state & ST_INIT)
		cs_close(&handle);
}

void demov::set_relocations(std::unordered_map<uint64_t, std::string> *rels) {
	this->relocations = rels;
	state |= ST_REL;
}

void demov::set_segments(std::map<uint64_t,
                         std::tuple<uint8_t *, uint64_t, int>> *segs){
	mem->set_segments(segs);
	state |= ST_SEG;
}

void demov::set_entrypoint(uint64_t address) {
	entrypoint = address;
}

void demov::set_patch_call(bool b) {
	ash.set_patch_call(b);
}



int demov::init() {
	if (!cs_support(CS_ARCH_X86))
		return -1;
	if (CS_ERR_OK != cs_open(CS_ARCH_X86, CS_MODE_32, &handle))
		return -2;
	if (CS_ERR_OK != cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON)){
		cs_close(&handle);
		return -3;
	}
	dis.init(handle);
	dis.set_mem(mem);
	ash.set_mem(mem);
	state |= ST_INIT;
	flags = 0;
	return 0;
}

std::string* demov::get_call_target(cs_insn *ins) {
	cs_insn *tmp;
	uint64_t target;
	size_t size;
	uint8_t *code;

	if (ins->detail->x86.op_count != 1) return NULL;
	if (ins->detail->x86.operands[0].type != X86_OP_IMM) {
		std::cerr << "option type missmatch, expacted 2, got ";
		std::cerr << ins->detail->x86.operands[0].type << std::endl;
		return NULL;
	}
	target = ins->detail->x86.operands[0].imm;
	if (!mem->is_X(target)) {
		std::cerr << "plt not executable" << std::endl;
		return NULL;
	}
	code = mem->get_ptr(target);
	tmp = cs_malloc(handle);
	size = mem->space(target);
	if (!cs_disasm_iter(handle,(const uint8_t**) &code, &size, &target, tmp)) {
		std::cerr << "error disassambling plt" << std::endl; return NULL;
	}
	if (tmp->id != X86_INS_JMP || !is_dir_mem(tmp->detail->x86.operands, 0)) {
		std::cerr << "plt entry missmatch" << std::endl; return NULL;
	}
	auto rel = relocations->find((uint64_t) tmp->detail->x86.operands[0].mem.disp);
	if (rel == relocations->end()) {
		std::cerr << "relocation not found" << std::endl; return NULL;
	}
	cs_free(tmp, 1);
	return &rel->second;
}

int demov::analyse_sigaction(cs_insn *ins, size_t num, uint32_t **ret) {
	uint64_t ret_mem = 0;
	int sig = -1;
	size_t cur;
	// TODO [low] add support for chained write
	for (cur = num - 1; (sig == -1 || ret_mem == 0); cur--) {
		if(ins[cur].id != X86_INS_MOV) return -1;
		if(ins[cur].detail->x86.operands[0].type != X86_OP_MEM ||
		   (x86_reg) ins[cur].detail->x86.operands[0].mem.base != X86_REG_ESP ||
		   (x86_reg) ins[cur].detail->x86.operands[0].mem.index != X86_REG_INVALID ||
		   ins[cur].detail->x86.operands[1].type != X86_OP_IMM)
			continue;
		if(ins[cur].detail->x86.operands[0].mem.disp == 0 && sig == -1)
			sig = (int) OP(ins + cur, 1).imm;
		if(ins[cur].detail->x86.operands[0].mem.disp == 4 && ret_mem == 0)
			ret_mem = OP(ins + cur, 1).imm;
		if (cur == 0) break;
	}
	if (mem->get_data(ret_mem, ret)) return -2;
	return sig;
	//TODO
}

cs_insn *find_origin(cs_insn *ins, size_t st, unsigned int reg) {
	std::vector<std::string> trace;
	for (;;st--) {
		if (ins[st].id != X86_INS_MOV) return NULL;
		if (ins[st].detail->x86.operands[0].type == X86_OP_REG &&
		    ins[st].detail->x86.operands[0].reg == reg) {
			std::string tmp = std::string(ins[st].mnemonic);
			tmp += std::string(" ") + std::string(ins[st].op_str);
			trace.push_back(tmp);
			if (ins[st].detail->x86.operands[1].type == X86_OP_REG)
				reg = ins[st].detail->x86.operands[1].reg;
			else {
				while (!trace.empty())
					std::cout << trace.back() << std::endl, trace.pop_back();
				return &ins[st];
			}
		}
		if (!st) return NULL;
	}
}

int demov::find_on(cs_insn *ins, size_t num) {
	size_t c = 0, i = 0;
	if (flags & MOV_EXTERN) c++;
	if (flags & MOV_LOOP) c++;
	for (i = 0; c>0; i++) {
		if (cs_insn_group(handle, ins + i, CS_GRP_CALL)) c--;
	}
	
	i++;
	if (!(state & ST_LOOP)) {
		std::cerr << "guessing master loop to be at 0x" << std::hex;
		master_loop = ins[i].address;
		std::cerr << master_loop << std::dec << std::endl;
		state |= ST_LOOP;
	}

	for (; i < num; i++) {
		if (ins[i].id != X86_INS_MOV) continue;
		if (is_sel_mem(&(ins[i].detail->x86.operands[1]), 0)){
			uint32_t *val;
			cs_insn *tmp = dis.trace_back(ins + i,
			                              ins[i].detail->x86.sib_index, 0);
			if (tmp == NULL) return -1;
			if (!is_dir_mem(&(tmp->detail->x86.operands[1]), 0)) return -2;
			if (mem->get_data((uint64_t) tmp->detail->x86.operands[1].mem.disp,
			                  &val))
				return -3;
			if (*val != 1) return -4;
			sel_on = (uint64_t) ins[i].detail->x86.disp;
			std::cout << "sel_on is at " << std::hex << sel_on << std::endl;
			mem->add_sym(sel_on, SYM_SEL_ON);
			if (mem->get_data(sel_on + 4, &val)) return -5;
			on = *((uint64_t *) val);
			std::cout << "on is at " << on << std::dec << std::endl;
			mem->add_sym(on, SYM_ON);
			return 0;
		}
	}
	return -1;
}


int demov::parse_entry() {
	cs_insn *ins;
	size_t num, i;
	uint32_t *ptr;
	uint64_t sesp = 0;
	if ((ST_REL | ST_SEG | ST_INIT) != (state & (ST_REL | ST_SEG | ST_INIT)))
		return -1;
	if (dis.go_to(entrypoint)) return -2;
	if (dis.next()) return -3;
	num = dis.get_cur(&ins);
	//TODO stuff
	for (i = 0; i < num; i++) {
		if (!sesp && ins[i].id == X86_INS_MOV ) {
			cs_x86_op *op = ins[i].detail->x86.operands;
			if (is_dir_mem(op, 0) && op[1].reg == X86_REG_ESP)
				sesp = (uint64_t) op[0].mem.disp;
		}

		// skip non movs (just if someone patched the binary)
		if (ins[i].id == X86_INS_NOP) continue;

		// find the stack pointer
		// it is the only place that writes to esp
		if (OP(ins + i, 0).type == X86_OP_REG &&
		    OP(ins + i, 0).reg == X86_REG_ESP &&
			is_dir_mem(&OP(ins + i, 1),0)) {
			stackp = (uint32_t) OP(ins + i, 1).mem.disp;
			mem->add_sym(stackp, SYM_SP);
		}

		// find the calls that set up the environment
		if (cs_insn_group(handle, ins + i, CS_GRP_CALL)) {
			uint8_t* call_ptr = mem->get_ptr(ins[i].address);
			std::string *func = get_call_target(ins+i);
			int signum;
			if (strncmp("sigaction", func->c_str(), strlen("sigaction")))
				continue;
			// found a call (to sigaction), taint analysis to find parameter
			signum = analyse_sigaction(ins, i, &ptr);
			std::cout << std::hex;
			if (signum == SIGSEGV) {
				std::cout << "dispatcher at 0x";
				std::cout << *ptr << std::endl;
				mem->add_sym(*ptr, SYM_DISPATCH);
				flags |= MOV_EXTERN;
			}
			if (signum == SIGILL) {
				master_loop = (uint64_t) *ptr;
				std::cout << "master_loop is at 0x" << master_loop << std::endl;
				flags |= MOV_LOOP;
				state |= ST_LOOP;
			}
			std::cout << std::dec;
			memcpy(call_ptr, p, 5);

		}
		// once sesp is wirtten to the sigaction initialization is over
		if (sesp && is_dir_mem(&(ins[i].detail->x86.operands[1]), sesp))
			break;
	}
	if (find_on(ins, num)) {
		std::cerr << "unable to find on" << std::endl;
		return -4;
	}

	
	for (; i < num; i++) {
		if (OP(ins + i, 1).type == X86_OP_MEM &&
			(x86_reg) OP(ins + i, 1).mem.base != X86_REG_INVALID &&
			(x86_reg) OP(ins + i, 1).mem.index != X86_REG_INVALID &&
			OP(ins + i, 1).mem.scale == 4 && OP(ins + i, 1).mem.disp == 0) {
			cs_insn *a = dis.trace_back(ins + i, (x86_reg) OP(ins + i, 1).mem.base, 0);
			if (!is_sel_mem(&OP(a, 1), 0) ||
			    mem->analyse_table((uint64_t) OP(a, 1).mem.disp, 2) != SYM_ALU_ADD)
				continue;
			cs_insn *x = dis.trace_back(a, (x86_reg) OP(a, 1).mem.index, 0);
			cs_insn *y = dis.trace_back(ins + i, (x86_reg) OP(ins + i, 1).mem.index, 0);
			std::cerr << std::hex;
			if (is_dir_mem(&OP(x, 1), 0))
				std::cerr << "alu_x@" << OP(x, 0).mem.disp << std::endl;
			if (is_dir_mem(&OP(y, 1), 0))
				std::cerr << "alu_y@" << OP(y, 0).mem.disp << std::endl;
			break;
		}
	}



	return 0;
}

void demov::dump_stat() {
	std::cout << std::dec;
	for (auto &x: ac_stat) {
		std::cout << mem->get_sym_name(mem->get_sym(x.first)) << ": ";
		std::cout << x.second << std::endl;
	}
	std::cout << std::hex;
}

void demov::find_fault() {
	uint32_t *dis;
	uint32_t *tmp;
	if (mem->get_data(mem->get_sym_addr(SYM_SEL_DATA), &dis)) return;
	mem->add_sym(*dis, SYM_DISCARD);
	std::cout << "discard at " << *dis << std::endl;
	for (auto &x: ac_array) {
		if (mem->has_sym_to(x.first)) continue;
		if (mem->get_data(x.first, &tmp)) continue;
		if (*tmp != *dis && tmp[1] == 0 && mem->get_ptr(*tmp)) {
			mem->add_sym(x.first, SYM_FAULT);
			break;
		}
	}
}

int demov::scan() {
	cs_insn *ins;
	size_t num, i;
	uint64_t tmp;
	int run = 1;
	if ((ST_SEG | ST_INIT) != (state & (ST_SEG | ST_INIT)))
		return -1;
	if (dis.go_to(entrypoint)) return -2;

	// sweep over entire executable code
	while(0 == dis.next() && run) {
		num = dis.get_cur(&ins);
		enum symbl s;
		if (!num) return -3;
		for (i = 0; i < num; i++) {
			if (cs_insn_group(handle, ins + i, CS_GRP_JUMP) ||
				cs_insn_group(handle, ins + i, CS_GRP_CALL) ||
				cs_insn_group(handle, ins + i, CS_GRP_RET) ||
				ins[i].id == X86_INS_CMP || ins[i].id == X86_INS_NOP)
				continue;
			if (ins[i].id != X86_INS_MOV) {
				std::cout << "found non-mov instruction: " << std::endl;
				std::cout << ins[i].mnemonic << " " << ins[i].op_str << std::endl;
				return -1;
			}

			if (is_ill_ins(ins + i)) {
				end = (ins + i)->address;
				mem->add_sym(end, SYM_END);
				state |= ST_END;
				std::cout << "reached end" << std::endl;
				run = 0;
				break;
			}

			if (is_dir_mem(&OP(ins + i, 1), 0)) {
				ac_dir_r[(uint64_t) OP(ins + i, 1).mem.disp] += 1;
				continue;
			}

			if (is_dir_mem(&OP(ins + i, 0), 0)) {
				ac_dir_w[(uint64_t) OP(ins + i, 0).mem.disp] += 1;
				continue;
			}

			if (OP(ins + i, 1).type != X86_OP_MEM ||
			    OP(ins + i, 1).mem.disp == 0)
				continue;

			s = mem->get_sym(OP(ins + i, 1).mem.disp);
			if (s == SYM_INVALID)
				s = mem->analyse_table((uint64_t) OP(ins + i, 1).mem.disp, 1);
			if (s == SYM_INVALID)
				s = mem->analyse_table((uint64_t) OP(ins + i, 1).mem.disp, 2);
			if (s == SYM_INVALID)
				ac_array[OP(ins + i, 1).mem.disp] += 1;
			else
				ac_stat[OP(ins + i, 1).mem.disp] += 1;
		}

	}
	std::cout << std::hex;
	i = 0;
	int64_t spmov1 = 0, spmov2 = 0;

	for (auto &x: ac_array) {
		if (i < x.second && !(x.first & 0x8000000000000000)) {
			tmp = x.first;
			i = x.second;
		} else if (x.first & 0x8000000000000000) {
			if (spmov1)
				spmov2 = (int64_t) x.first;
			else
				spmov1 = (int64_t) x.first;
		}
		//std::cout << "0x" << x.first << ": 0x" << x.second << std::endl;
	}

	if (spmov1 && spmov2) {
		int32_t tmpl;
		if (spmov1 > spmov2) {
			tmpl = spmov1;
			spmov1 = spmov2;
			spmov2 = tmpl;
		}
		mem->add_sym((uint64_t) spmov1, SYM_STP_SUB4);
		mem->add_sym((uint64_t) spmov2, SYM_STP_ADD4);
	}
	if (i) {
		std::cout << "SYM_SEL_DATA@0x" << tmp << " : 0x" << i << std::endl;
		mem->add_sym(tmp, SYM_SEL_DATA);
	}

	i = 0;
	for (auto &x: ac_dir_r) {
		if (!ac_dir_w.count(x.first) && i < x.second) {
			tmp = x.first;
			i = x.second;
		}
	}
	if (i) {
		std::cout << "SYM_ON@0x" << tmp << " : 0x" << i << std::endl;
		mem->add_sym(tmp, SYM_ON);
	}

	i = 0;
	for (auto &x: ac_dir_w) {
		if (!ac_dir_r.count(x.first) && i < x.second) {
			tmp = x.first;
			i = x.second;
		}
	}
	if (i) {
		std::cout << "SYM_DATA@0x" << tmp << " : 0x" << i << std::endl;
		mem->add_sym(tmp, SYM_DATA);
	}
	find_fault();
	return 0;

}

int demov::parse_data() {
	// memory carving
	if (!(state & ST_END)) return -1;
	// 16 byte alligned
	auto seg = mem->get_segment(mem->get_sym_addr(SYM_ALU_EQ));
	uint64_t pos = (((uint64_t) seg->first) + 15) & (~0xF);
	std::cout << "carving memory" << std::endl;
	uint32_t *data;
	bool skip = false;
	while (0 == mem->get_data(pos, &data) && data) {
		if (mem->has_sym_to(pos)) {
			switch(mem->get_sym(pos)) {
				case SYM_BOOL_OR:
				case SYM_BOOL_XOR:
				case SYM_BOOL_AND:
				case SYM_BOOL_XNOR:
					pos += (4 * 2) + (2 * 2 * 4);
				case SYM_BIT_SET:
				case SYM_BIT_CLR:
					pos += (8 * 4) + (8 * 256);
					break;
				case SYM_ALU_AND:
				case SYM_ALU_EQ:
				case SYM_ALU_OR:
				case SYM_ALU_XOR:
				case SYM_ALU_MULL:
				case SYM_ALU_MULH:
					pos += (256 * 4) + (256 * 256);
					break;
				case SYM_ALU_SHL:
				case SYM_ALU_SHR:
				case SYM_ALU_SARI:
					pos += (33 * 4) + (33 * 256 * 4);
					break;
				case SYM_ALU_ADD:
					pos += (65536 * 2 * 4) * 2;
					break;
				default:
					pos += 16;
					break;
			}
			skip = false;
			pos = (pos + 15) & (~0xF);
			continue;
		}
		if (mem->get_ptr(*data)) {
			if (skip || SYM_INVALID == mem->analyse_table(pos, 2))
				pos += 16;
			skip = true;
		} else {
			if (SYM_INVALID == mem->analyse_table(pos, 1)) pos += 16;
			skip = false;
		}
	}
	std::cout << std::hex << "carving memory finished:" << std::endl;
	std::cout << ((seg->first + 15) & (~0xF)) << " - " << pos << std::endl;
	return 0;
}

std::string demov::dump_idc() {
	uint32_t cur;
	std::stringstream ret;
	int d = 0, r = 0;
	auto regtmp = regs;
	ret << std::hex;
	while (!regtmp.empty()) {
		cur = regtmp.back();
		regtmp.pop_back();
		std::vector<uint32_t>::iterator tmp;
		tmp = std::find(regtmp.begin(), regtmp.end(), cur);
		ret << "\tMakeName(0x" << cur << ", \"";
		if (tmp != regtmp.end()) {
			regtmp.erase(tmp);
			ret << "D" << d++ << "\");" << std::endl;
		}
		else
			ret << "R" << r++ << "\");" << std::endl;
	}
	ret << mem->dump_syms_idc();
	return ret.str();
}


void demov::dump_regs() {
	uint32_t cur;
	int d = 0, r = 0;
	auto regtmp = regs;
	std::cout << std::hex;
	while (!regtmp.empty()) {
		cur = regtmp.back();
		regtmp.pop_back();
		std::vector<uint32_t>::iterator tmp;
		tmp = std::find(regtmp.begin(), regtmp.end(), cur);
		if (tmp != regtmp.end()) {
			regtmp.erase(tmp);
			std::cout << "D" << d++ << "@" << cur << std::endl;
		}
		else
			std::cout << "R" << r++ << "@" << cur << std::endl;
	}
}

uint64_t demov::analyse_sel_on(cs_insn *ins) {
	bool on = false;
	bool off = false;
	uint64_t bbstart;
	std::vector<cs_insn *> tr;

	// trace forward to see if it is toggeling on or off
	auto tar = dis.trace_fwd(ins, ins->detail->x86.operands[0].reg);
	for (auto &x: tar) {
		if (is_reg_mem(x->detail->x86.operands, X86_REG_INVALID) &&
			x->detail->x86.operands[1].type == X86_OP_IMM) {
			switch (x->detail->x86.operands[1].imm) {
				case 1:
					on = true;
					bbstart = x->address + x->size;
					break;
				case 0:
					off = true;
					break;
				default:
					return 0;
			}
		}
	}

	/* if (off && !on)
		std::cout << "toggle off" << std::endl; */

	if (off || !on) return 0;

	// only toggel on pass this point
	std::stack<element> st;

	// std::cout << "toggle on from " << ins[0].address << ": "  << ins[0].mnemonic << " " << ins[0].op_str << std::endl;
	// find the condition of the toggle
	dis.trace_back(&st, ins, (x86_reg) OP(ins, 1).mem.index, 0 /*sel_on*/);
	// std::cout << "trace back finished" << std::endl;
	// std::cout << std::hex << "toggle on if" << std::endl;
	if (st.top().type == ELE_MEM && st.size() == 1) {
		// specially for the toggle_execution statement
		dump_elem(&st.top());
	} else {
		uint64_t addr, label;
		st = simplify_stack(st);
		try {
			// get the label from the taint analysis stack
			label = get_label(st, &addr);
			// add it as a possible jump and return target
			jmp_tar.emplace(label, bbstart);
			ret_tar.emplace(bbstart, true);
			// it regs have not been identified
			if (regs.empty()) {
				dis.find_regs(&regs, ins, label);
			}

			if (!target_reg) {
				target_reg = addr;
				mem->add_sym(addr, SYM_TARGET);
			} else
				assert(addr == target_reg);

		} catch (int ex) {
			std::cout << "ERROR: Shit is broken " << ex << std::endl;
		}
		//std::cout << "[ " << addr << "] == " << label << std::endl;
	}
	return 0;
}

void trap() {;}

int demov::analyse() {
	int run = 1;
	if (dis.go_to(master_loop)) return -1;
	cs_insn *ins;
	size_t ncur;

	// first pass: finding all the labels
	while(run && dis.next() == 0) {
		// iterate over all instructions in the buffer
		ncur = dis.get_cur(&ins);
		for (size_t i = 0; i < ncur; i++) {
			if (cs_insn_group(handle, ins + i, CS_GRP_JUMP) ||
				cs_insn_group(handle, ins + i, CS_GRP_CALL) ||
				cs_insn_group(handle, ins + i, CS_GRP_RET) ||
				ins[i].id == X86_INS_CMP || ins[i].id == X86_INS_NOP)
				continue;
			if (ins[i].id != X86_INS_MOV) {
				std::cout << "found non-mov instruction: " << std::endl;
				std::cout << ins[i].mnemonic << " " << ins[i].op_str << std::endl;
				run = 0;
				break;
			}

			if (is_ill_ins(ins + i)) {
				end = ins->address + ins->size;
				mem->add_sym(end, SYM_END);
				state |= ST_END;
				std::cout << "reached end" << std::endl;
				break;
			}

			if (is_sel_mem(&(ins[i].detail->x86.operands[1]), 0)) {
				cs_insn *ins_tmp = dis.trace_mem(ins + i - 1, ins[i].detail->x86.operands[1].mem.disp, 0, true);
				if (ins_tmp != nullptr) {
					ins_tmp = dis.trace_back(ins_tmp, ins_tmp->detail->x86.operands[1].reg, 0);
					if (is_dir_mem(&(ins_tmp->detail->x86.operands[1]), on)) {
						//std::cout << "tracing back on from " << ins[i].address << std::endl;
						analyse_sel_on(ins + i);
					}
				}
			}

			// find the label + jump target register
			if (is_sel_mem(&(ins[i].detail->x86.operands[1]), sel_on)) {
				//std::cout << "tracing back sel_on from " << ins[i].address << std::endl;
				analyse_sel_on(ins + i);
			}
		}
	}

	// output all labels
	mem->add_sym(target_reg, SYM_TARGET);
	std::cout << "target register: " << std::hex << target_reg << std::endl;
	for (auto &i: jmp_tar) {
		ctlelem cele(i.second, i.first);
		ctl.add_elem(cele);
	}

	// second pass: find jumps
	std::cout << "second pass:" << std::endl;
	if (dis.go_to(master_loop)) return -1;
	run = 1;
	while(run && dis.next() == 0) {
		// iterate over instructions buffer
		ncur = dis.get_cur(&ins);
		for (size_t i = 0; i < ncur; i++) {
			if (cs_insn_group(handle, ins + i, CS_GRP_JUMP) ||
				cs_insn_group(handle, ins + i, CS_GRP_CALL) ||
				cs_insn_group(handle, ins + i, CS_GRP_RET) ||
				ins[i].id == X86_INS_CMP || ins[i].id == X86_INS_NOP)
				continue;

			// stop if program end
			if (ins[i].id != X86_INS_MOV|| is_ill_ins(ins + i)) {
				run = 0;
				break;
			}

			// if target is updated
			if (dis.is_sel_target(&OP(ins + i, 1))) {
				uint64_t t;
				if (find_target(ins + i, &t)) continue;
				std::cout << "target updated to 0x" << t << std::endl;
				tar = t;
			}

			// destinglish between jump and return targets
			// return targets are not targeted by jumps
			if (tar && is_sel_mem(&OP(ins + i, 1), sel_on)) {
				cs_insn* tg_off = find_toggle(ins + i, OP(ins + i, 0).reg);
				if (tg_off && ((OP(tg_off, 1).imm & 1) == 0)) {
					auto ele = jmp_tar.find(tar);
					if (ele == jmp_tar.end())
						continue;
					auto bb = ret_tar.find(ele->second);
					bb->second = false;
				}
			}
		}
	}

	std::cout << "third pass:" << std::endl;
	// third pass builds element buffer for graph drawing
	// and patches the binary
	if (dis.go_to(master_loop)) return -1;
	run = 1;
	// iterate over program
	while(run && dis.next() == 0) {
		ncur = dis.get_cur(&ins);
		for (size_t i = 0; i < ncur; i++) {
			if (cs_insn_group(handle, ins + i, CS_GRP_JUMP) ||
				cs_insn_group(handle, ins + i, CS_GRP_CALL) ||
				cs_insn_group(handle, ins + i, CS_GRP_RET) ||
				ins[i].id == X86_INS_CMP || ins[i].id == X86_INS_NOP)
				continue;
			// stop if program end
			if (ins[i].id != X86_INS_MOV || is_ill_ins(ins + i)) {
				state |= ST_ANLY;
				return 0;
			}

			// continusly update the jump target
			if (dis.is_sel_target(&OP(ins + i, 1))) {
				uint64_t t;
				if (find_target(ins + i, &t)) continue;
				tar = t;
			}

			// if toggle off
			if (is_sel_mem(&OP(ins + i, 1), sel_on)) {
				cs_insn* tg_off = find_toggle(ins + i, OP(ins + i, 0).reg);
				if (tg_off && ((OP(tg_off, 1).imm & 1) == 0)) {
					std::stack<element> st;
					// search backwards
					if (dis.trace_back(&st, ins + i,
									   (x86_reg) OP(ins + i, 1).mem.index, sel_on))
						throw 6;
					// if toggle is unconditional
					if (st.top().type == ELE_MEM &&
					    mem->get_sym((uint64_t) st.top().mem.disp) == SYM_ON) {
						// if jump target is known (not ret / indirect)
						if (tar) {
							// find next label
							auto ele = ret_tar.upper_bound(tg_off->address);
							// if it is a return target
							if (ele != ret_tar.end() && ele->second) {
								auto tar_ad = jmp_tar.find(tar);
								//add element
								if (tar_ad != jmp_tar.end()) {
									ctlelem ctele(CTL_CALL, tg_off->address,
									              tar_ad->second);
									ctl.add_elem(ctele);
								}
								patch_call(tg_off, tar);
							} else {
								// next label is not a return target
								// therfor it is only a jump
								auto tar_ad = jmp_tar.find(tar);
								if (tar_ad != jmp_tar.end()) {
									ctlelem ctele(CTL_JMP, tg_off->address,
									              tar_ad->second);
									ctl.add_elem(ctele);
								}
								patch_jmp(tg_off, tar);
							}
						} else {
							// either ret / indirect jmp
							ctlelem ctele(CTL_RET, tg_off->address);
							ctl.add_elem(ctele);
							patch_ret(tg_off);
						}
					} else {
						// toggle is conditional
						assert(tar);
						auto tar_ad = jmp_tar.find(tar);
						if (tar_ad != jmp_tar.end()) {
							ctlelem ctele(CTL_JCC, tg_off->address,
							              tar_ad->second);
							ctl.add_elem(ctele);
						}
						patch_jcc(ins + i, tg_off, tar);
					}
				}
			}
		}
	}
	state |= ST_ANLY;
	return 0;
}

std::string demov::dump_flow() {
	if (! (state & ST_ANLY)) return std::string("");
	state |= ST_CTANLY;
	return ctl.analyse();
}

std::vector<std::pair<uint32_t, uint32_t>> demov::get_blocks() {
	return ctl.get_blocks();
}

std::string demov::dump_calls() {
	if (! (state & ST_CTANLY)) return std::string("");
	return ctl.dump_calls();
}

int demov::patch_jmp(cs_insn *tg, uint64_t tar, uint8_t OP) {
	assert(tg->size >= 5);
	uint32_t rip = (uint32_t) tg->address + 5;
	uint8_t *pt = mem->get_ptr(tg->address);
	uint32_t *off = (uint32_t *) (pt + 1);
	uint32_t dist = ((uint32_t) jmp_tar.find(tar)->second) - rip;
	//jmp relativ
	*pt = OP;
	//jmp distance
	*off = dist;
	for (int i = 5; i < tg->size; i++) 
		pt[i] = 0x90;
	return 0;
}

int demov::patch_call(cs_insn *tg, uint64_t tar) {
	uint8_t *ptr = mem->get_ptr(tg->address);
	uint32_t ret = (uint32_t) ret_tar.upper_bound(tg->address)->first;
	uint32_t rip = tg->address;
	uint32_t *sp = (uint32_t*) (ptr + 2);
	uint32_t ct = ((uint32_t) jmp_tar.find(tar)->second);
	// mov esp, [sp]
	ptr[0] = 0x8b;
	ptr[1] = 0x25;
	sp[0] = stackp;
	// pop eax
	ptr[6] = 0x58;
	// call tar
	ptr[7] = 0xE8;
	sp = (uint32_t*) (ptr + 8);
	*sp = ct - (rip + 12);
	// jmp ret
	ptr[0xC] = 0xE9;
	sp = (uint32_t*) (ptr + 0xD);
	*sp = ret - (rip + 17);
	return 0;
}

int demov::patch_ret(cs_insn *tg) {
	assert(tg->size >= 6);
	uint8_t *ptr = mem->get_ptr(tg->address);
	// ret so the other programs can work with it
	ptr[0] = 0xff;
	ptr[1] = 0x25;
	uint32_t *pt32 = (uint32_t*) (ptr + 2);
	*pt32 = (uint32_t) target_reg;
	for (int i = 6; i < tg->size; i++)
		ptr[i] = 0x90;
	return 0;
}

int demov::patch_jcc(cs_insn *sel, cs_insn *tg, uint64_t tar) {
	assert(sel->size >= 2 && tg->size >= 6);
	uint8_t *tst_cd = test_patch((x86_reg) OP(sel, 1).mem.index);
	uint8_t *buf = mem->get_ptr(sel->address);
	uint32_t rip = tg->address + 6;
	buf[0] = tst_cd[0];
	buf[1] = tst_cd[1];
	for (int i = 2; i < sel->size; i++)
		buf[i] = 0x90;
	buf = mem->get_ptr(tg->address);
	//opcode jne label
	buf[0] = 0x0f;
	buf[1] = 0x85;
	uint32_t *target = (uint32_t *) (buf + 2);
	uint32_t dif = ((uint32_t) jmp_tar.find(tar)->second) - rip;
	*target = dif;
	for (int i = 6; i < tg->size; i++)
		buf[i] = 0x90;
	return 0;
}

cs_insn* demov::find_toggle(cs_insn *i, x86_reg reg) {
	auto tr = dis.trace_fwd(i, reg);
	cs_insn *ret = NULL;
	for (auto &x: tr) {
		if (is_reg_mem(&OP(x, 0), X86_REG_INVALID) && OP(x, 1).type == X86_OP_IMM)
			ret = x;
	}
	return ret;
}

int demov::do_switch(cs_insn *ins){
	std::cerr << "indirect jump found proceed with caution:" << std::endl;
	std::stack<element> st;
	dump_ins(ins);
	if (dis.trace_back(&st, ins, OP(ins, 1).reg, sel_on))
		return -1;
	while (!st.empty()) {
		dump_elem(&st.top());
		st.pop();
	}

	return 0;
}

/**
 * traces forward to see what will be writen to the memory location
 * pointed by the immidiate in the 2nd operand
 * @param instruction with the 2nd operands beeing an immidiate
 */
int demov::find_target(cs_insn *ins, uint64_t *tar) {
	int ret = -1;
	if (is_dir_mem(&OP(ins, 0), 0)) {
		cs_insn *i = dis.trace_mem_fwd(ins, (uint64_t) OP(ins, 0).mem.disp);
		if (i && is_sel_mem(&OP(i, 1), 0)) {
			return find_target(i, tar);
		}
	} else {
		auto res = dis.trace_fwd(ins, OP(ins, 0).reg);
		for (auto &x: res) {
			if (is_reg_mem(&OP(x, 0), X86_REG_INVALID)) {
				if (OP(x, 1).type == X86_OP_IMM)
					*tar = OP(x, 1).imm;
				else {
					std::stack<element> st;
					if (dis.trace_back(&st, x, OP(x, 1).reg, sel_on))
						continue;
					if (st.top().type == ELE_CONST)
						*tar = st.top().imm;
					else {
						if (!is_ret(st))
							do_switch(x);
						*tar = 0;
					}
				}
				ret = 0;
			} else {
				std::cout << "no idea what to do" << std::endl;
				dump_ins(x);
			}
		}
	}
	return ret;
}

int demov::resub(uint64_t start, uint64_t length) {
	cs_insn *ins;
	uint64_t on_addr;
	size_t num;

	if (dis.disasm(start, length)) return -1;
	std::cout << std::hex;
	std::cout << "resub block: << 0x" << start << ", length: 0x" << length;
	std::cout << std::endl;
	num = dis.get_cur(&ins);

	on_addr = mem->get_sym_addr(SYM_ON);

	do {
		num--;
		if (is_dir_mem(&OP(ins + num, 1), on_addr)) {
			ash.replace(ins + num, NULL, SYM_ON);
			continue;
		}
		if (OP(ins + num, 1).type == X86_OP_MEM) {
			if (mem->has_sym_to((uint64_t) OP(ins + num, 1).mem.disp)) {
				if (ash.replace(ins + num, dis.nxt_insn(ins + num),
				            mem->get_sym((uint64_t) OP(ins + num, 1).mem.disp)) == 0) {
					auto f = dis.trace_fwd(ins + num, OP(ins + num, 0).reg);
					if (f.size() != 1) continue;
					ash.replace(ins + num, f[0], mem->get_sym((uint64_t)
								OP(ins + num, 1).mem.disp));
				}
			}
		}
	} while (num > 0);

	return 0xBAD;
}
