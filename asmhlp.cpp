#include <sstream>
#include <keystone/keystone.h>
#include "asmhlp.hpp"
#include "dishlp.hpp"
#include "utils.hpp"


int valid_for_replace_long(x86_reg reg) {
	switch(reg) {
		case X86_REG_EAX:
		case X86_REG_EBX:
		case X86_REG_ECX:
		case X86_REG_EDX:
			return 1;
		default:
			return 0;
	}
}

asmhlp::asmhlp() {
	ks_open(KS_ARCH_X86, KS_MODE_LITTLE_ENDIAN | KS_MODE_32, &eng);
}

asmhlp::~asmhlp() {
	ks_close(eng);
}

void asmhlp::set_mem (std::shared_ptr<memhlp> mem) {
	this->mem = mem;
}

int asmhlp::replace(cs_insn *i, cs_insn *nxt, enum symbl sym) {
	std::stringstream str;
	int valid = 1;
	uint8_t *enc;
	cs_insn *tar = i;
	cs_insn *nop = NULL;
	size_t size;
	size_t stat_cnt;
	if (nxt && OP(nxt, 1).type == X86_OP_MEM &&
	    OP(nxt, 1).mem.disp == 0 &&
	    OP(nxt, 1).mem.base == OP(i, 0).reg &&
	    OP(nxt, 1).mem.index != X86_REG_INVALID)
		valid = 2;
	str << std::hex;
	switch (sym) {
		case SYM_BOOL_AND:
		case SYM_ALU_AND:
			if (valid == 1) return 0;
			str << "mov " << get_name(get_32bit(OP(nxt, 0).reg)) << ", ";
			if (OP(i, 1).mem.base != X86_REG_INVALID)
				str << get_name(OP(i, 1).mem.base);
			else
				str << get_name(OP(i, 1).mem.index);
			str << "; and " << get_name(get_32bit(OP(nxt, 0).reg));
			str << ", " << get_name(OP(nxt, 1).mem.index);
			nop = nxt;
			break;
		case SYM_BOOL_OR:
		case SYM_ALU_OR:
			if (valid == 1) return 0;
			str << "mov " << get_name(get_32bit(OP(nxt, 0).reg)) << ", ";
			if (OP(i, 1).mem.base != X86_REG_INVALID)
				str << get_name(OP(i, 1).mem.base);
			else
				str << get_name(OP(i, 1).mem.index);
			str << "; or " << get_name(get_32bit(OP(nxt, 0).reg));
			str << ", " << get_name(OP(nxt, 1).mem.index);
			nop = nxt;
			break;
		case SYM_BOOL_XOR:
		case SYM_ALU_XOR:
			if (valid == 1) return 0;
			str << "mov " << get_name(get_32bit(OP(nxt, 0).reg)) << ", ";
			if (OP(i, 1).mem.base != X86_REG_INVALID)
				str << get_name(OP(i, 1).mem.base);
			else
				str << get_name(OP(i, 1).mem.index);
			str << "; xor " << get_name(get_32bit(OP(nxt, 0).reg));
			str << ", " << get_name(OP(nxt, 1).mem.index);
			nop = nxt;
			break;
		case SYM_STP_ADD4:
			str << "lea " << get_name(OP(i, 0).reg) << ", [";
			if (OP(i, 1).mem.base != X86_REG_INVALID)
				str << get_name(OP(i, 1).mem.base);
			else
				str << get_name(OP(i, 1).mem.index);
			str << " + 4]";
			break;
		case SYM_STP_SUB4:
			str << "lea " << get_name(OP(i, 0).reg) << ", [";
			if (OP(i, 1).mem.base != X86_REG_INVALID)
				str << get_name(OP(i, 1).mem.base);
			else
				str << get_name(OP(i, 1).mem.index);
			str << " - 4]";
			break;
		case SYM_ALU_INV8:
		case SYM_ALU_INV16:
			nxt = NULL;
			if (OP(i, 1).mem.base != X86_REG_INVALID &&
			    OP(i, 1).mem.index != X86_REG_INVALID) {
				str << "lea " << get_name(get_32bit(OP(nxt, 0).reg));
				str << ", [" << get_name(OP(i, 1).mem.base);
				str << " + " << get_name(OP(i, 1).mem.index);
				str << "]; ";
			} else if (OP(i, 1).mem.base != X86_REG_INVALID) {
				str << "mov " << get_name(get_32bit(OP(i, 0).reg));
				str << ", " << get_name(OP(i, 1).mem.base) << "; ";
			} else {
				str << "mov " << get_name(get_32bit(OP(i, 0).reg));
				str << ", " << get_name(OP(i, 1).mem.index) << "; ";
			}
			str << "not " << get_name(OP(i, 0).reg);
			break;
		case SYM_ALU_B7:
			nxt = NULL;
			if (OP(i, 1).mem.base != X86_REG_INVALID &&
			    OP(i, 1).mem.index != X86_REG_INVALID) {
				str << "lea " << get_name(get_32bit(OP(nxt, 0).reg));
				str << ", [" << get_name(OP(i, 1).mem.base);
				str << " + " << get_name(OP(i, 1).mem.index);
				str << "]; ";
			} else if (OP(i, 1).mem.base != X86_REG_INVALID) {
				str << "mov " << get_name(get_32bit(OP(i, 0).reg));
				str << ", " << get_name(OP(i, 1).mem.base) << "; ";
			} else {
				str << "mov " << get_name(get_32bit(OP(i, 0).reg));
				str << ", " << get_name(OP(i, 1).mem.index) << "; ";
			}
			str << "shr " << get_name(OP(i, 0).reg) << ", 7";
			break;
		case SYM_ALU_ADD:
			if (valid == 1) return 0;
			str << "lea " << get_name(get_32bit(OP(nxt, 0).reg));
			str << ", [" << get_name(OP(i, 1).mem.index);
			str << " + " << get_name(OP(nxt, 1).mem.index);
			str << "]";
			tar = nxt;
			nop = i;
			break;
		case SYM_ON:
			str << "mov " << get_name(OP(i, 0).reg) << ", 1";
			break;
		case SYM_FAULT:
			if (!(is_reg_mem(&OP(nxt, 0), X86_REG_INVALID) &&
			    OP(nxt, 0).mem.base == OP(i, 0).reg) &&
			    !(is_reg_mem(&OP(nxt, 1), X86_REG_INVALID) &&
			    OP(nxt, 1).mem.base == OP(i, 0).reg))
				return 0;
			if (pc)
				str << "call 0x";
			else
				str << "jmp 0x";

			str <<  mem->get_sym_addr(SYM_DISPATCH);
			nop = nxt;
			break;
		default:
			return 0;
	}
	/*if (sym == SYM_ALU_ADD) {
		std::cout << "REPLACE: " << std::endl;
		std::cout << i->mnemonic << " " << i->op_str << std::endl;
		if (nxt)
			std::cout << nxt->mnemonic << " " << nxt->op_str << std::endl;
		std::cout << str.str() << std::endl;
	}*/
	if (ks_asm(eng, str.str().c_str(), tar->address, &enc, &size, &stat_cnt)) return 0;
	if (tar->size >= size) {
		memcpy(mem->get_ptr(tar->address), enc, size);
		memset(mem->get_ptr(tar->address) + size, 0x90, tar->size - size);
	}

	if (nop) 
		memset(mem->get_ptr(nop->address), 0x90, nop->size);

	ks_free(enc);
	return size;
}

void asmhlp::set_patch_call(bool b) {
	pc = b;
}
