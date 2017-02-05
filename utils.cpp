#include <string>
#include <iostream>
#include "stackMachine.hpp"
#include "utils.hpp"


char names[][4] = {"eax", "ebx", "ecx", "edx",
	"ax", "bx", "cx", "dx", "al", "ah", "bl", "bh",
	"cl", "ch", "dl", "dh", "err"};

char* get_name(unsigned int reg) {
	char *ret;
	switch ((x86_reg) reg) {
		case X86_REG_EAX:
			ret = names[0];
			break;
		case X86_REG_EBX:
			ret = names[1];
			break;
		case X86_REG_ECX:
			ret = names[2];
			break;
		case X86_REG_EDX:
			ret = names[3];
			break;
		case X86_REG_AX:
			ret = names[4];
			break;
		case X86_REG_BX:
			ret = names[5];
			break;
		case X86_REG_CX:
			ret = names[6];
			break;
		case X86_REG_DX:
			ret = names[7];
			break;
		case X86_REG_AL:
			ret = names[8];
			break;
		case X86_REG_AH:
			ret = names[9];
			break;
		case X86_REG_BH:
			ret = names[10];
			break;
		case X86_REG_BL:
			ret = names[11];
			break;
		case X86_REG_CH:
			ret = names[12];
			break;
		case X86_REG_CL:
			ret = names[13];
			break;
		case X86_REG_DH:
			ret = names[14];
			break;
		case X86_REG_DL:
			ret = names[15];
			break;
		default:
			ret = names[16];
			break;
	}
	return ret;
}

uint8_t *test_patch(x86_reg r) {
	switch (r) {
		case X86_REG_EAX:
			return tst_pt[0];
		case X86_REG_EBX:
			return tst_pt[1];
		case X86_REG_ECX:
			return tst_pt[2];
		case X86_REG_EDX:
			return tst_pt[3];
		default:
			return NULL;
	}
}

int is_sel_mem(element *e) {
	if (e->type == ELE_MEM && e->mem.base == X86_REG_INVALID &&
	    e->mem.index != X86_REG_INVALID &&
	    e->mem.scale == 4)
		return 1;
	return 0;
}

void print_func(symbl sym) {
	std::string str = "unknown function";
	switch (sym) {
		case SYM_ALU_EQ:
			str = "==";
			break;
		case SYM_BOOL_AND:
			str = "&&";
			break;
		case SYM_ALU_ADD:
			str = "+";
			break;
		case SYM_ALU_OR:
			str = "|";
			break;
		case SYM_ALU_AND:
		case SYM_IMP_BAND:
			str = "&";
			break;
		case SYM_ALU_XOR:
			str = "^";
			break;
		case SYM_ALU_SHL:
			str = "<<";
			break;
		case SYM_ALU_SHR:
			str = "shr";
			break;
		case SYM_ALU_SARI:
			str = "sari";
			break;
		case SYM_BOOL_XNOR:
			str = "BOOL XNOR";
			break;
		case SYM_ALU_MULL:
			str = "MULL";
			break;
		case SYM_ALU_MULH:
			str = "MULH";
			break;
		case SYM_BOOL_OR:
			str = "||";
			break;
		case SYM_BOOL_XOR:
			str = "^^";
			break;
		case SYM_INVALID:
			str = "invalid function";
		default:
			break;
	}
	std::cout << str << std::endl;
}

void dump_elem(element *e) {
	bool prv = false;
	switch (e->type) {
		case ELE_CONST:
			std::cout << e->imm << std::endl;
			break;
		case ELE_MEM:
			std::cout << "[";
			if (e->mem.base != X86_REG_INVALID) {
				std::cout << "reg";
				prv = true;
			}
			if (e->mem.index != X86_REG_INVALID) {
				std::cout << ((prv) ? " + reg * " : "reg * ");
				std::cout << e->mem.scale;
				prv = true;
			}
			if (e->mem.disp) {
				if (prv) std::cout << " + ";
				std::cout << e->mem.disp;
			}
			std::cout << "]" << std::endl;
			break;
		case ELE_FUNC:
			print_func(e->fun);
			break;
		case ELE_INVALID:
			std::cout << "invalid operation" << std::endl;
			break;
	}
}

uint64_t get_mask(x86_reg reg) {
	switch (reg) {
		case X86_REG_AL:
		case X86_REG_BL:
		case X86_REG_CL:
		case X86_REG_DL:
			return 0xFF;
		case X86_REG_AH:
		case X86_REG_BH:
		case X86_REG_CH:
		case X86_REG_DH:
			return 0xFF00;
		case X86_REG_AX:
		case X86_REG_BX:
		case X86_REG_CX:
		case X86_REG_DX:
			return 0xFFFF;
		default:
			return 0xFFFFFFFF;
	}
}

x86_reg get_32bit(x86_reg reg) {
	switch (reg) {
		case X86_REG_AL:
		case X86_REG_AH:
		case X86_REG_AX:
			return X86_REG_EAX;
		case X86_REG_BL:
		case X86_REG_BH:
		case X86_REG_BX:
			return X86_REG_EBX;
		case X86_REG_CL:
		case X86_REG_CH:
		case X86_REG_CX:
			return X86_REG_ECX;
		case X86_REG_DL:
		case X86_REG_DH:
		case X86_REG_DX:
			return X86_REG_EDX;
		default:
			return reg;
	}
}


x86_reg get_16bit(x86_reg reg) {
	switch (reg) {
		case X86_REG_EAX:
		case X86_REG_AL:
		case X86_REG_AH:
		case X86_REG_AX:
			return X86_REG_AX;
		case X86_REG_EBX:
		case X86_REG_BL:
		case X86_REG_BH:
		case X86_REG_BX:
			return X86_REG_BX;
		case X86_REG_ECX:
		case X86_REG_CL:
		case X86_REG_CH:
		case X86_REG_CX:
			return X86_REG_CX;
		case X86_REG_EDX:
		case X86_REG_DL:
		case X86_REG_DH:
		case X86_REG_DX:
			return X86_REG_DX;
		default:
			return reg;
	}
}


x86_reg get_8h(x86_reg reg) {
	switch (reg) {
		case X86_REG_EAX:
		case X86_REG_AL:
		case X86_REG_AH:
		case X86_REG_AX:
			return X86_REG_AH;
		case X86_REG_EBX:
		case X86_REG_BL:
		case X86_REG_BH:
		case X86_REG_BX:
			return X86_REG_BH;
		case X86_REG_ECX:
		case X86_REG_CL:
		case X86_REG_CH:
		case X86_REG_CX:
			return X86_REG_CH;
		case X86_REG_EDX:
		case X86_REG_DL:
		case X86_REG_DH:
		case X86_REG_DX:
			return X86_REG_DH;
		default:
			return reg;
	}
}


x86_reg get_8l(x86_reg reg) {
	switch (reg) {
		case X86_REG_EAX:
		case X86_REG_AL:
		case X86_REG_AH:
		case X86_REG_AX:
			return X86_REG_AL;
		case X86_REG_EBX:
		case X86_REG_BL:
		case X86_REG_BH:
		case X86_REG_BX:
			return X86_REG_BL;
		case X86_REG_ECX:
		case X86_REG_CL:
		case X86_REG_CH:
		case X86_REG_CX:
			return X86_REG_CL;
		case X86_REG_EDX:
		case X86_REG_DL:
		case X86_REG_DH:
		case X86_REG_DX:
			return X86_REG_DL;
		default:
			return reg;
	}
}

x86_reg get_alike(x86_reg reg, x86_reg size) {
	switch (size) {
		case X86_REG_AL:
		case X86_REG_BL:
		case X86_REG_CL:
		case X86_REG_DL:
			return get_8l(reg);
		case X86_REG_AH:
		case X86_REG_BH:
		case X86_REG_CH:
		case X86_REG_DH:
			return get_8h(reg);
		case X86_REG_AX:
		case X86_REG_BX:
		case X86_REG_CX:
		case X86_REG_DX:
			return get_16bit(reg);
		case X86_REG_EAX:
		case X86_REG_EBX:
		case X86_REG_ECX:
		case X86_REG_EDX:
			return get_32bit(reg);
		default:
			std::cerr << "non standard register" << std::endl;
			return X86_REG_INVALID;
	}
}


int get_size(x86_reg size) {
	switch (size) {
		case X86_REG_AL:
		case X86_REG_BL:
		case X86_REG_CL:
		case X86_REG_DL:
		case X86_REG_AH:
		case X86_REG_BH:
		case X86_REG_CH:
		case X86_REG_DH:
			return 8;
		case X86_REG_AX:
		case X86_REG_BX:
		case X86_REG_CX:
		case X86_REG_DX:
			return 16;
		case X86_REG_EAX:
		case X86_REG_EBX:
		case X86_REG_ECX:
		case X86_REG_EDX:
			return 32;
		default:
			std::cerr << "non standard register" << std::endl;
			return 0;
	}
}
