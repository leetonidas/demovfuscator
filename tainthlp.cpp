#include "tainthlp.hpp"
#include "utils.hpp"

int tainthlp::add_taint(uint32_t base, size_t len, size_t ref) {
	if (len > 0) {
		mem_taint.erase(base);
		mem_taint.emplace(base, ref);
		return add_taint(base + 1, len - 1, ref);
	}
	if (len == 0)
		return 0;
	else
		return 1;
}

bool tainthlp::has_taint(uint32_t base, size_t len) {
	std::map<uint32_t, size_t>::iterator it = mem_taint.lower_bound(base);
	if (it->first < base + len)
		return true;
	else
		return false;
}

size_t tainthlp::get_taint(uint32_t addr) {
	std::map<uint32_t, size_t>::iterator it = mem_taint.find(addr);
	if (it == mem_taint.end())
		return 0;
	else
		return it->second;
}

int tainthlp::add_taint(x86_reg reg, size_t ref) {
	reg_taint.erase(reg);
	reg_taint.emplace(reg, ref);
	switch (reg) {
		case X86_REG_EAX:
			return add_taint(X86_REG_AX, ref);
		case X86_REG_EBX:
			return add_taint(X86_REG_BX, ref);
		case X86_REG_ECX:
			return add_taint(X86_REG_CX, ref);
		case X86_REG_EDX:
			return add_taint(X86_REG_DX, ref);
		case X86_REG_AX:
			return add_taint(X86_REG_AH, ref) & add_taint(X86_REG_AL, ref);
		case X86_REG_BX:
			return add_taint(X86_REG_AH, ref) & add_taint(X86_REG_AL, ref);
		case X86_REG_CX:
			return add_taint(X86_REG_AH, ref) & add_taint(X86_REG_AL, ref);
		case X86_REG_DX:
			return add_taint(X86_REG_AH, ref) & add_taint(X86_REG_AL, ref);

		case X86_REG_EBP:
			return add_taint(X86_REG_BP, ref);
		case X86_REG_BP:
			return add_taint(X86_REG_BPL, ref);
		case X86_REG_EDI:
			return add_taint(X86_REG_DI, ref);
		case X86_REG_DI:
			return add_taint(X86_REG_DIL, ref);
		case X86_REG_ESI:
			return add_taint(X86_REG_SI, ref);
		case X86_REG_SI:
			return add_taint(X86_REG_SIL, ref);
		case X86_REG_ESP:
			return add_taint(X86_REG_SP, ref);
		case X86_REG_SP:
			return add_taint(X86_REG_SPL, ref);
		case X86_REG_AH:
		case X86_REG_AL:
		case X86_REG_BH:
		case X86_REG_BL:
		case X86_REG_CH:
		case X86_REG_CL:
		case X86_REG_DH:
		case X86_REG_DL:
		case X86_REG_BPL:
		case X86_REG_SPL:
		case X86_REG_SIL:
		case X86_REG_DIL:
			return 0;
		default:
			return 1;
	}
}

bool tainthlp::has_taint(x86_reg reg) {
	return reg_taint.find(reg) != reg_taint.end();
}

size_t tainthlp::get_taint(x86_reg reg) {
	auto it = reg_taint.find(reg);
	if (it != reg_taint.end())
		return it->second;
	return 0;
}
