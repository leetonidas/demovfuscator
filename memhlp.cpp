#include "memhlp.hpp"
#include "hashes.h"
#include <sstream>
#include <cstring>
#include <iostream>
#include <openssl/evp.h>

void memhlp::set_segments(std::map<uint64_t,
                                   std::tuple<uint8_t *, uint64_t, int>>* seg){
	segs = *seg;
}

std::string memhlp::get_sym_name(enum symbl sym) {
	std::stringstream ret;
	switch (sym) {
		case SYM_ON:
			ret << "on";
			break;
		case SYM_SEL_ON:
			ret << "sel_on";
			break;
		case SYM_M_LOOP:
			ret << "master_loop";
			break;
		case SYM_ENTRYP:
			ret << "entrypoint";
			break;
		case SYM_ALU_EQ:
			ret << "equal";
			break;
		case SYM_ALU_ADD:
			ret << "add";
			break;
		case SYM_BIT_SET:
			ret << "bit_set";
			break;
		case SYM_BIT_CLR:
			ret << "bit_clear";
			break;
		case SYM_IMP_BAND:
		case SYM_ALU_AND:
			ret << "and";
			break;
		case SYM_ALU_OR:
			ret << "or";
			break;
		case SYM_ALU_XOR:
			ret << "xor";
			break;
		case SYM_ALU_SHL:
			ret << "shl";
			break;
		case SYM_ALU_SHR:
			ret << "shr";
			break;
		case SYM_ALU_SARI:
			ret << "sari";
			break;
		case SYM_ALU_MULL:
			ret << "mul_l";
			break;
		case SYM_ALU_MULH:
			ret << "mul_h";
			break;
		case SYM_BOOL_OR:
			ret << "bool_or";
			break;
		case SYM_BOOL_XOR:
			ret << "bool_xor";
			break;
		case SYM_BOOL_XNOR:
			ret << "bool_xnor";
			break;
		case SYM_BOOL_AND:
			ret << "bool_and";
			break;
		case SYM_TARGET:
			ret << "target_reg";
			break;
		case SYM_SEL_TARGET:
			ret << "sel_target";
			break;
		case SYM_SP:
			ret << "esp";
			break;
		case SYM_END:
			ret << "end";
			break;
		case SYM_ALU_TRUE:
			ret << "SYM_ALU_TRUE";
			break;
		case SYM_ALU_FALSE:
			ret << "SYM_ALU_FALSE";
			break;
		case SYM_ALU_B0:
			ret << "SYM_ALU_B0";
			break;
		case SYM_ALU_B1:
			ret << "SYM_ALU_B1";
			break;
		case SYM_ALU_B2:
			ret << "SYM_ALU_B2";
			break;
		case SYM_ALU_B3:
			ret << "SYM_ALU_B3";
			break;
		case SYM_ALU_B4:
			ret << "SYM_ALU_B4";
			break;
		case SYM_ALU_B5:
			ret << "SYM_ALU_B5";
			break;
		case SYM_ALU_B6:
			ret << "SYM_ALU_B6";
			break;
		case SYM_ALU_B7:
			ret << "SYM_ALU_B7";
			break;
		case SYM_ALU_ADD8L:
			ret << "SYM_ALU_ADD8L";
			break;
		case SYM_ALU_ADD8H:
			ret << "SYM_ALU_ADD8H";
			break;
		case SYM_ALU_INV8:
			ret << "SYM_ALU_INV8";
			break;
		case SYM_ALU_INV16:
			ret << "SYM_ALU_INV16";
			break;
		case SYM_ALU_CLAMP32:
			ret << "SYM_ALU_CLAMP32";
			break;
		case SYM_ALU_MUL_SUM8L:
			ret << "SYM_ALU_MUL_SUM8L";
			break;
		case SYM_ALU_MUL_SUM8H:
			ret << "SYM_ALU_MUL_SUM8H";
			break;
		case SYM_ALU_MUL_SHL2:
			ret << "SYM_ALU_MUL_SHL2";
			break;
		case SYM_ALU_MUL_SUMS:
			ret << "SYM_ALU_MUL_SUMS";
			break;
		case SYM_ALU_DIV_SHL1_8_C_D:
			ret << "SYM_ALU_DIV_SHL1_8_C_D";
			break;
		case SYM_ALU_DIV_SHL1_8_D:
			ret << "SYM_ALU_DIV_SHL1_8_D";
			break;
		case SYM_ALU_DIV_SHL2_8_D:
			ret << "SYM_ALU_DIV_SHL2_8_D";
			break;
		case SYM_ALU_DIV_SHL3_8_D:
			ret << "SYM_ALU_DIV_SHL3_8_D";
			break;
		case SYM_ALU_SEX8:
			ret << "SYM_ALU_SEX8";
			break;
		case SYM_DATA:
			ret << "SYM_DATA";
			break;
		case SYM_SEL_DATA:
			ret << "SYM_SEL_DATA";
			break;
		case SYM_INVALID:
			ret << "invalid";
			break;
		case SYM_STP_ADD4:
			ret << "STACK_ADD4(pop)";
			break;
		case SYM_STP_SUB4:
			ret << "STACK_SUB4(push)";
			break;
		case SYM_DISCARD:
			ret << "DISCARD";
			break;
		case SYM_DISPATCH:
			ret << "DISPATCH";
			break;
		case SYM_FAULT:
			ret << "FAULT";
			break;
		default:
			ret << "unrecognized";
			break;
	}
	return ret.str();
}

std::string memhlp::dump_syms() {
	std::stringstream ret;
	ret << std::hex;
	for (auto &x: symbol) {
		ret << get_sym_name(x.second) << "@" << x.first << std::endl;
	}
	return ret.str();
}

std::string memhlp::dump_syms_idc() {
	std::stringstream ret;
	ret << std::hex;
	for (auto &x: symbol) {
		if (x.second == SYM_STP_SUB4 || x.second == SYM_STP_ADD4)
			continue;
		ret << "\tMakeName(0x";
		ret << x.first << ", " << get_sym_name(x.second);
		ret << ");" << std::endl;
	}
	return ret.str();
}

uint8_t* memhlp::get_ptr(uint64_t addr) {
	size_t off;
	uint8_t *st;
	auto *seg = this->get_segment(addr);
	if (seg == NULL) return NULL;
	off = addr - seg->first;
	return (st = std::get<0>(seg->second)) ? st + off : NULL;
}

size_t memhlp::space(uint64_t addr) {
	auto *seg = this->get_segment(addr);
	if (seg == NULL) return 0;
	return (std::get<1>(seg->second)) - (addr - seg->first);
}

int memhlp::is_X(uint64_t addr) {
	auto *seg = get_segment(addr);
	return (seg && ((std::get<2>(seg->second)) & PF_X))? 1 : 0;
}

std::pair<const uint64_t, std::tuple<uint8_t *, uint64_t, int>>*
memhlp::get_segment(uint64_t addr) {
	for (auto &i: segs) {
		if (i.first <= addr && (i.first + std::get<1>(i.second)) >= addr)
			return &i;
	}
	return NULL;
}

symbl memhlp::analyse_table(uint64_t addr, int dim) {
	if (has_sym_to(addr)) return get_sym(addr);
	uint8_t *ptr = get_ptr(addr);
	if (!ptr) return SYM_INVALID;
	symbl ret = SYM_INVALID;

	if (dim == 2) {
		uint32_t *ind = (uint32_t *) ptr;
		uint8_t *elem;

		if (get_ptr(*ind) == NULL) return SYM_INVALID;

		/* indexed 1D table looks like 2D */
		if ((*ind) + 16 == *(ind + 4) && get_ptr(*ind)[4] == 1) {
			add_sym(addr, SYM_ALU_ADD);
			return SYM_ALU_ADD;
		}

		/* boolean operations are very small 2D tables */
		if (get_ptr((uint64_t) ind[1]) && !get_ptr((uint64_t) ind[2])) {
			uint32_t *target = (uint32_t*) get_ptr((uint64_t) ind[0]);
			int tmp = target[0] | (target[1] << 1);
			target = (uint32_t*) get_ptr((uint64_t) ind[1]);
			tmp |= (target[0] << 2) | (target[1] << 3);
			switch (tmp) {
				case 0xE:
					ret = SYM_BOOL_OR;
					break;
				case 0x8:
					ret = SYM_BOOL_AND;
					break;
				case 0x6:
					ret = SYM_BOOL_XOR;
					break;
				case 0x9:
					ret = SYM_BOOL_XNOR;
					break;
				default:
					std::cerr << "unrecognized boolean op: " << tmp << std::endl;
			}
			if (ret != SYM_INVALID)
				add_sym(addr, ret);
			return ret;
		}

		if (!(elem = get_ptr((uint64_t) ind[7]))) return SYM_INVALID;

		/* mad magic here */
		switch (elem[0xCB]) {
			case 0xCB:
				ret = SYM_BIT_SET;
				break;
			case 0x4B:
				ret = SYM_BIT_CLR;
				break;
			case 0:
				if (elem[0xC8] == 0x80)
					ret = SYM_ALU_SHL;
				else if(!elem[0xC8] && elem[0x7] == 1)
					ret = SYM_ALU_EQ;
				else
					ret = SYM_INVALID;
				break;
			case 3:
				ret = SYM_ALU_AND;
				break;
			case 0xCF:
				ret = SYM_ALU_OR;
				break;
			case 0xCC:
				ret = SYM_ALU_XOR;
				break;
			case 0x01:
				ret = SYM_ALU_SHR;
				break;
			case 0xFF:
				ret = SYM_ALU_SARI;
				break;
			case 0x8D:
				ret = SYM_ALU_MULL;
				break;
			case 0x5:
				ret = SYM_ALU_MULH;
				break;
			default:
				ret = SYM_INVALID;
				break;
		}
		/*else
			std::cerr << "table not recognized" << std::endl; */
	}

	if (dim == 1 && space(addr) > 256) {
		EVP_MD_CTX *ctx;
		uint64_t diggest[256 >> 6];
		size_t i;

		do {
			ctx = EVP_MD_CTX_create();
			if (ctx == 0) break;

			if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)) break;
			if (!EVP_DigestUpdate(ctx, (const void*) ptr, 256)) break;
			if (!EVP_DigestFinal_ex(ctx, (uint8_t *) diggest, NULL)) break;
			EVP_MD_CTX_destroy(ctx);
			for (i = 0; i < (sizeof(hashes) / sizeof(uint64_t*)); i++) {
				if (memcmp(hashes[i],diggest, 256 >> 3) == 0) {
					ret = (enum symbl) (((unsigned int)SYM_ALU_TRUE) + i);
					break;
				}
			}
			if (ret == SYM_ALU_B6) {
				uint32_t *tbl = (uint32_t *) ptr;
				int st = 0;
				ret = SYM_INVALID;
				if (space(addr) < 4 * 256) return ret;
				for (i = 64; i < 256; i++) {
					st |= (i & 0xC0) ^ ((tbl[i] << 7) | (tbl[i] << 6));
					if (tbl[i] & (~1)) {
						if (tbl[i] == 0x1010101)
							st = 0x20;
						else
							st = 0;
						break;
					}
				}
				if (st == 0x80)
					ret = SYM_ALU_B6;
				if (st == 0x40)
					ret = SYM_ALU_B7;
				if (st == 0x20)
					ret = SYM_ALU_MUL_SUM8H;
			}
		} while(0);

	}
	if (ret != SYM_INVALID) {
		std::cout << get_sym_name(ret) << "@0x" << std::hex << addr;
		std::cout << std::dec << std::endl;
		add_sym(addr, ret);
	}
	/*std::cerr << "1D tables not implemented yet" << std::endl;*/
	return ret;
}

int memhlp::add_sym(uint64_t addr, symbl sym) {
	if (sym != SYM_INVALID)
		return symbol.emplace(addr, sym).second ? 0 : -1;
	else
		return -1;
}

symbl memhlp::get_sym (uint64_t addr) {
	auto res = symbol.find(addr);
	return ((res == symbol.end()) ? SYM_INVALID : res->second);
}

bool memhlp::has_sym (symbl sym) {
	for (auto &i : symbol)
		if (i.second == sym) return true;
	return true;
}

uint64_t memhlp::get_sym_addr (symbl sym) {
	for (auto &i : symbol)
		if (i.second == sym) return i.first;
	return 0;
}

bool memhlp::has_sym_to (uint64_t sym) {
	return symbol.count(sym);
}

int memhlp::rem_sym (uint64_t addr) {
	return symbol.erase(addr) -1;
}
