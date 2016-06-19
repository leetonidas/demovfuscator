#ifndef MEMHLP_H
#define MEMHLP_H

#include <tuple>
#include <map>
#include <unordered_map>
#include <elf.h>

enum symbl{
	SYM_INVALID, SYM_ON, SYM_SEL_ON, SYM_M_LOOP, SYM_ENTRYP,
	SYM_ALU_EQ, SYM_ALU_ADD, SYM_BIT_SET, SYM_BIT_CLR,
	SYM_ALU_AND, SYM_ALU_OR, SYM_ALU_XOR, SYM_ALU_SHL,
	SYM_ALU_SHR, SYM_ALU_SARI, SYM_ALU_MULL, SYM_ALU_MULH,
	SYM_BOOL_OR, SYM_BOOL_XOR, SYM_BOOL_XNOR, SYM_BOOL_AND,
	SYM_IMP_BAND, SYM_TARGET, SYM_SEL_TARGET, SYM_SP, SYM_END,
	SYM_ALU_TRUE, SYM_ALU_FALSE, SYM_ALU_B0, SYM_ALU_B1,
	SYM_ALU_B2, SYM_ALU_B3, SYM_ALU_B4, SYM_ALU_B5, SYM_ALU_B6,
	SYM_ALU_B7, SYM_ALU_ADD8L, SYM_ALU_ADD8H, SYM_ALU_INV8,
	SYM_ALU_INV16, SYM_ALU_CLAMP32, SYM_ALU_MUL_SUM8L,
	SYM_ALU_MUL_SUM8H, SYM_ALU_MUL_SHL2, SYM_ALU_MUL_SUMS,
	SYM_ALU_DIV_SHL1_8_C_D, SYM_ALU_DIV_SHL1_8_D, SYM_ALU_DIV_SHL2_8_D,
	SYM_ALU_DIV_SHL3_8_D, SYM_ALU_SEX8, SYM_SEL_DATA, SYM_DATA,
	SYM_STP_ADD4, SYM_STP_SUB4, SYM_DISCARD, SYM_FAULT, SYM_DISPATCH
};

class memhlp{
	public:
		void set_segments(std::map<uint64_t,
		                           std::tuple<uint8_t *, uint64_t, int>>*);
		std::pair<const uint64_t, std::tuple<uint8_t *, uint64_t, int>>*
		        get_segment(uint64_t addr);
		uint8_t* get_ptr(uint64_t addr);
		size_t space(uint64_t addr);
		int is_X(uint64_t addr);
		symbl analyse_table(uint64_t addr, int dim);
		symbl get_sym(uint64_t addr);
		int add_sym(uint64_t addr, symbl sym);
		bool has_sym(symbl sym);
		uint64_t get_sym_addr(symbl sym);
		bool has_sym_to(uint64_t addr);
		int rem_sym(uint64_t addr);
		std::string dump_syms();
		std::string dump_syms_idc();
		std::string get_sym_name(enum symbl sym);
		template <typename T>
		int get_data(uint64_t addr, T** data) {
			size_t off;
			auto *seg = get_segment(addr);
			if (!seg) return -1;
			off = addr - seg->first;
			if ((std::get<1>(seg->second)) - off < sizeof(T)) return -2;
			if ((std::get<0>(seg->second)) == NULL)
				*data = NULL;
			else
				*data = ((T*) ((std::get<0>(seg->second)) + off));
			return 0;
		}
	private:
		std::map<uint64_t, std::tuple<uint8_t *, uint64_t, int>> segs;
		std::unordered_map<uint64_t, symbl> symbol;
};

#endif
