#ifndef DEMOV_H
#define DEMOV_H

#include <map>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <tuple>
#include <sys/types.h>
#include <capstone/capstone.h>
#include <signal.h>
#include <memory>
#include "memhlp.hpp"
#include "dishlp.hpp"
#include "stackMachine.hpp"
#include "ctlelem.hpp"
#include "ctlhlp.hpp"
#include "asmhlp.hpp"

enum mov_flags{
	MOV_ID = 1,
	MOV_FLOW = 2,
	MOV_EXTERN = 4,
	MOV_LOOP = 8
};

enum demov_state{
	ST_REL = 1,
	ST_SEG = 2,
	ST_INIT = 4,
	ST_LOOP = 8,
	ST_MAIN = 16,
	ST_ANLY = 32,
	ST_CTANLY = 64,
	ST_END = 128,
};

class demov{
	public:
		demov();
		void set_relocations(std::unordered_map<unsigned long, std::string>*);
		void set_segments(std::map<unsigned long,
		                  std::tuple<uint8_t *, unsigned long, int>>*);
		void set_entrypoint(uint64_t);
		int analyse_sigaction(cs_insn *ins, size_t num, uint32_t **ret);
		int parse_entry();
		int parse_data();
		int resub(uint64_t start, uint64_t length);
		void dump_regs();
		std::string dump_idc();
		void dump_stat();
		int init();
		int analyse();
		std::vector<std::pair<uint32_t, uint32_t>> get_blocks();
		int scan();
		std::string dump_flow();
		std::string dump_calls();
		uint64_t analyse_sel_on(cs_insn*);
		std::string dump_syms();
		void set_patch_call(bool b);
		~demov();
	private:
		int find_on(cs_insn *ins, size_t num);
		std::string* get_call_target(cs_insn *ins);
		int find_target(cs_insn *i, uint64_t *tar);
		cs_insn *find_toggle(cs_insn *i, x86_reg reg);
		template<typename c>
		int is_ret(std::stack<element, c> st);
		int patch_jmp(cs_insn *off, uint64_t tar, uint8_t OP=0xE9);
		int patch_ret(cs_insn *off);
		int patch_jcc(cs_insn *sel, cs_insn *off, uint64_t tar);
		int patch_call(cs_insn *off, uint64_t tar);
		int do_switch(cs_insn *ins);
		void find_fault();

		dishlp dis;
		ctlhlp ctl;
		asmhlp ash;
		csh handle;
		uint64_t end;
		int state = 0;
		int flags;
		uint64_t entrypoint;
		uint64_t on;
		uint64_t sel_on;
		uint64_t master_loop;
		uint64_t target_reg = 0;
		uint64_t tar;
		uint32_t stackp = 0;
		std::unordered_map<unsigned long, std::string>* relocations;
		std::shared_ptr<memhlp> mem;
		std::unordered_map<uint64_t, uint64_t> jmp_tar;
		std::map<uint64_t, bool> ret_tar;
		std::map<uint64_t, size_t> ac_array;
		std::map<uint64_t, size_t> ac_dir_r;
		std::map<uint64_t, size_t> ac_dir_w;
		std::map<uint64_t, size_t> ac_stat;
		std::vector<uint32_t> regs;
};

template <typename c>
int demov::is_ret(std::stack<element, c> st) {
	if (st.size() != 2) return 0;
	element e = st.top();
	st.pop();
	if (e.type != ELE_MEM ||
	    e.mem.base == X86_REG_INVALID ||
	    e.mem.index != X86_REG_INVALID ||
	    e.mem.disp != 0)
		return 0;
	e = st.top();
	if (e.type != ELE_MEM ||
	    e.mem.base != X86_REG_INVALID ||
		e.mem.index != X86_REG_INVALID ||
		e.mem.disp == 0)
		return 0;
	if (mem->get_sym((uint64_t) e.mem.disp) == SYM_SP)
		return 1;
	return 0;
}
#endif
