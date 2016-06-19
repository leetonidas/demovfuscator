#ifndef ASMHLP_H
#define ASMHLP_H

#include <capstone/capstone.h>
#include <keystone/keystone.h>
#include <memory>
#include "memhlp.hpp"

class asmhlp {
	public:
		asmhlp ();
		void set_mem (std::shared_ptr<memhlp> mem);
		int replace(cs_insn *i, cs_insn *nxt, enum symbl sym);
		void set_patch_call(bool b);
		~asmhlp();
	private:
		ks_engine *eng = NULL;
		std::shared_ptr<memhlp> mem;
		bool pc = false;
};
#endif
