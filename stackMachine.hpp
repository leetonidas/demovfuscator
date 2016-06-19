#ifndef STACKMACHINE_H
#define STACKMACHINE_H

#include <capstone/x86.h>
#include <stack>
#include <queue>
#include <string>
#include <z3/z3++.h>
#include "memhlp.hpp"

#define inv_ele {ELE_INVALID, {SYM_INVALID}}

enum elem{
	ELE_CONST,
	ELE_MEM,
	ELE_FUNC,
	ELE_INVALID
};

typedef struct element{
	elem type;
	union{
		symbl fun;
		int64_t imm;
		x86_op_mem mem;
	};
} element;

template<typename c>
int print_infix(std::stack<element, c> *st,
                std::string *ret, uint64_t *dis = NULL);

template<typename c>
std::stack<element, c> simplify_stack(std::stack<element, c> st);

template<typename c>
uint64_t get_label(std::stack<element, c> st, uint64_t *addr);

template<typename c>
z3::expr gen_expr(std::stack<element, c> *st, 
                  z3::context *ctx, z3::symbol *mem, bool mem_valid);

template<typename c>
uint64_t get_label(std::stack<element, c> st, uint64_t *addr) {
	z3::context ctx;
	z3::expr mem = ctx.int_val(0);
	uint64_t mv;
	uint64_t ret;
	bool mem_valid;
	auto res = gen_expr(&st, &ctx, &mem, &mv, &mem_valid).simplify();
	z3::solver s(ctx);

	s.add(res);
	if (s.check() != z3::sat)
		return 0;
	z3::model m = s.get_model();
	for (unsigned i = 0; i < m.size(); i++) {
		z3::func_decl v = m[i];
		assert(v.is_const());
		z3::expr cn = m.get_const_interp(v);
		if (Z3_get_numeral_uint64(ctx, cn,(unsigned long long*)  &ret)) {
			*addr = mv;
			return ret;
		}
	}
	return 0;
}

template<typename c>
z3::expr gen_expr(std::stack<element, c> *st, 
                  z3::context *ctx, z3::expr *mem, uint64_t* mv, bool *mem_valid) {
	if (st->empty()) throw 1;
	z3::expr ret = ctx->int_val(0);
	element cur = st->top();
	st->pop();

	if (cur.type == ELE_CONST) {
		ret = ctx->bv_val((unsigned long long) cur.imm, 32);
	} if (cur.type == ELE_MEM) {
		if (!*mem_valid) {
			*mv = (uint64_t) cur.mem.disp;
			*mem = ctx->bv_const("mem", 32);
			*mem_valid = true;
		} else 
			if (*mv != (uint64_t) cur.mem.disp) throw 2;
		ret = *mem;
	}
	if (cur.type == ELE_INVALID) throw 3;
	if (cur.type == ELE_FUNC) {
		z3::expr l = gen_expr(st, ctx, mem, mv, mem_valid);
		z3::expr r = gen_expr(st, ctx, mem, mv, mem_valid);

		switch (cur.fun) {
			case SYM_ALU_EQ:
				ret = (l == r);
				break;
			case SYM_ALU_AND:
			case SYM_IMP_BAND:
				ret = (l & r);
				break;
			case SYM_BOOL_AND:
				ret = (l && r);
				break;
			default:
				throw 4;
				break;
		}
	}
	return ret;
}


template<typename c>
int print_infix(std::stack<element, c> *st,
                std::string *ret, uint64_t *dis) {
	uint64_t d = 0;
	if (st->empty()) return -1;
	element cur = st->top();
	st->pop();
	if (cur.type == ELE_INVALID) return -1;
	if (cur.type == ELE_FUNC) {
		*ret += "(";
		if (print_infix(st, ret, dis ? dis : &d)) return -1;
		switch (cur.fun) {
			case SYM_ALU_EQ:
				*ret += " == ";
				break;
			case SYM_ALU_ADD:
				*ret += " + ";
				break;
			case SYM_ALU_AND:
			case SYM_IMP_BAND:
				*ret += " & ";
				break;
			case SYM_ALU_OR:
				*ret += " | ";
				break;
			case SYM_ALU_XOR:
				*ret += " ^ ";
				break;
			case SYM_BOOL_AND:
				*ret += " && ";
				break;
			default:
				*ret += " op_unk ";
		}
		print_infix(st, ret, dis ? dis : &d);
		*ret += ")";
		return 0;
	}
	if (cur.type == ELE_CONST) {
		*ret += std::to_string(cur.imm);
		return 0;
	}
	if (cur.type == ELE_MEM) {
		if (dis && *dis == 0)
			*dis = (uint64_t) cur.mem.disp;

		if (!dis || *dis == (uint64_t) cur.mem.disp)
			*ret += "a";
		return 0;
	}
	return -1;
}

template<typename c>
std::stack<element, c> simplify_stack(std::stack<element, c> st) {
	std::stack<element, c> tmp;
	size_t ign = 0;
	while (!st.empty()) {
		element cur = st.top();
		st.pop();

		if (ign) {
			if (cur.type == ELE_FUNC) {
				switch (cur.fun) {
					case SYM_ALU_EQ:
					case SYM_ALU_ADD:
					case SYM_BIT_SET:
					case SYM_BIT_CLR:
					case SYM_ALU_AND:
					case SYM_ALU_OR:
					case SYM_ALU_XOR:
					case SYM_ALU_SHL:
					case SYM_ALU_SHR:
					case SYM_ALU_SARI:
					case SYM_ALU_MULL:
					case SYM_ALU_MULH:
					case SYM_BOOL_OR:
					case SYM_BOOL_AND:
					case SYM_BOOL_XOR:
					case SYM_BOOL_XNOR:
						ign++;
					default:
						break;
				}
			} else
				ign --;
			continue;
		}

		if (cur.type == ELE_FUNC && cur.fun == SYM_IMP_BAND && !st.empty()) {
			element nxt = st.top();
			if (nxt.type == ELE_CONST) {
				st.pop();
				element aft = st.top();
				if (aft.type == ELE_FUNC && (aft.fun == SYM_BOOL_AND ||
					aft.fun == SYM_BOOL_OR || aft.fun == SYM_BOOL_XOR ||
					aft.fun == SYM_BOOL_XNOR || aft.fun == SYM_ALU_EQ)) {
					if ((nxt.imm & 1) == 0) {
						element fls;
						fls.type = ELE_CONST;
						fls.imm = 0;
						tmp.push(fls);
						ign = 1;
					}
					continue;
				}
				tmp.push(cur);
				tmp.push(nxt);
				continue;
			}
		}
		tmp.push(cur);
	}
	while (!tmp.empty()) {
		st.push(tmp.top());
		tmp.pop();
	}
	return st;
}

#endif
