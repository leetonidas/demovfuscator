#include "ctlhlp.hpp"

#include <iostream>
#include <deque>
#include <sstream>
#include <set>
#include <cassert>

bool ctlhlp::add_elem(ctlelem e) {
	return elems.emplace(e.pos, e).second;
}

std::string to_string_hex(uint64_t ad) {
	std::stringstream st;
	st << std::hex << ad;
	return st.str();
}

std::string ctlhlp::analyse() {
	std::map<uint32_t, ctlelem> cp = elems;
	std::deque<uint32_t> func_list;
	std::set<uint32_t> jmp_list;
	std::stringstream ret;

	uint32_t fun_end;

	// find call to main (first call/jmp)
	for (auto &e: cp) {
		if (e.second.type == CTL_CALL || e.second.type == CTL_JMP) {
			func_list.push_back(e.second.dst);
			break;
		}
		assert (e.second.type == CTL_LABEL);
	}

	ret << std::hex;

	while (!func_list.empty()) {
		uint32_t fun = func_list.front();
		fun_end = fun;
		func_list.pop_front();
		std::unordered_set<uint32_t> cls;

		if (cp.count(fun) == 0) {
			continue;
		}
		jmp_list.clear();
		jmp_list.emplace(fun);
		{
			auto tmp = cp.find(fun);
			assert(tmp->second.type == CTL_LABEL);
			tmp->second.lab.function = true;
			functions.emplace(fun);
		}

		ret << "digraph fun_" << fun << " {" << std::endl;
		ret << "node [shape = box];" << std::endl;

		while(!jmp_list.empty()) {
			uint32_t thr = *jmp_list.begin();
			jmp_list.erase(jmp_list.begin());
			std::map<uint32_t, ctlelem>::iterator cur = cp.find(thr);
			auto nxt = cur;
			if (cur == cp.end()) continue;
			ctlelem l;
			do {
				l = cur->second;
				nxt = std::next(cur);
				assert(nxt != cp.end());
				assert(l.type != CTL_INVALID && nxt->second.type != CTL_INVALID);
				cp.erase(cur);

				node *curnd = get_node(to_string_hex(l.pos), l.pos);
				ctlelem nxtel = elems.upper_bound(l.pos)->second;
				node *fl = get_node(to_string_hex(nxtel.pos), nxtel.pos);
				node *tmp;
				switch (l.type) {
					case CTL_JCC:
						// add intermediate node
						tmp = get_node(to_string_hex(l.pos) + "_f", l.pos);
						// branch not taken
						if (nxtel.pos > fun_end)
							fun_end = nxtel.pos;

						curnd->add_adj(tmp->get_num(), ADJ_JCC_C);
						tmp->add_adj(fl->get_num(),ADJ_CNT);
						tmp->set_end(nxtel.pos);
						// branch taken
						if (l.dst > fun_end)
							fun_end = l.dst;
						tmp = get_node(to_string_hex(l.dst), l.dst);
						curnd->add_adj(tmp->get_num(), ADJ_JCC_T);
						// update search list
						jmp_list.emplace(l.dst);
						break;
					case CTL_JMP:
						tmp = get_node(to_string_hex(l.dst), l.dst);
						curnd->add_adj(tmp->get_num(), ADJ_JMP);
						jmp_list.emplace(l.dst);
						break;
					case CTL_CALL:
						if (l.dst > fun && l.dst < fun_end) {
							tmp = get_node(to_string_hex(l.dst), l.dst);
							curnd->add_adj(tmp->get_num(), ADJ_JMP);
							jmp_list.emplace(l.dst);
							break;
						}
						cls.emplace(l.dst);
						func_list.push_back(l.dst);
					case CTL_LABEL:
						curnd->add_adj(fl->get_num(), ADJ_CNT);
						curnd->set_label(l.lab.name);
						curnd->set_end(nxtel.pos);
						if (fun_end < nxtel.pos)
							fun_end = nxtel.pos;
						break;
					default:
						break;
				}
				cur = nxt;
				if (nxt->second.type == CTL_RET)
					curnd->set_end(nxtel.pos);
			} while (l.type != CTL_JMP && nxt->second.type != CTL_RET);

			// attempt to find elements within the bound of the function
			// and add them to the jump list
			if (jmp_list.empty()) {
				std::map<uint32_t, ctlelem>::iterator it = cp.upper_bound(fun);
				if (it->first < fun_end)
					jmp_list.emplace(it->first);
			}
		}

		// simplify graph
		auto root = nodes.find(0);
		if (root != nodes.end())
			root->second.merge();
		// print all node names
		for (auto &x: (nodes))
			ret << x.second.dump_name();
		// print the connections
		for (auto &x: (nodes)) {
			ret << x.second.dump();
			bb.push_back(std::make_pair(x.second.get_pos(),
			                            x.second.get_end()));
		}
		// delete all nodes
		nodes.clear();
		// reset node counter
		cur = 0;

		calls.emplace(fun, cls);
		ret << "}" << std::endl << std::endl;
	}
	clean_calls();
	return ret.str();
}

std::vector<std::pair<uint32_t, uint32_t>> ctlhlp::get_blocks() {
	return bb;
}

std::string ctlhlp::dump_calls() {
	std::stringstream ret;
	ret << "digraph calls {" << std::hex << std::endl;
	for (auto &fun: functions) {
		auto c = calls.find(fun);
		if (c == calls.end()) {
			std::cerr << "could not find calls for fun_" << fun << std::endl;
			continue;
		}
		if (c->second.empty())
			continue;
		for (const auto &t: c->second)
			ret << "fun_" << fun << " -> fun_" << t << ";" << std::endl;
	}
	ret << "}";
	return ret.str();
}

void ctlhlp::clean_calls() {
	for (auto &fun: calls) {
		auto it = fun.second.begin();
		while (it != fun.second.end()) {
			if (!functions.count(*it)) {
				std::cerr << "fun_" << *it << " is actually not a function";
				std::cerr << std::endl;
				it = fun.second.erase(it);
			} else
				it++;
		}
	}
}
