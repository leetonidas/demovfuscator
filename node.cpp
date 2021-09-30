#include "node.hpp"
#include <iostream>
#include <sstream>
#include <cassert>

std::map<unsigned, node> nodes;
unsigned cur = 0;

node::node(std::string name, uint32_t pos, uint32_t label)
	: name (name),
	pos (pos),
	label (label),
	end (0),
	del (false),
	val (0)
{
	num = cur++;
}

void node::set_format(std::string f) {
	format = f;
}

node *get_node(std::string name, uint32_t pos) {
	for (auto &n : nodes) {
		if (n.second.get_name() == name)
			return &(n.second);
	}
	node n(name, pos);
	nodes.emplace(n.get_num(), n);
	return &(nodes.find(n.get_num())->second);
}

node *get_node(unsigned n) {
	auto f = nodes.find(n);
	node *ret;
	if (f == nodes.end()) {
		return NULL;
	} else
		ret = &(f->second);
	return ret;
}

uint32_t node::get_pos() {
	return pos;
}

uint32_t node::get_end() {
	return end;
}

std::string node::get_name() {
	return name;
}

unsigned node::get_num() {
	return num;
}

void node::add_adj(unsigned n, adj_type tp) {
	auto nod = nodes.find(n);
	if (nod == nodes.end()) std::cerr << "node not found" << std::endl;
	adj.emplace(n, tp);
	nod->second.val += ((tp == ADJ_CNT) ? 1 : 2);
}

void node::merge() {
	std::map<unsigned, node>::iterator x = nodes.begin();
	bool mrg;
	// for every node in nodes
	while (x != nodes.end()) {
		mrg = false;
		// look at every succesor
		for (auto y: x->second.adj) {
			auto n = nodes.find(y.first);
			assert (n != nodes.end());
			// if the only incoming connections is ADJ_CONT
			if (n->second.val == adj_type::ADJ_CNT) {
				//merge the nodes
				mrg = true;
				if (n->second.end > x->second.end)
					x->second.end = n->second.end;
				if (n->second.pos > x->second.end)
					x->second.end = n->second.pos;
				for (auto &z: n->second.adj)
					x->second.adj.emplace(z.first, z.second);
				x->second.adj.erase(n->first);
				nodes.erase(n->first);
			}
		}
		if (!mrg)
			x = std::next(x);
	}
}

std::string node::dump_name() {
	std::stringstream st;
	st << num << std::hex << " [label=\"" << name << "\"];" << std::endl;
	return st.str();
}

void node::set_label(uint32_t label) {
	this->label = label;
}

void node::set_end(uint32_t end) {
	this->end = end;
}

std::string node::dump() {
	std::stringstream st;
	for (auto y: adj) {
		st << num << " -> " << y.first;
		switch (y.second) {
			case ADJ_JMP:
				st << " [label=jmp];" << std::endl;
				break;
			case ADJ_JCC_T:
				st << " [label=true, color=green];" << std::endl;
				break;
			case ADJ_JCC_C:
				st << " [label=false, color=red];" << std::endl;
				break;
			default:
				st << ";" << std::endl;
		}
	}
	std::cout << std::hex << label << ": " << pos << " - " << end << std::endl;
	return st.str();
}
