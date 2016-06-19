#include "ctlelem.hpp"
#include <iostream>
#include <sstream>

ctlelem::ctlelem(ctlflow tp, uint32_t o, uint32_t d) {
	type = tp;
		pos = o;
	if (tp == CTL_LABEL) {
		lab.name = o;
		lab.function = d ? true : false;
	} else {
		dst = d;
	}
}

ctlelem::ctlelem(uint32_t pos, uint32_t name, bool function) {
	type = CTL_LABEL;
	this->pos = pos;
	lab.name = name;
	lab.function = function;
}

std::string ctlelem::dump(ctlelem nxt) {
	std::stringstream str;
	str << std::hex;
	switch (type) {
		case CTL_JMP:
			str << "l" << pos << " -> l" << dst << " [label = jmp];" << std::endl;
			break;
		case CTL_JCC:
			str << "l" << pos << " -> l" << dst << " [color = green];" << std::endl;
			str << "l" << pos << " -> l" << pos << "_2 [color = red];" << std::endl;
			str << "l" << pos << "_2 -> l" << nxt.pos << ";" << std::endl;
			break;
			case CTL_CALL:
			str << "l" << pos << " [shape=record, label = \"{ l" << pos << " | ";
			str << "call fun_" << dst << " }\"];" << std::endl;
			str << "l" << pos << " -> l" << nxt.pos << std::endl;
			break;
		case CTL_LABEL:
			if (lab.function)
				str << "fun_";
			else
				str << "l";
			str << pos << " -> l" << nxt.pos << ";" << std::endl;
		case CTL_RET:
			break;
		default:
			std::cerr << "tried to dump invalid element" << std::endl;
			break;
	}
	return str.str();
}
