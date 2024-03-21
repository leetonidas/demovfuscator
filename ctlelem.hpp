#ifndef CTLELEM_H
#define CTLELEM_H

#include <string>
#include <cstdint>

enum ctlflow{
	CTL_INVALID, CTL_JMP, CTL_JCC, CTL_RET, CTL_LABEL, CTL_CALL
};

typedef struct ctllabel{
	uint32_t name;
	bool function;
} ctllabel;

class ctlelem{
	public:
		ctlelem(ctlflow tp = CTL_INVALID, uint32_t o = 0, uint32_t d = 0);
		ctlelem(uint32_t pos, uint32_t name, bool function = false);
		std::string dump(ctlelem nxt);
		ctlflow type;
		uint32_t pos;
		union{
			uint32_t dst;
			ctllabel lab;
		};
};

#endif
