#ifndef CTLHLP_H
#define CTLHLP_H

#include <string>
#include <map>
#include <unordered_set>
#include <vector>
#include "ctlelem.hpp"
#include "node.hpp"

class ctlhlp{
	public:
		bool add_elem(ctlelem e);
		std::string analyse();
		std::string dump_calls();
		std::vector<std::pair<uint32_t, uint32_t>> get_blocks();
	private:
		std::map<uint32_t, ctlelem> elems;
		std::unordered_set<uint32_t> functions;
		std::map<uint32_t, std::unordered_set<uint32_t>> calls;
		void clean_calls();
		std::vector<std::pair<uint32_t, uint32_t>> bb;
};

#endif
