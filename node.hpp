#ifndef NODE_H
#define NODE_H

#include <set>
#include <string>
#include <map>
#include <cstdint>

typedef enum adj_type{
	ADJ_CNT,
	ADJ_JMP,
	ADJ_JCC_T,
	ADJ_JCC_C
} adj_type;

extern unsigned cur;

class node{
	public:
		node(std::string name, uint32_t pos, uint32_t label = 0);
		void set_format(std::string format);
		void merge();
		void add_adj(unsigned n, adj_type type);
		std::string get_name();
		unsigned get_num();
		void set_end(uint32_t end);
		uint32_t get_pos();
		uint32_t get_end();
		std::string dump();
		std::string dump_name();
		void set_label(uint32_t l);
	private:
		std::string name;
		std::string format;
		uint32_t pos;
		uint32_t label;
		uint32_t end;
		bool del;
		unsigned num;
		unsigned val;
		std::map<unsigned, adj_type> adj;
};

extern std::map<unsigned, node> nodes;
node* get_node(std::string name, uint32_t pos);
node* get_node(unsigned num);

#endif
