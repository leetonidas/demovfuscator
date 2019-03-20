#ifndef ELFHLP_H
#define ELFHLP_H

#include <string>
#include <unordered_map>
#include <map>
#include <tuple>
#include <sys/types.h>

enum seg_flags{
	SEG_X = 0,
	SEG_W,
	SEG_R
};

class elfhlp{
	public:
		elfhlp(void);
		elfhlp(const elfhlp&);
		~elfhlp(void);
		int open(std::string file);
		uint32_t get_entrypoint();
		bool isx86mov();
		std::unordered_map<uint64_t, std::string>* getrelocations();
		std::map<uint64_t, std::tuple<uint8_t *,
		                                   uint64_t, int>>* getsegments();
		uint64_t get_size();
		uint8_t *get_buf();
	private:
		std::string file;
		uint8_t *buf;
		uint64_t size;
		int fd;
};

#endif
