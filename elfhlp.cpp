#include <string>
#include <iostream>
#include <cstdlib>
#include <unordered_map>
#include <map>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <elf.h>

#include "elfhlp.hpp"

template <class T>
T* addp(T *ptr, unsigned long inc) {
	return (T*) (((uint8_t *) ptr) + inc);
}

elfhlp::elfhlp(void){
	buf = NULL;
	size = 0;
	fd = -1;
}

elfhlp::elfhlp(const elfhlp& hlp){
	this->file = hlp.file;
	this->buf = hlp.buf;
	this->size = hlp.size;
	this->fd = hlp.fd;
}

elfhlp::~elfhlp(){
	if (fd >= 0) {
		munmap(buf, size);
	}
	close(fd);
}

uint32_t elfhlp::get_entrypoint() {
	Elf32_Ehdr *ehdr;
	if (buf != NULL) {
		ehdr = (Elf32_Ehdr *) buf;
		return ehdr->e_entry;
	} else
		return 0;
}

int elfhlp::open(std::string file){
	struct stat st;

	// closing other file if open
	if (fd >= 0) {
		munmap(buf, size);
	}
	close(fd);
	buf = NULL;
	fd = -1;
	size = 0;

	// getting the size of the file
	if (stat(file.c_str(), &st) != 0) return -1;
	size = st.st_size;
	this->file = file;

	// opening it
	fd = ::open(file.c_str(), O_RDONLY);
	if (fd == -1) {
		size = 0;
		return -1;
	}

	// mapping it into memory
	buf = (uint8_t *) mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (buf == ((void *) -1)) {
		close(fd);
		fd = -1;
		buf = NULL;
		size = 0;
		return -1;
	}

	// testing the elf magic
	if (buf[0] == ELFMAG0
		&& buf[1] == ELFMAG1
		&& buf[2] == ELFMAG2
		&& buf[3] == ELFMAG3){
		return 0;
	} else {
		munmap(buf, size);
		close(fd);
		fd = -1;
		buf = NULL;
		return -2;
	}
}

std::unordered_map<unsigned long, std::string>* elfhlp::getrelocations(){
	std::unordered_map<unsigned long, std::string> *rels;
	Elf32_Ehdr *ehdr = (Elf32_Ehdr*) buf;
	Elf32_Shdr *sbase;
	Elf32_Rel *rel;
	Elf32_Shdr *symhdr;
	Elf32_Sym *sym;
	char *str;

	if (buf == NULL) return NULL;
	rels = new std::unordered_map<unsigned long, std::string>();
	sbase = (Elf32_Shdr*) (buf + ehdr->e_shoff);

	for (int i = 0; i < ehdr->e_shnum; i++) {
		if (sbase[i].sh_type == SHT_REL || sbase[i].sh_type == SHT_RELA) {
			// std::cout << "Found relocations section" << std::dec << std::endl;
			int num;
			rel = (Elf32_Rel*) (buf + sbase[i].sh_offset);
			symhdr = sbase + sbase[i].sh_link;
			sym = (Elf32_Sym *) (buf + symhdr->sh_offset);
			str = (char *) buf + sbase[symhdr->sh_link].sh_offset;
			num = sbase[i].sh_size / sbase[i].sh_entsize;

			/*
			std::cout << num << " relocations in section ";
			std::cout << buf + sbase[ehdr->e_shstrndx].sh_offset + sbase[i].sh_name;
			std::cout << std::hex << std::endl;
			*/

			for (int x = 0; x < num; x++) {
				Elf32_Rel *cur;
				unsigned long addr;
				std::string name;
				cur = addp(rel, x * sbase[i].sh_entsize);
				addr = cur->r_offset;
				name = std::string(str + sym[ELF32_R_SYM(cur->r_info)].st_name);
				rels->insert(std::make_pair(addr, name));
				// std::cout << addr << ": " << name << std::endl;
			}
			// std::cout << std::dec;
		}
	}

	return rels;
}

std::map<unsigned long, std::tuple<uint8_t *, unsigned long, int>>*
elfhlp::getsegments(){
	std::map<unsigned long, std::tuple<uint8_t *, unsigned long, int>> *seg;
	Elf32_Ehdr *ehdr = (Elf32_Ehdr *) buf;
	Elf32_Phdr *pbase;

	if (buf == NULL) return NULL;
	seg = new std::map<unsigned long, std::tuple<uint8_t *, unsigned long, int>>();

	pbase = (Elf32_Phdr*) (buf + ehdr->e_phoff);
	for (int i = 0; i < ehdr->e_phnum; i++) {
		if (pbase[i].p_type == PT_LOAD) {
			std::tuple<uint8_t *, unsigned long, int>  data;
			unsigned long addr;
			// std::cout << "Found loadable segment" << std::endl;
			addr = pbase[i].p_vaddr;
			data = std::make_tuple(buf + pbase[i].p_offset,
			                       pbase[i].p_filesz, pbase[i].p_flags & 7);
			seg->insert(std::make_pair(addr, data));

			if (pbase[i].p_filesz < pbase[i].p_memsz) {
				addr += pbase[i].p_filesz;
				data = std::make_tuple((uint8_t *) NULL,
				                       pbase[i].p_memsz - pbase[i].p_filesz,
				                       pbase[i].p_flags & 7);
				seg->insert(std::make_pair(addr, data));
			}
		}
	}

	return seg;
}

unsigned long elfhlp::get_size() {
	return size;
}

uint8_t *elfhlp::get_buf() {
	return buf;
}

bool elfhlp::isx86mov(){
	Elf32_Ehdr *ehdr;
	if (fd == -1) return false;
	ehdr = (Elf32_Ehdr*) buf;
	if (buf[EI_CLASS] != ELFCLASS32) return false;
	if (buf[EI_DATA] != ELFDATA2LSB) return false;
	if (ehdr->e_machine != EM_386) return false;
	return true;
}
