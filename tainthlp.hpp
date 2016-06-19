#ifndef TAINTHLP_H
#define TAINTHLP_H

#include <map>
#include <unordered_map>
#include <capstone/x86.h>

class tainthlp{
	public:
		/** 
		 * Adds taint to a specified address and (len - 1) subsequent addresses
		 * @param base base address to taint
		 * @param len length of the area to taint
		 * @param ref the taint reference number (or colour or whatever)
		 * @return 0 if successful, else 1
		 */
		int add_taint(uint64_t base, size_t len, size_t ref);

		/**
		 * Querys whether an address is tainted
		 * @param addr The Querryed address
		 * @param len The length of the quarryed area
		 * @return true if any of the addresses are tainted, else false
		 */
		bool has_taint(uint64_t addr, size_t len);

		/**
		 * Returns the taint information of an memory cell
		 * @param addr The Memory address
		 * @return the taint reference number
		 */
		size_t get_taint(uint64_t addr);

		/**
		 * Taints a register and the subregisters (tainting ax also taints ah an al, but not eax)
		 * @param reg The register to taint
		 * @param ref The taint reference number
		 * @return 0 on success, 1 on failur
		 */
		int add_taint(x86_reg reg, size_t ref);

		/**
		 * Get the taintness status from the register
		 * @param reg The register
		 * @return true if tainted, false if not
		 */
		bool has_taint(x86_reg reg);

		/**
		 * @param get the taint information off a specific register
		 * @return the taint reference number
		 */
		size_t get_taint(x86_reg reg);
	private:
		std::map<uint32_t, size_t> mem_taint;
		std::unordered_map<x86_reg, size_t, std::hash<unsigned int> > reg_taint;
}

#endif
