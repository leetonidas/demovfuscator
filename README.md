## Demovfuscator


	                       Julian Kirsch & Clemens Jonischkeit
	                                 proudly present

	                               -------------------
	                               Movfuscator-Be-Gone
	                               -------------------
	                                    a.k.a the
	                                ___          ___
	                               /  /\        /  /\
	                              /  /::\      /  /::\
	                             /  /:/\:\    /  /:/\:\    _____
	                            /  /:/  \:\  /  /::\ \:\  /____/\
	                           /__/:/ \__\:|/__/:/\:\ \:\ \____\/
	                           \  \:\ /  /:/\  \:\ \:\_\/
	     ___     ___            \  \:\  /:/  \  \:\ \:\ __     ___          ___     ___
	    /\  \   /\  \    ___   /\\  \:\/:/.   \  \:\_\//__\   /\  \        /\  \   /\  \
	   |::\  \ /::\  \  /\  \ /:/ \  \::/  \ /:\  \:\ /   /  /::\  \  ___ /::\  \ /::\  \
	   |:::\  \:/\:\  \ \:\  \:/ /\\__\/:\  \:/ \__\//   /  /:/\:\  \/\__\:/\:\  \:/\:\__\
	 __|:|\:\  \  \:\  \ \:\  \ /:/  /  \:\  \ /::\  \  /  _:/ /::\  \/  //  \:\  \ /:/  /
	/::::|_\:\__\/ \:\__\ \:\__\:/  / \  \:\__\:/\:\__\/  /\__\:/\:\__\_//__/ \:\__\:/__/___
	\:\~~\  \/__/\ /:/  / |:|  |/  /\  \ /:/  // /:/  /\ /:/  //  \/__/ \\  \ /:/  /::::/  /
	 \:\  \  \:\  /:/  / \|:|  |__/\:\  /:/  // /:/  /  /:/  //__/:/\:\  \\  /:/  //~~/~~~~
	  \:\  \  \:\/:/  /\__|:|__|  \ \:\/:/  //_/:/  /:\/:/  /:\  \/__\:\  \\/:/  /:\~~\
	   \:\__\  \::/  /\::::/__/:\__\ \::/  /  /:/  / \::/  / \:\__\   \:\__\:/  / \:\__\
	    \/__/   \/__/  ~~~~    \/__/  \/__/   \/__/   \/__/   \/__/    \/__/ __/   \/__/

	              -- Recovering from soul-crushing RE nightmares --

### Summary

Since the publication of Christopher Domas'
[M/o/Vfuscator](https://github.com/xoreaxeaxeax/movfuscator), we spent a great
amount of time to analyze the inner workings of the famous
one-instruction-compiler. We are happy to announce and release the (to our
knowledge) first approach to a generic demovfuscator.

This tool constitutes a generic way of recovering the control flow of the original
program from movfuscated binaries. As our approach makes zero assumptions about
register allocations or a particular instruction order, but rather adheres to
the high-level invariants that each movfuscated binary needs to conform to,
our demovfuscator is also not affected by the proposed hardening techniques such
as register renaming and instruction reordering. To achieve this, we use a
combination of static taint analysis on the movfuscated code and a satisfiable
modulo theory (SMT) solver. We successfully used our demovfuscator against several
movfuscated binaries that emerged during several CTFs during the last months
(Hackover CTF and 0CTF) proving that it already can handle real-world binaries
that were not created by us.

### Compiling

The demovfuscator is programmed in C++ and as such has several (cool) dependencies:

  * [libcapstone](http://www.capstone-engine.org/) as the core disassembler
  * [libz3](https://github.com/Z3Prover/z3) to reason about the semantics of the mov code
  * [libkeystone](http://www.keystone-engine.org/) for re-substitution

As inconvenient this may be, we think that all three libraries should be in your
RE toolchain anyway. If this is just unacceptable for you (and you trust us),
there is a binary package that can be downloaded below.

After installing the dependencies, simply type `make` in the `demov` root
directory to compile. Note that you might have to adjust the library include
paths to match your distro.

### Usage

The demovfuscator supports the following parameters:

	./demov [-h] [-i symbols.idc] [-o patched_bin] [-g cfg.dot] obfuscated_input

	-h Use for a description of the options
	-i Derive symbols from the input bin and store them into symbols.idc
	-o Generate a patched executable with explicit control flow and some
	   instructions resubstituted
	-g Generate a UNIX dot compatible file containing the control flow
	   graph (might be easier to read than IDA's graph view)
	   Convert the .dot file to something usable by

	   cat cfg.dot | dot -Tpng > cfg.png

### Downloads

* [Compiled](https://kirschju.re/bins/demov-compiled.tar.gz) (very old) demovfuscator (you still need the compiled dependencies)
* [Bachelor's thesis](https://kirschju.re/docs/jonischkeit-2016-demovfuscator.pdf) describing parts of the approach
