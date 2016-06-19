OBJS = elfhlp.o demov.o test.o memhlp.o dishlp.o utils.o ctlhlp.o ctlelem.o node.o asmhlp.o
CC = clang++
FLAGS = -Wall -Wextra -pedantic -std=c++11
CFLAGS = $(FLAGS) -g -c
LFLAGS = $(FLAGS) -lcapstone -lkeystone -lz3 -lssl -lcrypto

demov: $(OBJS)
	$(CC) $(LFLAGS) $(OBJS) -o demov

asmhlp.o: asmhlp.hpp asmhlp.cpp demov.hpp utils.hpp
	$(CC) $(CFLAGS) asmhlp.cpp

test.o: test.cpp elfhlp.hpp demov.hpp
	$(CC) $(CFLAGS) test.cpp

elfhlp.o: elfhlp.hpp elfhlp.cpp
	$(CC) $(CFLAGS) elfhlp.cpp

demov.o: demov.hpp demov.cpp memhlp.hpp dishlp.hpp stackMachine.hpp ctlhlp.hpp ctlelem.hpp
	$(CC) $(CFLAGS) demov.cpp

memhlp.o: hashes.h memhlp.hpp memhlp.cpp
	$(CC) $(CFLAGS) memhlp.cpp

dishlp.o: dishlp.hpp dishlp.cpp memhlp.hpp stackMachine.hpp utils.hpp
	$(CC) $(CFLAGS) dishlp.cpp

utils.o: utils.hpp utils.cpp stackMachine.hpp
	$(CC) $(CFLAGS) utils.cpp

ctlelem.o: ctlelem.hpp ctlelem.cpp
	$(CC) $(CFLAGS) ctlelem.cpp

ctlhlp.o: ctlhlp.hpp ctlhlp.cpp ctlelem.hpp node.hpp
	$(CC) $(CFLAGS) ctlhlp.cpp

node.o: node.hpp node.cpp
	$(CC) $(CFLAGS) node.cpp

clean:
	rm -f demov *.o *.gch

