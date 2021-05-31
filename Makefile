export LD_LIBRARY_PATH=./
CXX = g++
CC= gcc
all:
	 ${CXX} -o test main.cpp EPET.cpp bn_pair.cpp   miracl.a -g 
clean:
	rm -f test
