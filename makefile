all:
	g++ main.cpp parser.cpp -o parser -lpcap -std=c++11
clean:
	rm -f parser
