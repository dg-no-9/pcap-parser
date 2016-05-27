all:
	g++ main.cpp parser.cpp packet.cpp sender.cpp -o parser -lpcap -std=c++11 -pthread
clean:
	rm -f parser
