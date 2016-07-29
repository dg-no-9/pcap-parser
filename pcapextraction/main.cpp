#include "parser.h"
#include "sender.h"
/**
	Command Line Arguments: 
			1.	File name to be parsed.
			2.	Number of Threads
			3.	Server IP
			4.  Server Port
*/
int main(int argc, char** argv){
	int thread_count = 1;
	if(argc < 5){
		cout << "Usage:\n\t1.File name to be parsed.\n\t2.Number of Threads\n\t3.Server IP\n\t4.Server Port"<<endl;
		exit(1);
	}
	if(argv[1]) thread_count =  atoi(argv[2]);
	d_ip = argv[3];
	port = atoi(argv[4]);
	string filename = argv[1];
	string pcap = filename.substr(0, filename.size() - 3);
	Parser *p = new Parser();
	const char* args = (string("gunzip -c ") + filename + string(" >") + pcap).c_str();
	system(args);
	auto begin = chrono::system_clock().now() ;
	p->parse(pcap.c_str(), 0.5, (const int) thread_count);
	chrono::duration<double> dur = chrono::system_clock().now()  - begin;

	cout << "Time Taken:" << dur.count() << endl;
	const char* args2 = (string("rm ") + pcap).c_str();
	system(args2);

	return 0;
}