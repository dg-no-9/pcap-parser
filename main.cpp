#include "parser.h"

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

int test() {
	pcap_t *handle;
	struct pcap_pkthdr header;
	const u_char *packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	const struct sniff_ip *ip; /* The IP header */

	// open capture file for offline processing
	handle = pcap_open_offline("equinix-sanjose.dirB.20110120-140100.UTC.anon.pcap", errbuf);
	if (handle == NULL) {
		cout << "pcap_open_live() failed: " << errbuf << endl;
		return 1;
	}


	// start packet processing loop, just like live capture
	/*if (pcap_loop(handle, 10, packetHandler, NULL) < 0) {
		cout << "pcap_loop() failed: " << pcap_geterr(descr);
		return 1;
	}*/
	
	packet = pcap_next(handle, &header);
	ip = (struct sniff_ip*)(packet);
	
	char src_ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(ip->ip_src), src_ip, INET_ADDRSTRLEN);

	cout << src_ip <<" Size:" <<header.len << endl;

	cout << "capture finished" << endl;

	return 0;
}


void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
	u_int size_ip;
	u_int size_tcp;
	const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	const u_char *payload; /* Packet payload */
	
	long t = pkthdr->ts.tv_sec;//tv_usec;
	//cout << t << ":" << pkthdr->len << endl;
	ip = (struct sniff_ip*)(packet);
	
	char src_ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(ip->ip_src), src_ip, INET_ADDRSTRLEN);

	cout <<t<< ":" << src_ip << "," << (int)(ip->ip_p) << " size: " << pkthdr->len << endl;
}

int hashCode(int* a) {
	if (a == NULL)
		return 0;  
	int result = 1;
	for (int i = 0; i < 4; i++){
		int element = a[i];
 		result = 31 * result + element;  
	}
 	return result;
}


int main(){
	
	
	string filename = /*"equinix-sanjose.dirA.20101029-135500.UTC.anon.pcap.gz";*/"equinix-sanjose.dirB.20110120-140100.UTC.anon.pcap.gz";
	string pcap = filename.substr(0, filename.size() - 3);
	Parser *p = new Parser();
	const char* args = (string("gunzip -c ") + filename + string(" >") + pcap).c_str();
	system(args);
	clock_t begin = clock();
	p->parse(pcap.c_str(), 0.5);
	int tm = ((std::clock() - begin)/(double)(CLOCKS_PER_SEC/1000000));

	cout << "Time Taken:" << tm << endl;
	const char* args2 = (string("rm ") + pcap).c_str();
	system(args2);

	return 0;
}