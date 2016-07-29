#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <cmath>
#include <iomanip>
#include <ctime>
#include <thread>
#include "header.h"
#include "packet.h"

class Parser{
	public:
		void parse(const char* filename, float slicetime, const int thread_count);
		int parseold(const char* filename, float slicetime);
	private:
		map<long, vector<Packet> > packets;
		vector<PacketGroup> aggregated;
		
		void readAndFillMap(const char* filename, float slicetime);
		void aggregate(long starttime, vector<Packet> packet_list, PacketGroup* out);
		void aggregatePackets(long starttime, vector<Packet> packet_list, PacketGroup* out);
		Packet getFromPacket(struct pcap_pkthdr header, const u_char *packet);

		PacketGroup aggregatePacketGroups(PacketGroup* groups, int size);
};