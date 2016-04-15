#include "parser.h"

int Parser::parse(const char* filename, float slicetime){
	pcap_t *handle;
	struct pcap_pkthdr header;
	const u_char *packet;
	char errbuf[PCAP_ERRBUF_SIZE];

	// open capture file for offline processing
	handle = pcap_open_offline(filename, errbuf);
	if (handle == NULL) {
		cout << "pcap_open_live() failed: " << errbuf << endl;
		return 1;
	}


	// start packet processing loop, just like live capture
	/*if (pcap_loop(handle, 10, packetHandler, NULL) < 0) {
		cout << "pcap_loop() failed: " << pcap_geterr(descr);
		return 1;
	}*/

	long ts,tcount=0,starttime=0,prevtime=0;
	long slice = (long)(slicetime * 1000000);
	int pktcount= 0,bytecount=0,fragcount=0,pktcountv6=0,bytecountv6=0,countsap=0,countsa=0,counttse=0,cbl=0,cbh=0,ws0=0,rsw0=0;
	int count = 0;
	bool flag = true;
	vector<PacketGroup> rows;
	int rowcount = 0;
	while(packet = pcap_next(handle, &header), packet != NULL ){
		ts = (long)header.ts.tv_sec*1000000 + (long)header.ts.tv_usec;
		Packet p = this->getFromPacket(header, packet);
		//p.t.seconds = (long)header.ts.tv_sec;
		//p.t.milliseconds = (long)header.ts.tv_usec;
		//row.addPacket(p);
		count++;
		if(count == 1){
			starttime = ts;
		}
		if(count > 1 && ts > (starttime+slice)){
			PacketGroup g;
			rowcount++;
			g.pktcount = pktcount;
			g.pktcountv6 = pktcountv6;
			g.bytecount = bytecount;
			g.bytecountv6 = bytecountv6;
			g.cbl = cbl;
			g.cbh = cbh;
			g.fragcount = fragcount;
			g.countsap = countsap;
			g.countsa = countsa;
			g.ws0 = ws0;
			g.counttse = counttse;
			rows.push_back(g);
			if (rowcount == 10){exit(0);}
			g.print(); 
			pktcount=bytecount=pktcountv6=bytecountv6=cbl=cbh=fragcount=countsap=counttse=countsa=ws0=0;
			starttime += slice;
		}
		
		if(p.sport > 0){
			int sp = p.sport;
			int dp = p.dport;
			if(sp > 1023){ 
				sp = 1024;
				tcount++;
			}
			if(dp > 1023) dp = 1024;
			if(sp == 1024 && dp == 1024) cbh++;
			if(sp < 1024 && dp < 1024) cbl++;

		}
		if(p.v6){
			pktcountv6++;
			bytecountv6 += p.pktsize;
		}
		else if(p.v4){
			pktcount++;
			bytecount += p.pktsize;
			if (p.os>0){
				fragcount+=1;
			} 

			if (p.protocol==6 and p.sport>0){
				if (p.ws==0) ws0++;
				if (p.sap>0) countsap++;
				if (p.tse>0) counttse++;
				if (p.sa>0) countsa++;
			}
		}

		//if(p.os > 0) cout << p.os << endl;
		//if(count == 10000) exit(0);
		//
		//printf("%d\n", ts);
	}
	
	return 0;
}

Packet Parser::getFromPacket(struct pcap_pkthdr header, const u_char *packet){
	Packet p;
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	const u_char *payload; /* Packet payload */
	ip = (struct sniff_ip*)(packet);
	unsigned short iph_len = (short) IP_HL(ip)*4;
	
	
	tcp = (struct sniff_tcp*)(packet + iph_len); //Move pointer to TCP
	p.v4 = (IP_V(ip) == IPV4) ? 4 : -1; //IPV4
	p.v6 = (IP_V(ip) == IPV6) ? 6 : -1; //IPV6
	if (p.v4 == IPV4){
		p.protocol = ip->ip_p;					//Protocol
		p.pktsize = TRANSFORM(ip->ip_len);
		p.ttl = ip->ip_ttl;
		p.sip = (long)(ip->ip_src).s_addr;
		p.dip = (long)(ip->ip_dst).s_addr;
		p.os = (int)*(packet+7);
		if (p.protocol == 1){				//ICMP Protocol
			p.icmptype = (int)*(packet+20);
		}
		if(p.protocol == 6 || p.protocol == 17){	//TCP or UDP
			p.sport = TRANSFORM(tcp->th_sport);
			p.dport = TRANSFORM(tcp->th_dport);
		}
		if(p.protocol == 6){ //TCP
			p.hs = (tcp->th_offx2) >> 4;
			p.ws = TRANSFORM(tcp->th_win);
			p.fb = tcp->th_flags;
			if(p.hs > 5){ //If packet has TCP 1 byte Option-Type (0 for end of option), 1 byte option length, variable sized option data
				int i = 40;
				int val = (int)*(packet + i);
				while(val = (int)*(packet + i), val != 0){
					int option_size = (int)*(packet + i+ 1);
					if(val == 3 && option_size==3){ //Option Type 3, Window Scale
						p.wscale = (int)*(packet + i + 2);
						i += option_size; //Increment Pointer by total option size
					}
					else if(val == 2 && option_size == 4){ //Option Type 2, Segment Size
						p.ss = TWOBYTE_TO_INT(packet, i + 2);
						i += option_size; //Increment Pointer by total option size

					}
					else if(val == 4 && option_size == 2){
						p.sap = 1;
						i += option_size;
					}
					else if(val == 5){
						p.sa = 1;
						break;
					}
					else if(val == 8){
						p.tse = 1;
						break;
					}
					else if (val == 1){
						i++;
					}
					else break;
				}
				//cout << p.wscale << ','<< p.ss << ',' << p.sap <<','<< p.sa <<','<< p.tse << endl;
			}

		}
	}

	if(p.v6 = IPV6){
		p.protocol = (int) *(packet + 6);
		p.pktsize = TWOBYTE_TO_INT(packet,4);
		if( p.protocol == 58){ //ICMP Protocol
			p.icmptype = (int)*(packet+ 40);
		}
		else if(p.protocol == 6 || p.protocol == 17){
			p.sport = TWOBYTE_TO_INT(packet,40);
			p.dport = TWOBYTE_TO_INT(packet,42);
			//cout << p.sport << "," << p.dport<< endl;
		}
	}
	
	return p;
}


