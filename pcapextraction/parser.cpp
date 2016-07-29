#include "parser.h"
#include "sender.h"
template <typename T>
float entropy(map<T, int> m){
	typename map<T, int>::iterator it;
	int sum;
	for(it = m.begin(); it != m.end(); it++){
		sum += it->second;
	}
	float divided;
	float ent;
	for(it = m.begin(); it != m.end(); it++){
		divided = (it->second)/(float)sum;
		ent += log(divided) * divided;
	}
	return (-1) * ent;
}
int hashCode(initializer_list <long> a) {
	//if (a == NULL) return 0;

	int result = 1;
	for (auto element: a) {
		//long element = a[i];
 		int elementHash = (int)(element ^ (element >> 32));
 		result = 31 * result + elementHash;
 	}  
 	return result;      
}

void update(map<int, int> *master, map<int, int> child){
	for (auto it=child.begin(); it!=child.end(); ++it) {
	  if ( (*master)[it->first] )
	    (*master)[it->first] += it->second;
	  else
	    (*master)[it->first] = it->second;
	}
}

void Parser::parse(const char* filename, float slicetime, const int thread_count){
	this->readAndFillMap(filename, slicetime);
	typename map<long, vector<Packet> > ::iterator it;
	//const int thread_count = 5;
	const int size = packets.size();
	int count = 0;
	PacketGroup *p = new PacketGroup[size];

	count = 0;
	cout << "---------------" <<endl;
	Sender* sender = new Sender();
	for(it = packets.begin(); it != packets.end(); it++){
		long ts = it->first;
		vector<Packet> pktsperts = it->second;
		PacketGroup* groups = new PacketGroup[thread_count];
		thread *t = new thread[thread_count];
		int start = 0, end = 0;
		int chunksize = pktsperts.size()/ thread_count;
		int extra = pktsperts.size() % thread_count;
		for(int i = 0; i < thread_count; i++){
			end += chunksize;
			if(extra > 0){
				end++;
				extra--;
			}
			vector<Packet> chunk (pktsperts.begin()+start, pktsperts.begin() + end);
			
			t[i] = thread(&Parser::aggregatePackets, this, ts, chunk, &groups[i]);
			start = end;
		}

		for (int j = 0; j < thread_count; j++){
			t[j].join();
		}
		PacketGroup g = this->aggregatePacketGroups(groups, thread_count);

		count++;
		
		string json = g.buildjson();
		sender->sendjson(json.c_str(), json.length()); //Send json to socket.
	}
	sender->finish();
	cout << "Pcap Extraction Complete." << endl;

}

PacketGroup Parser::aggregatePacketGroups(PacketGroup* groups, int size){
	
	PacketGroup g;
	g.starttime = groups->starttime; //Same for all;
	for(int i = 0; i < size; i++, groups++){
		g.pktcount 		+= groups->pktcount;
		g.bytecount 	+= groups->bytecount;
		g.fragcount 	+= groups->fragcount;
		g.pktcountv6 	+= groups->pktcountv6;
		g.bytecountv6 	+= groups->bytecountv6;
		g.countsap 		+= groups->countsap;
		g.countsa 		+= groups->countsa;
		g.counttse		+= groups->counttse;
		g.cbl 			+= groups->cbl;
		g.cbh			+= groups->cbh;
		g.ws0 			+= groups->ws0;
		g.rsw0			+= groups->rsw0;

		update(&g.counters._cttl, groups->counters._cttl);
		update(&g.counters._csip, groups->counters._csip);
		update(&g.counters._cdip, groups->counters._cdip);
		update(&g.counters._cmsbip, groups->counters._cmsbip);
		update(&g.counters._cmsb2ip, groups->counters._cmsb2ip);

		update(&g.counters.cipv6prot, groups->counters.cipv6prot);
		update(&g.counters.cipprot, groups->counters.cipprot);
		update(&g.counters.cipv6tcppnum, groups->counters.cipv6tcppnum);
		update(&g.counters.ciptcppnum, groups->counters.ciptcppnum);
		update(&g.counters.cipv6udppnum, groups->counters.cipv6udppnum);
		update(&g.counters.cipudppnum, groups->counters.cipudppnum);
		update(&g.counters.cipv6icmp, groups->counters.cipv6icmp);
		update(&g.counters.cipicmp, groups->counters.cipicmp);

		update(&g.counters.ctcphs, groups->counters.ctcphs);
		update(&g.counters.ctcpflagbyte, groups->counters.ctcpflagbyte);
		update(&g.counters.ctemp, groups->counters.ctemp);
		update(&g.counters.css, groups->counters.css);
		update(&g.counters.cwscale, groups->counters.cwscale);
		update(&g.counters.ctcpflag8, groups->counters.ctcpflag8);
		update(&g.counters._ctcpcon, groups->counters._ctcpcon);
		update(&g.counters._cudpcon, groups->counters._cudpcon);


	}
	
	/*Dict Counters*/
	g.counters.lcttl 	= g.counters._cttl.size();
	g.counters.lcdip 	= g.counters._cdip.size();
	g.counters.lcsip 	= g.counters._csip.size();
	g.counters.lcmsbip 	= g.counters._cmsbip.size();
	g.counters.lcmsb2ip = g.counters._cmsb2ip.size();
	g.counters.lctcpcon = g.counters._ctcpcon.size();
	g.counters.lcudpcon = g.counters._cudpcon.size();


	/*Entropies of dicts */
	g.counters.cttl = entropy(g.counters._cttl);
	g.counters.csip = entropy(g.counters._csip);
	g.counters.cdip = entropy(g.counters._cdip);
	g.counters.cmsbip = entropy(g.counters._cmsbip);
	g.counters.cmsb2ip = entropy(g.counters._cmsb2ip);

	return g;
}

void Parser::readAndFillMap(const char* filename, float slicetime){
	pcap_t *handle;
	struct pcap_pkthdr header;
	const u_char *packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	long ts, starttime=0, prevtime=0;

	long count = 0;
	long slicecount =0;

	long slice = (long)(slicetime * 1000000);
	// open capture file for offline processing
	handle = pcap_open_offline(filename, errbuf);
	if (handle == NULL) {
		cout << "pcap_open_live() failed: " << errbuf << endl;
		exit(1);
	}

	vector<Packet> v;
	while(packet = pcap_next(handle, &header), packet != NULL ){

		ts = (long)header.ts.tv_sec*1000000 + (long)header.ts.tv_usec;
		Packet p = this->getFromPacket(header, packet);
		v.push_back(p);

		count++;
		if(count == 1){
			starttime = ts;
			prevtime = starttime;
		}
		if(count > 1 && ts > (starttime+slice)){
			//v.pop_back(); //Last packet removed, //TODO remove this later on.
			v.erase(v.begin());
			packets[starttime] = v;
			v.clear();
			slicecount++;

			prevtime = starttime;
			starttime += slice;
		}
	}
	cout << "Total Packets:" << count << endl;
	pcap_close(handle);
}

void Parser::aggregate(long starttime, vector<Packet> packet_list, PacketGroup* g){
	int pktcount= 0,bytecount=0,fragcount=0,pktcountv6=0,bytecountv6=0,countsap=0,countsa=0,counttse=0,cbl=0,cbh=0,ws0=0,rsw0=0;
	
	vector<PacketGroup> rows;
	map<int, int> 	cipv6prot, cipprot,cipv6tcppnum, ciptcppnum,cipv6udppnum, cipudppnum, cipv6icmp, cipicmp
					,cttl, csip, cdip, cmsbip, cmsb2ip, ctcphs, ctcpflagbyte, ctemp, css, cwscale,ctcpflag8;

    map<int, int> hctcpcon, hcudpcon;

	typename vector<Packet> :: iterator it;
	for(it = packet_list.begin(); it != packet_list.end(); it++){
		Packet p = *it;

		int sp, dp;
		if(p.sport > 0){
			sp = p.sport;
			dp = p.dport;
			if(sp > 1023){ 
				sp = 1024;
			}
			if(dp > 1023) dp = 1024;
			if(sp == 1024 && dp == 1024) cbh++;
			if(sp < 1024 && dp < 1024) cbl++;

		}
	
		if(p.v6 > 0){
			pktcountv6++;
			bytecountv6 += p.pktsize;
			cipv6prot[p.protocol]++;
			if (p.icmptype>-1) cipv6icmp[p.icmptype]++;
            else if (p.protocol==6 && p.sport>0){
                cipv6tcppnum[sp]++;
                cipv6tcppnum[dp]++;
            }
            else if (p.protocol==17 && p.sport>0){
                cipv6udppnum[sp]++;
                cipv6udppnum[dp]++;
            }
		}
		else if(p.v4 > 0){
			pktcount++;
			cipprot[p.protocol]++;
			bytecount += p.pktsize;
			if (p.ttl >= 0) cttl[p.ttl]++;
            csip[p.sip]++;
            cdip[p.dip]++;
            cmsbip[p.sip>>24]++;
            cmsbip[p.dip>>24]++;
            cmsb2ip[p.sip>>16]++;
            cmsb2ip[p.dip>>16]++;

            if (p.os>0) fragcount++;
			if (p.protocol==1) cipicmp[p.icmptype]++;

			/*tuple<long, long, int, int> comb1(p.sip,p.dip, p.sport, p.dport), 
										comb2(p.dip, p.sip, p.dport, p.sport); // Two way combination of source IP/port and Dest IP/port. */
			int hash1 = hashCode({p.sip, p.dip, (long)p.sport, (long)p.dport});
			int hash2 = hashCode({p.dip, p.sip, (long)p.dport, (long)p.sport});
            if (p.protocol==17 && p.sport>0){
                cipudppnum[sp]++; 
                cipudppnum[dp]++;
                //cudpcon[comb1]++; 
                //cudpcon[comb2]++;
                hcudpcon[hash1]++;
                hcudpcon[hash2]++;
            }

			
			if (p.protocol==6 and p.sport>0){
				if (p.ws==0) ws0++;
				if (p.ss>0) css[p.ss]++;
				if (p.wscale>0) cwscale[p.wscale]++;
				if (p.sap>0) countsap++;
				if (p.tse>0) counttse++;
				if (p.sa>0) countsa++;

				ciptcppnum[sp]++;
                ciptcppnum[dp]++;
                //ctcpcon[comb1]++; 
                //ctcpcon[comb2]++;
                hctcpcon[hash1]++;
                hctcpcon[hash2]++;
                if (p.hs>-1) ctcphs[p.hs]++;

				if (p.fb>-1){
					ctcpflagbyte[p.fb]++;
                    if (p.fb&(1<<0))  ctcpflag8[TH_FIN]++;
                    if (p.fb&(1<<1))  ctcpflag8[TH_SYN]++;
                    if (p.fb&(1<<2))  ctcpflag8[TH_RST]++;
                    if (p.fb&(1<<3))  ctcpflag8[TH_PUSH]++;
                    if (p.fb&(1<<4))  ctcpflag8[TH_ACK]++;
                    if (p.fb&(1<<5))  ctcpflag8[TH_URG]++;
                    if (p.fb&(1<<6))  ctcpflag8[TH_ECE]++;
                    if (p.fb&(1<<7))  ctcpflag8[TH_CWR]++;
					if ( (p.fb&(1<<2)) && (p.ws==0) ) rsw0+=1;
				}
			}
		}

	}

	//Store aggregated values into structure PacketGroup
	{

		g->starttime = starttime;

		/* Integer Counters */
		g->pktcount = pktcount;
		g->pktcountv6 = pktcountv6;
		g->bytecount = bytecount;
		g->bytecountv6 = bytecountv6;

		g->counters.lcttl = cttl.size();
		g->counters.lcsip = csip.size();
		g->counters.lcdip = cdip.size();
		g->counters.lcmsbip = cmsbip.size();
		g->counters.lcmsb2ip = cmsb2ip.size();
		g->counters.lctcpcon = hctcpcon.size();
		g->counters.lcudpcon = hcudpcon.size();

		g->cbl = cbl;
		g->cbh = cbh;
		g->ws0 = ws0;
		g->rsw0 = rsw0;
		g->fragcount = fragcount;
		g->countsap = countsap;
		g->countsa = countsa;

		g->counters.cttl = entropy(cttl);
	    g->counters.csip = entropy(csip);
	    g->counters.cdip = entropy(cdip);
	    g->counters.cmsbip = entropy(cmsbip);
	    g->counters.cmsb2ip = entropy(cmsb2ip);
		

		g->counttse = counttse;
		/*Integer Counters End */

		g->counters._cttl = cttl;
	    g->counters._csip = csip;
	    g->counters._cdip = cdip;
	    g->counters._cmsbip = cmsbip;
	    g->counters._cmsb2ip = cmsb2ip;

		/* Dictionary Counters */
		g->counters.cipv6prot = cipv6prot;
	    g->counters.cipprot = cipprot;
	    g->counters.cipv6tcppnum = cipv6tcppnum;
	    g->counters.ciptcppnum = ciptcppnum;
	    g->counters.cipv6udppnum = cipv6udppnum;
	    g->counters.cipudppnum = cipudppnum;
	    g->counters.cipv6icmp = cipv6icmp;
	    g->counters.cipicmp = cipicmp;
	    
	    g->counters._ctcpcon = hcudpcon;
	    g->counters._cudpcon = hcudpcon;
	    g->counters.ctcphs = ctcphs;
	    g->counters.ctcpflagbyte = ctcpflagbyte;
	    g->counters.ctemp = ctemp;
	    g->counters.css = css;
	    g->counters.cwscale = cwscale;
	    g->counters.ctcpflag8 = ctcpflag8;
		/*Dictionary Counters End*/

	}
}

void Parser::aggregatePackets(long starttime, vector<Packet> packet_list, PacketGroup* g){
	int pktcount= 0,bytecount=0,fragcount=0,pktcountv6=0,bytecountv6=0,countsap=0,countsa=0,counttse=0,cbl=0,cbh=0,ws0=0,rsw0=0;
	
	vector<PacketGroup> rows;
	map<int, int> 	cipv6prot, cipprot,cipv6tcppnum, ciptcppnum,cipv6udppnum, cipudppnum, cipv6icmp, cipicmp
					,cttl, csip, cdip, cmsbip, cmsb2ip, ctcphs, ctcpflagbyte, ctemp, css, cwscale,ctcpflag8;

    map<tuple<long, long, int, int>, int> ctcpcon, cudpcon;

    map<int, int> hctcpcon, hcudpcon;

	typename vector<Packet> :: iterator it;
	for(it = packet_list.begin(); it != packet_list.end(); it++){
		Packet p = *it;

		int sp, dp;
		if(p.sport > 0){
			sp = p.sport;
			dp = p.dport;
			if(sp > 1023){ 
				sp = 1024;
			}
			if(dp > 1023) dp = 1024;
			if(sp == 1024 && dp == 1024) cbh++;
			if(sp < 1024 && dp < 1024) cbl++;

		}
	
		if(p.v6 > 0){
			pktcountv6++;
			bytecountv6 += p.pktsize;
			cipv6prot[p.protocol]++;
			if (p.icmptype>-1) cipv6icmp[p.icmptype]++;
            else if (p.protocol==6 && p.sport>0){
                cipv6tcppnum[sp]++;
                cipv6tcppnum[dp]++;
            }
            else if (p.protocol==17 && p.sport>0){
                cipv6udppnum[sp]++;
                cipv6udppnum[dp]++;
            }
		}
		else if(p.v4 > 0){
			pktcount++;
			cipprot[p.protocol]++;
			bytecount += p.pktsize;
			if (p.ttl >= 0) cttl[p.ttl]++;
            csip[p.sip]++;
            cdip[p.dip]++;
            cmsbip[p.sip>>24]++;
            cmsbip[p.dip>>24]++;
            cmsb2ip[p.sip>>16]++;
            cmsb2ip[p.dip>>16]++;

            if (p.os>0) fragcount++;
			if (p.protocol==1) cipicmp[p.icmptype]++;

			/*tuple<long, long, int, int> comb1(p.sip,p.dip, p.sport, p.dport), 
										comb2(p.dip, p.sip, p.dport, p.sport); // Two way combination of source IP/port and Dest IP/port. */
			int hash1 = hashCode({p.sip, p.dip, (long)p.sport, (long)p.dport});
			int hash2 = hashCode({p.dip, p.sip, (long)p.dport, (long)p.sport});
            if (p.protocol==17 && p.sport>0){
                cipudppnum[sp]++; 
                cipudppnum[dp]++;
                hcudpcon[hash1]++;
                hcudpcon[hash2]++;
            }

			
			if (p.protocol==6 and p.sport>0){
				if (p.ws==0) ws0++;
				if (p.ss>0) css[p.ss]++;
				if (p.wscale>0) cwscale[p.wscale]++;
				if (p.sap>0) countsap++;
				if (p.tse>0) counttse++;
				if (p.sa>0) countsa++;

				ciptcppnum[sp]++;
                ciptcppnum[dp]++;
                hctcpcon[hash1]++;
                hctcpcon[hash2]++;
                if (p.hs>-1) ctcphs[p.hs]++;

				if (p.fb>-1){
					ctcpflagbyte[p.fb]++;
                    if (p.fb&(1<<0))  ctcpflag8[TH_FIN]++;
                    if (p.fb&(1<<1))  ctcpflag8[TH_SYN]++;
                    if (p.fb&(1<<2))  ctcpflag8[TH_RST]++;
                    if (p.fb&(1<<3))  ctcpflag8[TH_PUSH]++;
                    if (p.fb&(1<<4))  ctcpflag8[TH_ACK]++;
                    if (p.fb&(1<<5))  ctcpflag8[TH_URG]++;
                    if (p.fb&(1<<6))  ctcpflag8[TH_ECE]++;
                    if (p.fb&(1<<7))  ctcpflag8[TH_CWR]++;
					if ( (p.fb&(1<<2)) && (p.ws==0) ) rsw0+=1;
				}
			}
		}

	}

	//Store aggregated values into structure PacketGroup
	{

		g->starttime = starttime;

		/* Integer Counters */
		g->pktcount = pktcount;
		g->pktcountv6 = pktcountv6;
		g->bytecount = bytecount;
		g->bytecountv6 = bytecountv6;

		g->cbl = cbl;
		g->cbh = cbh;
		g->ws0 = ws0;
		g->rsw0 = rsw0;
		g->fragcount = fragcount;
		g->countsap = countsap;
		g->countsa = countsa;
		

		g->counttse = counttse;
		/*Integer Counters End */

		g->counters._cttl = cttl;
	    g->counters._csip = csip;
	    g->counters._cdip = cdip;
	    g->counters._cmsbip = cmsbip;
	    g->counters._cmsb2ip = cmsb2ip;
	    g->counters._ctcpcon = hctcpcon;
	    g->counters._cudpcon = hcudpcon;
	    

		/* Dictionary Counters */
		g->counters.cipv6prot = cipv6prot;
	    g->counters.cipprot = cipprot;
	    g->counters.cipv6tcppnum = cipv6tcppnum;
	    g->counters.ciptcppnum = ciptcppnum;
	    g->counters.cipv6udppnum = cipv6udppnum;
	    g->counters.cipudppnum = cipudppnum;
	    g->counters.cipv6icmp = cipv6icmp;
	    g->counters.cipicmp = cipicmp;
	    
	    g->counters._cudpcon = hcudpcon;
	    g->counters._ctcpcon = hctcpcon;
	    g->counters.ctcphs = ctcphs;
	    g->counters.ctcpflagbyte = ctcpflagbyte;
	    g->counters.ctemp = ctemp;
	    g->counters.css = css;
	    g->counters.cwscale = cwscale;
	    g->counters.ctcpflag8 = ctcpflag8;
		/*Dictionary Counters End*/
	}
  
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

	if (p.v4 > 0){
		p.protocol = ip->ip_p;					//Protocol
		p.pktsize = TRANSFORM(ip->ip_len);
		p.ttl = ip->ip_ttl;
		p.sip = (SHIFT(packet, 12, 24) + SHIFT(packet, 13, 16) + SHIFT(packet, 14, 8)) + (int) *(packet + 15);
		p.dip = (SHIFT(packet, 16, 24) + SHIFT(packet, 17, 16) + SHIFT(packet, 18, 8)) + (int) *(packet + 19);

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
			if(p.hs > 5){ //Options have three fields, 1. option kind(1 byte), 2. Option length, 3. Option Data(variable length)
				//If packet has TCP 1 byte Option-Type (0 for end of option), 1 byte option length, variable sized option data
				int i = 40; // Options start after 40 bytes of packet data.
				int val = (int)*(packet + i);
				while(val = (int)*(packet + i), val != 0){
					int option_size = (int)*(packet + i+ 1);
					if (val == 1){
						i++;
					}
					else if(val == 2 && option_size == 4){ //Option Type 2, Segment Size
						p.ss = TWOBYTE_TO_INT(packet, i + 2);
						i += option_size; //Increment Pointer by total option size

					}
					else if(val == 3 && option_size==3){ //Option Type 3, Window Scale
						p.wscale = (int)*(packet + i + 2);
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

					else break;
				}
				
			}

		}
	}

	if(p.v6 > 0){
		p.protocol = (int) *(packet + 6);
		p.pktsize = TWOBYTE_TO_INT(packet,4);
		if( p.protocol == 58){ //ICMP Protocol
			p.icmptype = (int)*(packet+ 40);
		}
		else if(p.protocol == 6 || p.protocol == 17){
			p.sport = TWOBYTE_TO_INT(packet,40);
			p.dport = TWOBYTE_TO_INT(packet,42);
		}
	}
	
	return p;
}



