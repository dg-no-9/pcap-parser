#include "parser.h"

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
	/*a=ctr.values()
    b=sum(a)
    al=numpy.asarray(a)
    al=al/float(b)
    return -sum(numpy.log(al)*al)*/
}

void Parser::parse(const char* filename, float slicetime){
	this->readAndFillMap(filename, slicetime);
	typename map<long, vector<Packet> > ::iterator it;

	for(it = packets.begin(); it != packets.end(); it++){
		//cout << it->first << " " << it->second.size() << endl;
		this->aggregate(it->first, it->second);
	}
	return;
	typename vector<PacketGroup>::iterator git;

	for(git = aggregated.begin(); git != aggregated.end(); git++ ){
		((PacketGroup)(*git)).print();
	}

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
			//cout << "Start Time:" << starttime << endl;
		}
		if(count > 1 && ts > (starttime+slice)){
			//vector<Packet> _new(v);
			packets[starttime] = v;
			v.clear();
			slicecount++;

			prevtime = starttime;
			starttime += slice;
		}
		//if(slicecount == 100) break;

	}
}

PacketGroup Parser::aggregate(long starttime, vector<Packet> packet_list){
	int pktcount= 0,bytecount=0,fragcount=0,pktcountv6=0,bytecountv6=0,countsap=0,countsa=0,counttse=0,cbl=0,cbh=0,ws0=0,rsw0=0;
	
	vector<PacketGroup> rows;
	map<int, int> 	cipv6prot, cipprot,cipv6tcppnum, ciptcppnum,cipv6udppnum, cipudppnum, cipv6icmp, cipicmp
					,cttl, csip, cdip, cmsbip, cmsb2ip, ctcphs, ctcpflagbyte, ctemp, css, cwscale,ctcpflag8;

    map<tuple<long, long, int, int>, int> ctcpcon, cudpcon;

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

			tuple<long, long, int, int> comb1(p.sip,p.dip, p.sport, p.dport), 
										comb2(p.dip, p.sip, p.dport, p.sport); // Two way combination of source IP/port and Dest IP/port.
            if (p.protocol==17 && p.sport>0){
                cipudppnum[sp]++; 
                cipudppnum[dp]++;
                cudpcon[comb1]++; 
                cudpcon[comb2]++;
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
                cudpcon[comb1]++; 
                cudpcon[comb2]++;
                
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
	PacketGroup g;
	{

		g.starttime = starttime;

		/* Integer Counters */
		g.pktcount = pktcount;
		g.pktcountv6 = pktcountv6;
		g.bytecount = bytecount;
		g.bytecountv6 = bytecountv6;

		g.counters.lcttl = cttl.size();
		g.counters.lcsip = csip.size();
		g.counters.lcdip = cdip.size();
		g.counters.lcmsbip = cmsbip.size();
		g.counters.lcmsb2ip = cmsb2ip.size();
		g.counters.lctcpcon = ctcpcon.size();
		g.counters.lcudpcon = cudpcon.size();

		g.cbl = cbl;
		g.cbh = cbh;
		g.ws0 = ws0;
		g.rsw0 = rsw0;
		g.fragcount = fragcount;
		g.countsap = countsap;
		g.countsa = countsa;

		g.counters.cttl = entropy(cttl);
	    g.counters.csip = entropy(csip);
	    g.counters.cdip = entropy(cdip);
	    g.counters.cmsbip = entropy(cmsbip);
	    g.counters.cmsb2ip = entropy(cmsb2ip);
		
		g.counttse = counttse;
		/*Integer Counters End */

		/* Dictionary Counters */
		g.counters.cipv6prot = cipv6prot;
	    g.counters.cipprot = cipprot;
	    g.counters.cipv6tcppnum = cipv6tcppnum;
	    g.counters.ciptcppnum = ciptcppnum;
	    g.counters.cipv6udppnum = cipv6udppnum;
	    g.counters.cipudppnum = cipudppnum;
	    g.counters.cipv6icmp = cipv6icmp;
	    g.counters.cipicmp = cipicmp;
	    
	    g.counters.ctcpcon = ctcpcon;
	    g.counters.cudpcon = cudpcon;
	    g.counters.ctcphs = ctcphs;
	    g.counters.ctcpflagbyte = ctcpflagbyte;
	    g.counters.ctemp = ctemp;
	    g.counters.css = css;
	    g.counters.cwscale = cwscale;
	    g.counters.ctcpflag8 = ctcpflag8;
		/*Dictionary Counters End*/
	}

	return g;
  
}

int Parser::parseold(const char* filename, float slicetime){
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
	long count = 0;
	bool flag = true;
	vector<PacketGroup> rows;
	int rowcount = 0;
	map<int, int> 
	cipv6prot, 
    cipprot,
    cipv6tcppnum, 
    ciptcppnum,
    cipv6udppnum,
    cipudppnum, 
    cipv6icmp, 
    cipicmp,
    cttl, 
    csip, 
    cdip, 
    cmsbip, 
    cmsb2ip, 
    ctcphs, 
    ctcpflagbyte, 
    ctemp,
    css, 
    cwscale,
    ctcpflag8;

    map<tuple<long, long, int, int>, int> ctcpcon, cudpcon;

	while(packet = pcap_next(handle, &header), packet != NULL ){
		
		ts = (long)header.ts.tv_sec*1000000 + (long)header.ts.tv_usec;
		Packet p = this->getFromPacket(header, packet);
		//p.t.seconds = (long)header.ts.tv_sec;
		//p.t.milliseconds = (long)header.ts.tv_usec;
		count++;
		if(count == 1){
			starttime = ts;
			prevtime = starttime;
			cout << "Start Time:" << starttime << endl;
		}
		if(count > 1 && ts > (starttime+slice)){
			PacketGroup g;
			rowcount++;
			g.starttime = starttime;
			g.prevtime = prevtime;
			/* Integer Counters */
			g.pktcount = pktcount;
			g.pktcountv6 = pktcountv6;
			g.bytecount = bytecount;
			g.bytecountv6 = bytecountv6;

			g.counters.lcttl = cttl.size();
			g.counters.lcsip = csip.size();
			g.counters.lcdip = cdip.size();
			g.counters.lcmsbip = cmsbip.size();
			g.counters.lcmsb2ip = cmsb2ip.size();
			g.counters.lctcpcon = ctcpcon.size();
			g.counters.lcudpcon = cudpcon.size();

			g.cbl = cbl;
			g.cbh = cbh;
			g.ws0 = ws0;
			g.rsw0 = rsw0;
			g.fragcount = fragcount;
			g.countsap = countsap;
			g.countsa = countsa;

			g.counters.cttl = entropy(cttl);
		    g.counters.csip = entropy(csip);
		    g.counters.cdip = entropy(cdip);
		    g.counters.cmsbip = entropy(cmsbip);
		    g.counters.cmsb2ip = entropy(cmsb2ip);
			
			g.counttse = counttse;
			/*Integer Counters End */

			/* Dictionary Counters */
			g.counters.cipv6prot = cipv6prot;
		    g.counters.cipprot = cipprot;
		    g.counters.cipv6tcppnum = cipv6tcppnum;
		    g.counters.ciptcppnum = ciptcppnum;
		    g.counters.cipv6udppnum = cipv6udppnum;
		    g.counters.cipudppnum = cipudppnum;
		    g.counters.cipv6icmp = cipv6icmp;
		    g.counters.cipicmp = cipicmp;
		    
		    g.counters.ctcpcon = ctcpcon;
		    g.counters.cudpcon = cudpcon;
		    g.counters.ctcphs = ctcphs;
		    g.counters.ctcpflagbyte = ctcpflagbyte;
		    g.counters.ctemp = ctemp;
		    g.counters.css = css;
		    g.counters.cwscale = cwscale;
		    g.counters.ctcpflag8 = ctcpflag8;
			/*Dictionary Counters End*/

			rows.push_back(g);
			//if (rowcount == 10){exit(0);}
			//g.print(); 

			pktcount=bytecount=pktcountv6=bytecountv6=cbl=cbh=fragcount=countsap=counttse=countsa=ws0=rsw0=0;
			cipv6prot.clear();
			cipprot.clear();
		    cipv6tcppnum.clear();
		    ciptcppnum.clear();
		    cipv6udppnum.clear();
		    cipudppnum.clear();
		    cipv6icmp.clear();
		    cipicmp.clear();
		    cttl.clear();
		    csip.clear();
		    cdip.clear();
		    cmsbip.clear();
		    cmsb2ip.clear();
		    ctcpcon.clear();
		    cudpcon.clear();
		    ctcphs.clear();
		    ctcpflagbyte.clear();
		    ctemp.clear();
		    css.clear();
		    cwscale.clear();
		    ctcpflag8.clear();
		    prevtime = starttime;
			starttime += slice;
		}
		int sp, dp;
		if(p.sport > 0){
			sp = p.sport;
			dp = p.dport;
			if(sp > 1023){ 
				sp = 1024;
				tcount++;
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

			tuple<long, long, int, int> comb1(p.sip,p.dip, p.sport, p.dport), 
										comb2(p.dip, p.sip, p.dport, p.sport); // Two way combination of source IP/port and Dest IP/port.
            if (p.protocol==17 && p.sport>0){
                cipudppnum[sp]++; 
                cipudppnum[dp]++;
                //cudpcon[comb1]++; 
                //cudpcon[comb2]++;
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
                //cudpcon[comb1]++; 
                //cudpcon[comb2]++;
                
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

		//if(count == 20) exit(0);
	}
	cout << "Total Packets:" << count << endl;
	cout << "End Time:" << starttime << endl;
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

	if (p.v4 > 0){
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
				int i = 40; // Options are 40 byte afterwards
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
			//cout << p.sport << "," << p.dport<< endl;
		}
	}
	
	return p;
}



