#include <iostream>
#include <cstdlib>
#include <sstream>
#include <fstream>
#include <map>
#include <vector>
#include <string>

using namespace std;
typedef struct time_s
{
	long seconds;
	long milliseconds;
}time_s;

struct Packet{
	Packet() : v4(-1),v6(-1),protocol(-1),pktsize(-1)
				,sip(-1),dip(-1),sport(-1),dport(-1),os(-1)
				,ttl(-1),frag(-1),hs(-1),ws(-1),fb(-1),ss(-1)
				,wscale(-1),sap(-1),sa(-1),tse(-1),icmptype(-1)
				{}

	int v4;
	int v6;
	int protocol;
	long pktsize;
	long sip;
	long dip;
	int sport;
	int dport;
	int os;
	int ttl;
	int frag;
	int hs;
	int ws;
	int fb;
	int ss;
	int wscale;
	int sap;
	int sa;
	int tse;
	int icmptype;

	void print(){
		printf("%d,%d,%d,%ld,%ld,%ld,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n", 
				v4,v6,protocol,pktsize,sip,dip,sport,dport,os,ttl,hs,ws,fb,ss,wscale,sap,sa,tse,icmptype);
	}

};

struct Counter{
	public:
		Counter():	cttl(0.0),csip(0.0), cdip(0.0), cmsbip(0.0), cmsb2ip(0.0)
					,lcttl(0), lcsip(0), lcdip(0), lcmsbip(0), lcmsb2ip(0), lctcpcon(0), lcudpcon(0)
					 {}
		map<int, int>
		cipv6prot, 
	    cipprot,
	    cipv6tcppnum, 
	    ciptcppnum,
	    cipv6udppnum,
	    cipudppnum, 
	    cipv6icmp, 
	    cipicmp,
	     
	    ctcphs, 
	    ctcpflagbyte,  
	    ctemp,
	    css, 
	    cwscale,
	    ctcpflag8;
	    //,hctcpcon,hcudpcon;

	    map<int, int> _cttl, _csip, _cdip, _cmsbip, _cmsb2ip, _ctcpcon, _cudpcon; //Maps whose entropy matters

	    /*map<tuple<long, long, int, int>, int> ctcpcon,cudpcon;*/
	    float cttl, csip, cdip, cmsbip, cmsb2ip; //Entropy Counters

	    int lcttl, lcsip, lcdip, lcmsbip, lcmsb2ip, lctcpcon, lcudpcon; //Length Counters

	    void print(){}

	    string tojson();
	    

    private:
		template <typename T>
		void printdict(map<T, int> m){
			typename map<T, int>::iterator it;
			cout << '{';
			for(it = m.begin(); it != m.end(); it++){
				if(it != m.begin()) cout << ',';
				cout <<' '<<it->first << ":" << it->second << ' ';
			}
			
			cout << '}' << endl;
		}

		template <typename T>
		string dict_str(map<T, int> m){
			typename map<T, int>::iterator it;
			stringstream out;
			out << '[';
			for(it = m.begin(); it != m.end(); it++){
				if(it != m.begin()) out << ',';
				out <<'('<<it->first << "," << it->second << ')';
			}
			
			out << ']';
			return out.str();
		}

		template <typename T>
		void printtupledict(map<T, int> m){
			typename map<T, int>::iterator it;
			cout << '[';
			for(it = m.begin(); it != m.end(); it++){
				if(it != m.begin()) cout << ',';
				cout << "(" << get<0>(it->first) << get<1>(it->first);
				
				cout <<"):" << it->second;
			}
			
			cout << ']' << endl;
		}

};

struct PacketGroup{
	public:
		PacketGroup():  pktcount(0),bytecount(0),fragcount(0)
						,pktcountv6(0),bytecountv6(0),countsap(0),countsa(0)
						,counttse(0),cbl(0),cbh(0),ws0(0),rsw0(0)
						{}
		long starttime;
		long prevtime;

		int pktcount;
		int bytecount;
		int fragcount;
		int pktcountv6;
		int bytecountv6;

		int cbl;
		int cbh;
		int ws0;
		int rsw0;

		int countsap;
		int countsa;
		int counttse;


		struct Counter counters; //Struct for dictionaries.

		void print(){
		}

		void printjson(char* filename);

		string buildjson();

};