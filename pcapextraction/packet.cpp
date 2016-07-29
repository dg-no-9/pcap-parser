#include "packet.h"

string PacketGroup::buildjson(){
	stringstream json;

	json << "{";
	json <<"\"STARTTIME\":" << starttime << ',';
	json <<"\"PKTCOUNT\":" << pktcount << ',';
	json <<"\"BYTECOUNT\":" << bytecount << ',';
	json <<"\"PKTCOUNTV6\":" << pktcountv6 << ',';
	json <<"\"BYTECOUNTV6\":" << bytecountv6 << ',';

	json <<"\"CBL\":" << cbl << ',';
	json <<"\"CBH\":" << cbh << ',';
	json <<"\"WS0\":" << ws0 << ',';
	json <<"\"RSW0\":" << rsw0 << ',';
	json <<"\"COUNT_SAP\":" << countsap << ',';
	json <<"\"COUNT_SA\":" << countsa << ',';
	json <<"\"COUNTT_SE\":" << counttse << ',';
	json << this->counters.tojson();
	json << "}" << endl;

	//cout << json.str();
	return json.str();
}


inline void PacketGroup::printjson(char* filename){
	ofstream json(filename);
	json << this->buildjson();
	json.close();
}

string Counter::tojson(){
	stringstream json;

	json <<"\"LCTTL\":" << lcttl << ',';
	json <<"\"LCSIP\":" << lcsip << ',';
	json <<"\"LDIP\":" << lcdip << ',';
	json <<"\"LCMSBIP\":" << lcmsbip << ',';
	json <<"\"LCMS2BIP\":" << lcmsb2ip << ',';
	json <<"\"LCTPCON\":" << lctcpcon << ',';
	json <<"\"LCUDPCON\":" << lcudpcon << ',';

	json <<"\"ENT_CTTL\":" << cttl << ',';
	json <<"\"ENT_CSIP\":" << csip << ',';
	json <<"\"ENT_CDIP\":" << cdip << ',';
	json <<"\"ENT_CMSBIP\":" << cmsbip << ',';
	json <<"\"ENT_CMSB2IP\":" << cmsb2ip << ',';

	json <<"\"CMS_BIP\":" << this->dict_str(_cmsbip) << ',';

	json <<"\"CIP_PROT\":" << this->dict_str(cipprot) << ',';
	json <<"\"CIP_TCP_PNUM\":" << this->dict_str(ciptcppnum) << ',';
	json <<"\"CIP_UDP_PNUM\":" << this->dict_str(cipudppnum) << ',';
	json <<"\"CIP_ICMP\":" << this->dict_str(cipicmp) << ',';
	json <<"\"CTCPHS\":" << this->dict_str(ctcphs) << ',';
	json <<"\"CTCP_FLAGBYTE\":" << this->dict_str(ctcpflagbyte)  << ',';
	json <<"\"CTCP_FLAG8\":" << this->dict_str(ctcpflag8)  << ',';
	json <<"\"CSS\":" << this->dict_str(css)  << ',';
	json <<"\"CIPV6PROT\":" << this->dict_str(cipv6prot)  << ',';
	json <<"\"CIPV6TCPPNUM\":" << this->dict_str(cipv6tcppnum)  << ',';
	json <<"\"CIPV6UDPPNUM\":" << this->dict_str(cipv6udppnum);
	
	
	string ret = json.str();

	return ret;
}
