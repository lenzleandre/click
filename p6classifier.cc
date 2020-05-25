#include <click/config.h>
#include <click/args.hh>
#include <click/error.hh>
#include "p6classifier.hh"

CLICK_DECLS

P6Classifier::P6Classifier()
{}

P6Classifier::~ P6Classifier()
{}

int P6Classifier::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (Args(conf, this, errh)
	.read_p("MAXPACKETSIZE", maxSize)
	.read_p("SRCPORT", srcport)
	.read_p("DSTPORT", dstport)
	.complete() < 0) return -1;
	if (maxSize <= 0) return errh->error("maxsize should be larger than 0");
	if (srcport == 0) return errh->error("Port different from 0 is needed to enable receiving a feedback!");
	return 0;
}

Packet* P6Classifier::simple_action(Packet *p){	
	//without extension headers
	click_ip6* p6 = (click_ip6*)(p ->network_header()); //pointer to network_header
	click_udp* pt6 = (click_udp*)(p6 +1); //  -pointer to transport_header());
	
	//With extension headers
	click_ip6* ip6 = (click_ip6*)(p->data()); // point to after IPheader
	
	struct click_ip6_hop_hop *hop_hd = (click_ip6_hop_hop*)(p6 + 1);//ip6
		 
	struct click_ip6_fragment_ext* frag_hd = (click_ip6_fragment_ext*)(hop_hd + 1);
	
	click_udp *pt_udp = (click_udp*)(frag_hd +1);
	
	click_chatter("Max possible packet is %d", maxSize); //fixing a packet length
	
	uint8_t extension = 0; // expression for extensions or non extensions
	
	// checking for next header for both cases extensions or non extensions
	if (p6 ->ip6_ctlun.ip6_un1.ip6_un1_nxt == extension?ip6_hop_code: IP_PROTO_UDP 
		&& (pt6 -> uh_sport != htons(srcport) && pt6 -> uh_dport != htons(dstport))){// combinatinatory condition:= both are required if are set in the script
		
		extended:
		
		p->kill();
		return 0;
		} 
		
	//Extension checking 	
	else if (p6 ->ip6_ctlun.ip6_un1.ip6_un1_nxt ==ip6_hop_code
			&& hop_hd ->hop_next_hdr == ip6_fragment_code
			&&frag_hd ->frag_nxt_hdr != IP_PROTO_UDP){
				
				goto extended;		
			}					
	else {	
		return p;
	}
}
CLICK_ENDDECLS
EXPORT_ELEMENT(P6Classifier)
