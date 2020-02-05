
#include <click/config.h>
#include <click/args.hh>
#include <click/error.hh>
#include <click/router.hh>
#include <click/standard/alignmentinfo.hh>
#include <click/glue.hh>
#include "ip6source.hh"


CLICK_DECLS

// set up IP6 header

IP6Source::IP6Source()	
{}

IP6Source::~IP6Source()
{}

int IP6Source::configure(Vector<String> &conf, ErrorHandler *errh){
	
	//IP6Address src;
	//IP6Address dst;	
	memset(&_iph6, 0, sizeof(click_ip6));
	/*
	if (Args(conf, this, errh)
	.read_mp("SRC_IP", _src)
	.read_mp("DST_IP", _dst)
	.complete() < 0) return -1;
	*/
	_iph6.ip6_src = _src;
	_iph6.ip6_dst = _dst;
	
    return 0;
}
	
void IP6Source::push(int, Packet *p_in){
		
	unsigned int offset_hd = sizeof(click_ip6); //initially only the size ip6 packet fixed header
	unsigned int extensions_size = sizeof(click_ip6_fragment_ext); //it keeps to be flexible as more extension header join.
	
	unsigned int header_size = offset_hd + extensions_size;
	
	/**initialisation of ptr p*/
			
	WritablePacket *p = p_in->push(header_size);
	
	memset(p->data(), 0, header_size); // memset(p->data(), 0, sizeof(click_ip6));
			    	
	//click_ip6 *ip6 = reinterpret_cast<click_ip6 *>(p->data());
	
	/**ip6 point initialization */
	click_ip6* ip6 = (click_ip6*)(p->data());
	
	ip6 ->ip6_ctlun.ip6_un3.ip6_un3_v = 0x06;	//version
	ip6 ->ip6_ctlun.ip6_un2_vfc = 0x00; //traffic class
	ip6 ->ip6_ctlun.ip6_un1.ip6_un1_flow = 0x00;	//flow label
	ip6 ->ip6_ctlun.ip6_un1.ip6_un1_plen = sizeof(click_ip6);	//palyload len
	ip6 ->ip6_ctlun.ip6_un1.ip6_un1_nxt = ip6_fragment_code; //44	next header
	ip6 ->ip6_ctlun.ip6_un1.ip6_un1_hlim = 250; //hop limit
	//ip6 ->ip6_src = 
	//ip6 ->ip6_dst =
	
	click_ip6_fragment_ext* frag_hd = (click_ip6_fragment_ext*)(ip6 + 1); //connecting a hierarchical active headers in a packet
	
	frag_hd ->frag_nxt_hdr = IP_PROTO_UDP; //17; // udp code for transport layer segments
	frag_hd ->frag_reserved = 0;
	frag_hd ->frag_offset = 0;
	
	//struct click_ip6_authentication * auth_hd = (struct click_ip6_authentication*)(frag_hd + 1); //connecting a hierarchical active headers in a packet fragmentation to auth
		
	memcpy(ip6, &_iph6, offset_hd);
	//memcpy(ip6, &_frag6_xt, sizeof(click_ip6_fragment_ext));
	
	if (ip6 ->ip6_nxt == 44){
		ip6->ip6_plen = htons(p->length() + sizeof(click_ip6_fragment_ext) + sizeof(struct click_ip6_authentication));
	}
	//p->set_ip6_header(ip6,offset_hd);
	p->set_ip6_header(ip6, (sizeof(p->ip6_header())+ extensions_size));
	
	output(0).push(p);
	click_chatter("The IP6 packet", p->length());
}
	
CLICK_ENDDECLS
EXPORT_ELEMENT(IP6Source)
  
