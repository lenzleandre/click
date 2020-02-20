
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
	unsigned int extensions_size = sizeof(click_ip6_hop_hop )+ sizeof(click_ip6_fragment_ext);
	//unsigned int extensions_size = sizeof(click_ip6_fragment_ext) + sizeof(click_ip6_authentication) + sizeof(click_ip6_hop_hop);  
	//it keeps to be flexible as more extension header join.
	
	unsigned int headers_size = offset_hd + extensions_size;
	
	/**initialisation of ptr p*/
			
	WritablePacket *p = p_in->push(headers_size);
	
	memset(p->data(), 0, headers_size); // memset(p->data(), 0, sizeof(click_ip6));
			    	
	//click_ip6 *ip6 = reinterpret_cast<click_ip6 *>(p->data());
	
	/**ip6 point initialization */
	click_ip6* ip6 = (click_ip6*)(p->data());
	
	 /**Big endian  order*/
	 /**20 bits(flow label), 
	 //8 bits(trf cl)
		//Differentiated Service(DS) field used to classify packets :6bits
		//Explicit Congestion Notification(ECN):2bits
	 //4 bits(version)*/
	ip6 ->ip6_ctlun.ip6_un1.ip6_un1_flow = 0b011000000000110000011000001100010;	 
	ip6 ->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(p->length() - sizeof(click_ip6)); // IPV6 packet payload length
	ip6 ->ip6_ctlun.ip6_un1.ip6_un1_nxt =  ip6_hop_code;  //0x00= 0 :next header*/
	ip6 ->ip6_ctlun.ip6_un1.ip6_un1_hlim = 250; //hop limit
	//ip6 ->ip6_src = 
	//ip6 ->ip6_dst =
	
	struct click_ip6_hop_hop *hop_hd = (click_ip6_hop_hop*)(ip6 + 1);	
	hop_hd ->hop_next_hdr = ip6_fragment_code;//0x2c= 44 :next header*/
	hop_hd ->hop_ext_len = 0; //jumbo gram
	hop_hd ->hop_options_padd = 0;
	hop_hd -> hop_options_padding = 0;
	 
	struct click_ip6_fragment_ext* frag_hd = (click_ip6_fragment_ext*)(hop_hd + 1); //hierarchical connection of ip6header and fragmentation E_header in a packet
	
	frag_hd ->frag_nxt_hdr = IP_PROTO_UDP; // 1 byte, 0X11 = 17; // udp code for transport layer segments //ip6_auth_code; // 0x33 = 51
	frag_hd ->frag_reserved = 0;
	frag_hd ->frag_offset = 1500; //ntohs(1500);	
	frag_hd ->frag_id =0;	
	
	/**
	 * 		  
	struct click_ip6_authentication * auth_hd = (click_ip6_authentication*)(frag_hd + 1); //hierarchical connection of fragmentation with authentication E_hin a packet fragmentation to auth
	auth_hd ->next_header = IP_PROTO_UDP; // 1 byte, 0X11 = 17; // udp code for transport layer segments
	auth_hd -> payload_len = 24; //1byte considered eg of 24 octet units
	auth_hd -> reserved =0; //2bytes
	auth_hd -> spi = 15; //4bytes
	
	auth_hd -> seq_num = 0;	 //4bytes
	auth_hd -> integ_check_v.auth_icv=1; //4*3bytes; it is x3 because of AH len restriction in ip6 to be multiple of 8
	*/
		
	output(0).push(p);
	
	click_chatter("The IP6 packet %d \n", p->length());
	//click_chatter("size of click_ip6 fixed hdr :%d", auth_hd -> seq_num);
}
	
CLICK_ENDDECLS
EXPORT_ELEMENT(IP6Source)
  
