
#ifndef CLICK_IP6SOURCE_HH
#define CLICK_IP6SOURCE_HH
#include <click/element.hh>
#include <click/glue.hh>
#include <click/atomic.hh>
#include <clicknet/ip6.h>
//#include "ip6_extended.h"
#include "ip6_extensions.h"
#include <clicknet/udp.h>
#include <click/ip6address.hh>

CLICK_DECLS

/** 
 * Basing on the concept of grouping elements in larger elements:
 * 
 * We need to concatinate the RandomSource of packet with IP6header to generate IP6 packets.
 * We would map an IP6header to any generated packet in order to ensure that the outpoing is IP6 size packet.
 * 
 * IP6_out_packet = const IP6header + generated_part()
 * 
 * */

class IP6Source : public Element{ 
	public:
	
	IP6Source();
	~IP6Source();
		
			
	const char *class_name() const	{ return "IP6Source"; }
	const char *port_count() const	{ return "1/1"; }
	const char *processing() const	{ return PUSH; }
	
	int configure(Vector<String> &, ErrorHandler *);
	
	//void add_handlers();
		
	void push(int, Packet *);
	
	private:
	
	click_ip6 _iph6;
	IP6Address _src;
	IP6Address _dst;		
	click_ip6_fragment_ext _frag6_xt;
	click_ip6_authentication _auth6_xt;
	
	//click_ip6_ext _iph6_xt;
};

CLICK_ENDDECLS
#endif
