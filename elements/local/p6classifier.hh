#ifndef CLICK_P6CLSSIFIER_HH
#define CLICK_P6CLASSIFIER_HH
#include <click/element.hh>
#include "ip6source.hh"
CLICK_DECLS

class P6Classifier : public Element { 
	public:
		P6Classifier();
		~P6Classifier();
		
		const char *class_name() const	{ return "P6Classifier"; }
		const char *port_count() const	{ return "1/1"; }
		const char *processing() const	{ return AGNOSTIC; }
		int configure(Vector<String>&, ErrorHandler*);
		
		Packet *simple_action(Packet *);
	private:	
				
		uint32_t maxSize;
		uint16_t srcport;
		uint16_t dstport;
		
};

CLICK_ENDDECLS
#endif
