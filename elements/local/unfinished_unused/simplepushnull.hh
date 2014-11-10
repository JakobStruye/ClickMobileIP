#ifndef CLICK_SIMPLEPUSHNULL_HH
#define CLICK_SIMPLEPUSHNULL_HH
#include <click/element.hh>
CLICK_DECLS

class SimplePushNull : public Element { 
	public:
		SimplePushNull();
		~SimplePushNull();
		
		const char *class_name() const	{ return "SimplePushNull"; }
		const char *port_count() const	{ return "1/1"; }
		const char *processing() const	{ return PUSH; }
		int configure(Vector<String>&, ErrorHandler*);
		
		void push(int, Packet *);
};

CLICK_ENDDECLS
#endif
