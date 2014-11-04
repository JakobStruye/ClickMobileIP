#ifndef CLICK_AGENTSOLICITATIONSENDER_HH
#define CLICK_AGENTSOLICITATIONSENDER_HH
#include <click/element.hh>
#include <click/timer.hh>
#include <clicknet/icmp.h>
#include <clicknet/ether.h>
#include "icmpagentsolicitation.hh"
CLICK_DECLS


class AgentSolicitationSender : public Element { 
	public:
		AgentSolicitationSender();
		~AgentSolicitationSender();
		
		const char *class_name() const	{ return "AgentSolicitationSender"; }
		const char *port_count() const	{ return "0/1"; }
		const char *processing() const	{ return PUSH; }
		int configure(Vector<String>&, ErrorHandler*);
    int initialize(ErrorHandler *);

		Packet* makePacket();
		void run_timer(Timer *);
		void push(int, Packet *);

		Packet* solicitation;
    Timer _timer;

};

CLICK_ENDDECLS
#endif
