#ifndef CLICK_REGISTRATIONREQUESTSENDER_HH
#define CLICK_REGISTRATIONREQUESTSENDER_HH
#include <click/element.hh>
#include <clicknet/udp.h>
#include <clicknet/icmp.h>
#include <clicknet/ether.h>
#include <click/timer.hh>
#include "registrationrequest.hh"
CLICK_DECLS

class RegistrationRequestSender : public Element { 
	public:
		RegistrationRequestSender();
		~RegistrationRequestSender();
		
		const char *class_name() const	{ return "RegistrationRequestSender"; }
		const char *port_count() const	{ return "1/2"; }
		const char *processing() const	{ return PUSH; }
		int configure(Vector<String>&, ErrorHandler*);
	    int initialize(ErrorHandler *);


		Packet* makePacket();
        void run_timer(Timer *);
		void push(int, Packet *);

	private:
	    Timer _timer;


};

CLICK_ENDDECLS
#endif
