#ifndef CLICK_REGISTRATIONREQUESTSENDER_HH
#define CLICK_REGISTRATIONREQUESTSENDER_HH
#include <click/element.hh>
#include <clicknet/udp.h>
#include <clicknet/icmp.h>
#include <clicknet/ether.h>
#include <click/timer.hh>
#include <list>
#include "registrationrequest.hh"
#include "registrationreply.hh"
#include "pendingregistration.hh"


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

	    PendingRegistration* getEntry(uint32_t);
        void deleteEntry(PendingRegistration*);

        static String getGateway(Element*, void*);
        void add_handlers();


		Packet* makePacket();
        void run_timer(Timer *);
		void push(int, Packet *);

        IPAddress gateway;

	private:
	    Timer _timer;
	    bool isHome;
	    std::list<PendingRegistration*> _pendingRegistrations;


};

CLICK_ENDDECLS
#endif
