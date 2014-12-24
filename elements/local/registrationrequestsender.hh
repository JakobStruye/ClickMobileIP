#ifndef CLICK_REGISTRATIONREQUESTSENDER_HH
#define CLICK_REGISTRATIONREQUESTSENDER_HH
#include <click/element.hh>
#include <clicknet/udp.h>
#include <clicknet/icmp.h>
#include <clicknet/ether.h>
#include <click/timer.hh>
#include <click/vector.cc>
#include "registrationrequest.hh"
#include "registrationreply.hh"
#include "pendingregistration.hh"
#include "agentadvertisement.hh"
#include "savedadvertisement.hh"



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

        SavedAdvertisement* getEntry(in_addr);


		Packet* makePacket(in_addr care_of);
        void run_timer(Timer *);
		void push(int, Packet *);

        IPAddress gateway;

	private:
	    Timer _timer;
	    bool _isRegistered;
	    Vector<PendingRegistration*> _pendingRegistrations;
        Vector<SavedAdvertisement*> _savedAdvertisements;

	    unsigned _remaining_lifetime;

	    in_addr _home_agent;
	    in_addr _home_address;
	    in_addr _care_of_address;


};

CLICK_ENDDECLS
#endif
