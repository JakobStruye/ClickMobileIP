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

/**
 * Generates Registration Requests triggered by advertisements and (nearly) timed out registrations
 *
 * Receives Replies to its Requests
 */
class RegistrationRequestSender : public Element { 
	public:
		RegistrationRequestSender();
		~RegistrationRequestSender();
		
		const char *class_name() const	{ return "RegistrationRequestSender"; }
		const char *port_count() const	{ return "1/2"; }
		const char *processing() const	{ return PUSH; }
		int configure(Vector<String>&, ErrorHandler*);
	    int initialize(ErrorHandler *);

	    PendingRegistration* getRegistration(uint32_t);
        void deleteRegistration(PendingRegistration*);

        static String getGateway(Element*, void*);
        void add_handlers();

        SavedAdvertisement* getAdvertisement(in_addr);
        void deleteAdvertisement(in_addr);


		Packet* makePacket(in_addr, int);
        void run_timer(Timer *);
		void push(int, Packet *);

        IPAddress gateway;

	private:
	    Timer _timer;
	    bool _isRegistered; //true if node has an active registration
	    Vector<PendingRegistration*> _pendingRegistrations;
        Vector<SavedAdvertisement*> _savedAdvertisements; //max 1 advertisement per agent

	    unsigned _remaining_lifetime; //Remaining lifetime of current registration (0 means no registration or at home)
	    bool _hasReregistered; //True if registration request has been sent to an agent already registered to (no Reply received yet)

	    in_addr _home_agent;
	    in_addr _home_address;
	    in_addr _care_of_address;

	    //Identification fields for next registration
	    uint32_t _lowerIdentification;
	    uint32_t _upperIdentification;
};

CLICK_ENDDECLS
#endif
