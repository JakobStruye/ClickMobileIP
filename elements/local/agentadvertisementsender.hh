#ifndef CLICK_AGENTADVERTISEMENTSENDER_HH
#define CLICK_AGENTADVERTISEMENTSENDER_HH
#include <click/element.hh>
#include <click/timer.hh>
#include <clicknet/icmp.h>
#include <clicknet/ether.h>
#include "agentadvertisement.hh"
CLICK_DECLS

/**
 * This element generates agent advertisements and sends them periodically
 * Every INTERVAL msec, an advertisement for care of address IP with lifetime LIFETIME and
 * registration lifetime RLIFETIME will be sent
 */
class AgentAdvertisementSender : public Element { 
	public:
		AgentAdvertisementSender();
		~AgentAdvertisementSender();
		
		const char *class_name() const	{ return "AgentAdvertisementSender"; }
		const char *port_count() const	{ return "0/1"; }
		const char *processing() const	{ return PUSH; }
		int configure(Vector<String>&, ErrorHandler*);
		int initialize(ErrorHandler *);

		Packet* makePacket();
		void run_timer(Timer *);
		void push(int, Packet *);

    Timer _timer;
    int _interval;
    int _lifetime;
    int _registration_lifetime;
    uint16_t _seq_number;
    in_addr _address;
    bool _isHomeAgent;
    bool _isForeignAgent;

};

CLICK_ENDDECLS
#endif
