#ifndef MOBILITYBINDINGLIST_HH_
#define MOBILITYBINDINGLIST_HH_


#include <click/vector.hh>
#include <click/element.hh>
#include <clicknet/udp.h>
#include <clicknet/icmp.h>
#include <clicknet/ether.h>
#include <click/timer.hh>
#include "registrationrequest.hh"
#include "registrationreply.hh"
#include "mobilitybindinglistentry.hh"
CLICK_DECLS

/**
 * Mobility binding list for home agent: generates binding for incoming requests,
 * checks if bindings stay valid for incoming replies,
 * checks if incoming packets should be encapsulated,
 * sets IP addresses for encapsulated packets
 */
class MobilityBindingList : public Element {
    public:
        MobilityBindingList();
        ~MobilityBindingList();

        const char *class_name() const  { return "MobilityBindingList"; }
        const char *port_count() const  { return "4/5"; }
        const char *processing() const  { return PUSH; }
        int configure(Vector<String>&, ErrorHandler*);
        int initialize(ErrorHandler*);

        void run_timer(Timer*);

        MobilityBindingListEntry* getEntry(in_addr);
        void insertEntry(MobilityBindingListEntry*);
        void deleteEntry(MobilityBindingListEntry*);
        void printList();

        void push(int, Packet *);
    private:
        Vector<MobilityBindingListEntry*> mobilityList;

        Timer _timer;



};

CLICK_ENDDECLS







#endif
