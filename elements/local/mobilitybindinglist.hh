#ifndef MOBILITYBINDINGLIST_HH_
#define MOBILITYBINDINGLIST_HH_


#include <list>
#include <click/element.hh>
#include <clicknet/udp.h>
#include <clicknet/icmp.h>
#include <clicknet/ether.h>
#include "registrationrequest.hh"
#include "registrationreply.hh"
#include "mobilitybindinglistentry.hh"
CLICK_DECLS

class MobilityBindingList : public Element {
    public:
        MobilityBindingList();
        ~MobilityBindingList();

        const char *class_name() const  { return "MobilityBindingList"; }
        const char *port_count() const  { return "3/4"; }
        const char *processing() const  { return PUSH; }
        int configure(Vector<String>&, ErrorHandler*);

        MobilityBindingListEntry* getEntry(in_addr);
        void insertEntry(MobilityBindingListEntry*);
        void deleteEntry(MobilityBindingListEntry*);
        void printList();

        void push(int, Packet *);
    private:
        std::list<MobilityBindingListEntry*> mobilityList;



};

CLICK_ENDDECLS







#endif
