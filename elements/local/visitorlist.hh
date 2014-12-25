#ifndef VISITORLIST_HH_
#define VISITORLIST_HH_

#include <click/vector.cc>
#include <click/element.hh>
#include <clicknet/udp.h>
#include <clicknet/icmp.h>
#include <clicknet/ether.h>
#include <click/timer.hh>
#include "registrationrequest.hh"
#include "registrationreply.hh"
#include "visitorlistentry.hh"
CLICK_DECLS

class VisitorList : public Element {
    public:
        VisitorList();
        ~VisitorList();

        const char *class_name() const  { return "VisitorList"; }
        const char *port_count() const  { return "3/3"; }
        const char *processing() const  { return PUSH; }
        int configure(Vector<String>&, ErrorHandler*);
        int initialize(ErrorHandler*);

        VisitorListEntry* getEntry(uint32_t);
        VisitorListEntry* getEntry(in_addr);

        void run_timer(Timer*);

        void insertEntry(VisitorListEntry*);
        void deleteEntry(VisitorListEntry*);
        void printList();

        void push(int, Packet *);
    private:
        Vector<VisitorListEntry*> visList;
        in_addr ipAddr;

        Timer _timer;



};

CLICK_ENDDECLS



#endif
