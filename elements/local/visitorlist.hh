#ifndef VISITORLIST_HH_
#define VISITORLIST_HH_

#include <vector>
#include <click/element.hh>
#include <clicknet/udp.h>
#include <clicknet/icmp.h>
#include <clicknet/ether.h>
#include "registrationrequest.hh"
#include "registrationreply.hh"
#include "visitorlistentry.hh"
CLICK_DECLS

class VisitorList : public Element {
    public:
        VisitorList();
        ~VisitorList();

        const char *class_name() const  { return "VisitorList"; }
        const char *port_count() const  { return "2/2"; }
        const char *processing() const  { return PUSH; }
        int configure(Vector<String>&, ErrorHandler*);

        VisitorListEntry* getEntry(uint32_t);
        void insertEntry(VisitorListEntry*);
        void deleteEntry(VisitorListEntry*);

        void push(int, Packet *);
    private:
        std::vector<VisitorListEntry*> visList;


};

CLICK_ENDDECLS



#endif
