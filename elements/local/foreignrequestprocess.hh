#ifndef FOREIGNREQUESTPROCESSOR_HH_
#define FOREIGNREQUESTPROCESSOR_HH_
#include <click/element.hh>
#include <clicknet/udp.h>
#include <clicknet/icmp.h>
#include <clicknet/ether.h>
#include "registrationrequest.hh"
CLICK_DECLS

class ForeignRequestProcess : public Element {
    public:
        ForeignRequestProcess();
        ~ForeignRequestProcess();

        const char *class_name() const  { return "ForeignRequestProcess"; }
        const char *port_count() const  { return "1/1"; }
        const char *processing() const  { return PUSH; }
        int configure(Vector<String>&, ErrorHandler*);

        Packet* makeReply();
        void push(int, Packet *);

};

CLICK_ENDDECLS

#endif
