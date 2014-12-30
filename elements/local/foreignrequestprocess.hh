#ifndef FOREIGNREQUESTPROCESSOR_HH_
#define FOREIGNREQUESTPROCESSOR_HH_
#include <click/element.hh>
#include <clicknet/udp.h>
#include <clicknet/icmp.h>
#include <clicknet/ether.h>
#include <click/vector.cc>
#include "registrationrequest.hh"
#include "registrationreply.hh"

CLICK_DECLS

/**
 * Expects Registration Requests, will verify it and pass it along or deny it and respond with Reply
 */
class ForeignRequestProcess : public Element {
    public:
        ForeignRequestProcess();
        ~ForeignRequestProcess();

        const char *class_name() const  { return "ForeignRequestProcess"; }
        const char *port_count() const  { return "1/2"; }
        const char *processing() const  { return PUSH; }
        int configure(Vector<String>&, ErrorHandler*);

        static int addOwnIP(const String&, Element*, void*, ErrorHandler*);
        void add_handlers();

        WritablePacket* makeReply(RegistrationRequest*, int);
        void push(int, Packet *);

        Vector<String> _addrs;

        in_addr _care_of_address;

};

CLICK_ENDDECLS

#endif
