#ifndef FOREIGNREPLYPROCESS_HH_
#define FOREIGNREPLYPROCESS_HH_
#include <click/element.hh>
#include <clicknet/udp.h>
#include <clicknet/icmp.h>
#include <clicknet/ether.h>
#include "registrationreply.hh"
CLICK_DECLS

/**
 * Filters registration replies from other packets at foreign agent
 */
class ForeignReplyProcess : public Element {
    public:
        ForeignReplyProcess();
        ~ForeignReplyProcess();

        const char *class_name() const  { return "ForeignReplyProcess"; }
        const char *port_count() const  { return "1/2"; }
        const char *processing() const  { return PUSH; }
        int configure(Vector<String>&, ErrorHandler*);

        void push(int, Packet *);

};

CLICK_ENDDECLS

#endif

