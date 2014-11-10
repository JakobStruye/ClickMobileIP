#ifndef REQUESTPRINTER_HH_
#define REQUESTPRINTER_HH_
#include <click/element.hh>
#include <clicknet/udp.h>
#include <clicknet/icmp.h>
#include <clicknet/ether.h>
#include "registrationreply.hh"
CLICK_DECLS

class ReplyPrinter : public Element {
    public:
        ReplyPrinter();
        ~ReplyPrinter();

        const char *class_name() const  { return "ReplyPrinter"; }
        const char *port_count() const  { return "1/1"; }
        const char *processing() const  { return PUSH; }
        int configure(Vector<String>&, ErrorHandler*);

        void push(int, Packet *);

};

CLICK_ENDDECLS

#endif

