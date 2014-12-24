#ifndef HOMEREQUESTPROCESS_HH_
#define HOMEREQUESTPROCESS_HH_

#include <click/element.hh>
#include <clicknet/udp.h>
#include <clicknet/icmp.h>
#include <clicknet/ether.h>
#include "registrationrequest.hh"
#include "registrationreply.hh"
#include <click/dequeue.hh>

CLICK_DECLS

class HomeRequestProcess : public Element {
    public:
        HomeRequestProcess();
        ~HomeRequestProcess();

        const char *class_name() const  { return "HomeRequestProcess"; }
        const char *port_count() const  { return "2/3"; }
        const char *processing() const  { return PUSH; }
        int configure(Vector<String>&, ErrorHandler*);

        WritablePacket* makeReply(RegistrationRequest*);
        void push(int, Packet *);

    private:
        DEQueue<Packet*> requests;

};

CLICK_ENDDECLS

#endif
