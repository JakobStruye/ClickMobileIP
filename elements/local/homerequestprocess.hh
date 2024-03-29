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

/**
 * Expects Requests: will generate Replies
 * Expects its own Replies back: will set IP and UDP fields
 */
class HomeRequestProcess : public Element {
    public:
        HomeRequestProcess();
        ~HomeRequestProcess();

        const char *class_name() const  { return "HomeRequestProcess"; }
        const char *port_count() const  { return "2/2"; }
        const char *processing() const  { return PUSH; }
        int configure(Vector<String>&, ErrorHandler*);

        bool contains(String);

        static int addHomeAgent(const String&, Element*, void*, ErrorHandler*);
        void add_handlers();

        WritablePacket* makeReply(RegistrationRequest*, int);
        void push(int, Packet *);

    private:
        DEQueue<Packet*> requests;
        Vector<String> _home_agents;

        int _lifetime;

};

CLICK_ENDDECLS

#endif
