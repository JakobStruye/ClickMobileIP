#ifndef ENCAPSULATOR_HH_
#define ENCAPSULATOR_HH_

#include <list>
#include <click/element.hh>
#include <clicknet/udp.h>
#include <clicknet/icmp.h>
#include <clicknet/ether.h>
CLICK_DECLS

class Encapsulator : public Element {
    public:
        Encapsulator();
        ~Encapsulator();

        const char *class_name() const  { return "Encapsulator"; }
        const char *port_count() const  { return "1/2"; }
        const char *processing() const  { return PUSH; }
        int configure(Vector<String>&, ErrorHandler*);

        void push(int, Packet *);

    private:
        in_addr ip_src;



};

CLICK_ENDDECLS







#endif
