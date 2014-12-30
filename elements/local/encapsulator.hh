#ifndef ENCAPSULATOR_HH_
#define ENCAPSULATOR_HH_

#include <click/element.hh>
#include <clicknet/udp.h>
#include <clicknet/icmp.h>
#include <clicknet/ether.h>
CLICK_DECLS

/**
 * Encapsulates all incoming packets (IP in IP)
 */
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
        in_addr ip_src; //Outer source IP



};

CLICK_ENDDECLS







#endif
