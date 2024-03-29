#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "encapsulator.hh"

CLICK_DECLS
Encapsulator::Encapsulator()
{}

Encapsulator::~ Encapsulator()
{}

int Encapsulator::configure(Vector<String> &conf, ErrorHandler *errh) {
    if (cp_va_kparse(conf, this, errh, "SRC", cpkM, cpIPAddress, &ip_src, cpEnd) < 0) return -1;
    return 0;
}

/*
 * Expects packets to be tunneled with outer IP header present
 *
 * Input 0: Packet to be tunneled
 *
 * Output 0: Packet from Input 0, now checked against routing loops and with outer tos set
 * Output 1: Packet from Input 1 that would cause loops, to be Discarded
 *
 */
void Encapsulator::push(int, Packet *p){
    click_chatter("Home Agent: Encapsulating a packet");
    WritablePacket* q = (WritablePacket*) p;
    click_ip* ip_outer_header = (click_ip*) (q->data());
    click_ip* ip_inner_header = (click_ip*) (ip_outer_header+1);
    if (ip_inner_header->ip_src == ip_outer_header->ip_dst ||
        ip_inner_header->ip_src == ip_src)
        output(1).push(q); //should be connected to discard, looping packet!
    ip_outer_header->ip_tos = ip_inner_header->ip_tos;
    output(0).push(p);
}




CLICK_ENDDECLS
EXPORT_ELEMENT(Encapsulator)
