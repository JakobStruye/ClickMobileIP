#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "encapsulator.hh"
#include <iostream>
#include <cmath>

CLICK_DECLS
Encapsulator::Encapsulator()
{}

Encapsulator::~ Encapsulator()
{}

int Encapsulator::configure(Vector<String> &conf, ErrorHandler *errh) {
    if (cp_va_kparse(conf, this, errh, "SRC", cpkM, cpIPAddress, &ip_src, cpEnd) < 0) return -1;
    return 0;
}


void Encapsulator::push(int, Packet *p){
    //Check if TTL not 0 before getting here
    //Set outer dst ip before getting here
    click_chatter("ENCAPPING");
    WritablePacket* q = (WritablePacket*) p;
    click_ip* ip_outer_header = (click_ip*) (q->data());
    click_ip* ip_inner_header = (click_ip*) (ip_outer_header+1);
    if (ip_inner_header->ip_src == ip_outer_header->ip_dst ||
        ip_inner_header->ip_src == ip_src)
        output(1).push(q); //should be connected to discard
    ip_outer_header->ip_tos = ip_inner_header->ip_tos;
    output(0).push(p);
}




CLICK_ENDDECLS
EXPORT_ELEMENT(Encapsulator)
