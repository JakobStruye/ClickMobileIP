#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "foreignreplyprocess.hh"
#include <iostream>

CLICK_DECLS
ForeignReplyProcess::ForeignReplyProcess(){

}

ForeignReplyProcess::~ ForeignReplyProcess()
{}

int ForeignReplyProcess::configure(Vector<String> &conf, ErrorHandler *errh) {
    if (cp_va_kparse(conf, this, errh, cpEnd) < 0) return -1;
    return 0;
}


void ForeignReplyProcess::push(int, Packet *p){
    WritablePacket* q = (WritablePacket*) p;
    click_ip* ip_header = (click_ip*) (q->data());
    click_udp* udp_header = (click_udp*) (ip_header+1);
    RegistrationReply* reply = (RegistrationReply*) (udp_header+1);
    ip_header->ip_src = ip_header->ip_dst;
    ip_header->ip_dst = reply->home_agent;
    click_chatter("PORTS %i %i", htons(udp_header->uh_sport), htons(udp_header->uh_dport));
    udp_header->uh_sport = 1235; //random?
    udp_header->uh_dport = 434;
    output(0).push(q);
}




CLICK_ENDDECLS
EXPORT_ELEMENT(ForeignReplyProcess)
