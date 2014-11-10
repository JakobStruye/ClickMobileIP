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

    if (ip_header->ip_p != 17) {
        output(0).push(p);
        return;
    }
    click_udp* udp_header = (click_udp*) (ip_header+1);
    if (ntohs(udp_header->uh_sport) != 434) {
        //click_chatter("NOT A REGISTER FORREP");
        output(0).push(p);
        return;
    }
    RegistrationReply* reply = (RegistrationReply*) (udp_header+1);
    if (reply->type != 3) {
        output(0).push(p);
        return;
    }
    ip_header->ip_src = ip_header->ip_dst;
    ip_header->ip_dst = reply->home_address;
    //click_chatter("FORREP %s %i %s %i", IPAddress(ip_header->ip_src).unparse().c_str(), ntohs(udp_header->uh_sport),IPAddress(ip_header->ip_dst).unparse().c_str(), ntohs(udp_header->uh_dport));
    udp_header->uh_sport = htons(434);
    output(1).push(q);
}




CLICK_ENDDECLS
EXPORT_ELEMENT(ForeignReplyProcess)
