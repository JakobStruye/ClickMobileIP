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


/*
 * Expects IP packets
 *
 * Input 0: Only input, will check if Registration Reply
 *
 * Output 0: Unchanged, not a Registration Reply
 * Output 1: Unchanged, Registration Reply
 */
void ForeignReplyProcess::push(int, Packet *p){
    WritablePacket* q = (WritablePacket*) p;
    click_ip* ip_header = (click_ip*) (q->data());

    if (ip_header->ip_p != 17) {
        output(0).push(p);
        return;
    }
    click_udp* udp_header = (click_udp*) (ip_header+1);
    if (ntohs(udp_header->uh_sport) != 434) {
        output(0).push(p);
        return;
    }
    RegistrationReply* reply = (RegistrationReply*) (udp_header+1);
    if (reply->type != 3) {
        output(0).push(p);
        return;
    }
    //Check UDP checksum (code based on CheckUDPHeader code)
    unsigned len = ntohs(udp_header->uh_ulen);
    unsigned csum = click_in_cksum((unsigned char *) udp_header, len);
    //Don't discard on csum == 0
    if (csum && click_in_cksum_pseudohdr(csum, ip_header, len) != 0) {
        click_chatter("Bad UDP checksum for registration reply at foreign agent, discarded");
        return;
    }
    //ip_header->ip_src = ip_header->ip_dst;
    //ip_header->ip_dst = reply->home_address;
    click_chatter("Foreign Agent: Registration Reply detected");
    output(1).push(q);
}




CLICK_ENDDECLS
EXPORT_ELEMENT(ForeignReplyProcess)
