#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "homerequestprocess.hh"
#include <iostream>

CLICK_DECLS
HomeRequestProcess::HomeRequestProcess(){

}

HomeRequestProcess::~ HomeRequestProcess()
{}

int HomeRequestProcess::configure(Vector<String> &conf, ErrorHandler *errh) {
    if (cp_va_kparse(conf, this, errh, cpEnd) < 0) return -1;
    return 0;
}




WritablePacket* HomeRequestProcess::makeReply(RegistrationRequest* req) {
    //TODO IMPLEMENT
    int packetsize = sizeof(RegistrationReply);
    int headroom = sizeof(click_udp) + sizeof(click_ip) + sizeof(click_icmp) + sizeof(click_ether);
    WritablePacket* packet = Packet::make(headroom,0,packetsize,0);
    if (packet == 0) click_chatter("cannot make packet!");
    memset(packet->data(), 0, packet->length());
    RegistrationReply* format = (RegistrationReply*) packet->data();
    format->type = 3; //fixed
    format->code = 1;
    format->lifetime = htons(300);
    format->home_address = req->home_address;
    format->home_agent = req->home_agent;
    format->identification[0] = req->identification[0];
    format->identification[1] = req->identification[1];
    return packet;
}


void HomeRequestProcess::push(int, Packet *p){
    //verify packet


    click_ip* ip_header = (click_ip*) (p->data());
    click_udp* udp_header = (click_udp*) (ip_header+1);
    RegistrationRequest * req = (RegistrationRequest*) (udp_header+1);
    WritablePacket* q = makeReply(req);
    p->kill();

    output(0).push(q);
}




CLICK_ENDDECLS
EXPORT_ELEMENT(HomeRequestProcess)




