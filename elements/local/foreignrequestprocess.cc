#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "foreignrequestprocess.hh"
#include <iostream>

CLICK_DECLS
ForeignRequestProcess::ForeignRequestProcess(){

}

ForeignRequestProcess::~ ForeignRequestProcess()
{}

int ForeignRequestProcess::configure(Vector<String> &conf, ErrorHandler *errh) {
    if (cp_va_kparse(conf, this, errh, cpEnd) < 0) return -1;
    return 0;
}




Packet* ForeignRequestProcess::makeReply() {
    //TODO IMPLEMENT
    int packetsize = sizeof(RegistrationRequest);
  click_chatter("%i", packetsize);
    int headroom = sizeof(click_udp) + sizeof(click_ip) + sizeof(click_icmp) + sizeof(click_ether);
    WritablePacket* packet = Packet::make(headroom,0,packetsize,0);
    if (packet == 0) click_chatter("cannot make packet!");
    memset(packet->data(), 0, packet->length());
    RegistrationRequest* format = (RegistrationRequest*) packet->data();
    format->type = htonl(1); //fixed
  format->flags[0] = 0; //S
  format->flags[1] = 0; //B
  format->flags[2] = 0; //D
  format->flags[3] = 0; //M
  format->flags[4] = 0; //G
  format->flags[5] = 0; //r, should be 0
  format->flags[6] = 0; //T
  format->flags[7] = 0; //x, should be 0 but will be ignored
  format->lifetime = htons(300);
  format->home_address = IPAddress("192.168.1.1").in_addr(); //192.168.1.1
  format->home_agent = IPAddress("192.168.1.2").in_addr(); //192.168.1.2
  format->care_of_address = IPAddress("192.168.2.1").in_addr(); //192.168.2.1
  format->identification[0] = htonl(1000);
  format->identification[1] = htonl(1100);

    return packet;
}


void ForeignRequestProcess::push(int, Packet *p){
    WritablePacket* q = (WritablePacket*) p;
    click_ip* ip_header = (click_ip*) (q->data());
    click_udp* udp_header = (click_udp*) (ip_header+1);
    RegistrationRequest * req = (RegistrationRequest*) (udp_header+1);
    ip_header->ip_src = ip_header->ip_dst;
    ip_header->ip_dst = req->home_agent;
    udp_header->uh_sport = htons(1234); //random?
    udp_header->uh_dport = htons(343);
    output(0).push(q);
}




CLICK_ENDDECLS
EXPORT_ELEMENT(ForeignRequestProcess)
