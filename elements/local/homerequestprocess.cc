#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "homerequestprocess.hh"
#include <iostream>


CLICK_DECLS
HomeRequestProcess::HomeRequestProcess(){
requests = std::queue<Packet*>();
}

HomeRequestProcess::~ HomeRequestProcess()
{}

int HomeRequestProcess::configure(Vector<String> &conf, ErrorHandler *errh) {
    if (cp_va_kparse(conf, this, errh, cpEnd) < 0) return -1;
    return 0;
}




WritablePacket* HomeRequestProcess::makeReply(RegistrationRequest* req) {
    int packetsize = sizeof(RegistrationReply);
    int headroom = sizeof(click_udp) + sizeof(click_ip) + sizeof(click_ether);
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


void HomeRequestProcess::push(int input, Packet *p){
    //verify packet

    //incoming request
    if (input == 0) {
        click_ip* ip_header = (click_ip*) (p->data());
        click_udp* udp_header = (click_udp*) (ip_header+1);
        RegistrationRequest * req = (RegistrationRequest*) (udp_header+1);
        WritablePacket* q = makeReply(req);
        RegistrationReply* rep = (RegistrationReply*) (q->data());
        requests.push(p);
        output(1).push(q);
    }
    //reply with UDPIP set
    else if (input == 1) {
        WritablePacket* q = (WritablePacket*) p;
        click_ip* ip_header_reply = (click_ip*) (q->data());
        click_udp* udp_header_reply = (click_udp*) (ip_header_reply+1);
        RegistrationReply * rep = (RegistrationReply*) (udp_header_reply+1);
        Packet* request = requests.front();
        requests.pop();
        click_ip* ip_header_request = (click_ip*) (request->data());
        click_udp* udp_header_request = (click_udp*) (ip_header_request+1);
        ip_header_reply->ip_src = ip_header_request->ip_dst;
        ip_header_reply->ip_dst = ip_header_request->ip_src;
        udp_header_reply->uh_sport = udp_header_request->uh_dport;
        udp_header_reply->uh_dport = udp_header_request->uh_sport;
        output(2).push(request); //to be discarded
        output(0).push(q);

    }
}




CLICK_ENDDECLS
EXPORT_ELEMENT(HomeRequestProcess)




