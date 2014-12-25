#include <iostream>

#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "foreignrequestprocess.hh"


CLICK_DECLS
ForeignRequestProcess::ForeignRequestProcess(){
    _addrs = Vector<String>();
}

ForeignRequestProcess::~ ForeignRequestProcess()
{}

int ForeignRequestProcess::configure(Vector<String> &conf, ErrorHandler *errh) {
    if (cp_va_kparse(conf, this, errh, cpEnd) < 0) return -1;
    return 0;
}


int ForeignRequestProcess::addOwnIP(const String& conf, Element* e, void* thunk, ErrorHandler* errh) {
    ForeignRequestProcess* me = (ForeignRequestProcess*) e;
    IPAddress new_addr;
    if (cp_va_kparse(conf, me, errh, "IP", cpkM, cpIPAddress, &new_addr,cpEnd) < 0) return -1;
    me->_addrs.push_back(new_addr.unparse());
    return 0;
}

void ForeignRequestProcess::add_handlers() {
    add_write_handler("addOwnIP", &addOwnIP, (void*) 0);
}


WritablePacket* ForeignRequestProcess::makeReply(RegistrationRequest* request, int errcode) {
    //Converts the request into a reply
    //int headroom = sizeof(click_ether);
    //int packetsize = sizeof(click_udp) + sizeof(click_ip) + sizeof(RegistrationReply);
    int headroom =  sizeof(click_udp) + sizeof(click_ip) + sizeof(click_ether);
    int packetsize = sizeof(RegistrationReply);
    WritablePacket* packet = Packet::make(headroom,0,packetsize,0);
    if (packet == 0) click_chatter("cannot make packet!");
    memset(packet->data(), 0, packet->length());
//    click_ether* eth_header = (click_ether*) req->data();
//    for(int i = 0; i < 6; i++) {
//        uint8_t temp = eth_header->ether_dhost[i];
//        eth_header->ether_dhost[i] = eth_header->ether_shost[i];
//        eth_header->ether_shost[i] = temp;
//    }
//    click_ip* ip_header_req = (click_ip*) req->data();
//    click_ip* ip_header_rep = (click_ip*) packet->data();
//    ip_header_rep->ip_p = ip_header_req->ip_p;
//    ip_header_rep->ip_v = ip_header_req->ip_v;
//    ip_header_rep->ip_hl = ip_header_req->ip_hl;
//    ip_header_rep->ip_src = ip_header_req->ip_dst;
//    ip_header_rep->ip_dst = ip_header_req->ip_src;
//    click_udp* udp_header_req = (click_udp*) (ip_header_req+1);
//    click_udp* udp_header_rep = (click_udp*) (ip_header_rep+1);
//    udp_header_rep->uh_dport = udp_header_req->uh_sport;
//    udp_header_rep->uh_sport = udp_header_req->uh_dport;
    RegistrationReply* reply = (RegistrationReply*) (packet->data());

    reply->type = 3; //fixed
    reply->code = errcode;
    reply->lifetime = request->lifetime;
    reply->home_address = request->home_address;
    reply->home_agent = request->home_agent;
    //uint32_t tempIdentification = request->identification[1];
    click_chatter("%i %i", ntohl(request->identification[0]), ntohl(request->identification[1]) );
    reply->identification[0] = request->identification[0];
    reply->identification[1] = request->identification[1];
    return packet; //now a reply, with some gibberish at the end which should be truncated
}
/**
 * Expects Registration Requests in IP
 *
 * Input 0: Registration Request
 *
 * Output 0: Request from Input 0, now with IP addresses and UDP ports changed to reach home agent
 */
void ForeignRequestProcess::push(int, Packet *p){
    //TODO verify if Registration Request
    WritablePacket* q = (WritablePacket*) p;
    click_ip* ip_header = (click_ip*) (q->data());
    click_udp* udp_header = (click_udp*) (ip_header+1);
    RegistrationRequest * req = (RegistrationRequest*) (udp_header+1);
    if (req->type != 1) {
        output(0).push(p);
        return;
    }
    //Check UDP checksum (code based on CheckUDPHeader code)
    unsigned len = ntohs(udp_header->uh_ulen);
    unsigned csum = click_in_cksum((unsigned char *) udp_header, len);
    //Don't discard on csum == 0
    if (csum && click_in_cksum_pseudohdr(csum, ip_header, len) != 0) {
        click_chatter("Bad UDP checksum for registration request at foreign agent, discarded");
        return;
    }
    //Check if reserved bit is 0
    if (req->flags & (1 << 2)) {
        click_chatter("Foreign host received request with reserved bit set");
        Packet* reply = makeReply(req, 70);
        output(1).push(reply);
        return;
    }
    for (Vector<String>::iterator it = _addrs.begin(); it != _addrs.end(); it++) {
        if (*it == IPAddress(req->home_agent).unparse()) {
            //home address is interface of this foreign agent
            click_chatter("Foreign host received request with its own IP address as home address");
            Packet* reply = makeReply(req, 136);
            output(1).push(reply);
            return;
        }
    }


    ip_header->ip_src = ip_header->ip_dst;
    ip_header->ip_dst = req->home_agent;
    udp_header->uh_sport = htons(1234); //random?
    udp_header->uh_dport = htons(434);
    click_chatter("Foreign Agent: Registration Request detected");
    click_chatter("Foreign Agent: Registration Request modified");
    output(0).push(q);
}




CLICK_ENDDECLS
EXPORT_ELEMENT(ForeignRequestProcess)
