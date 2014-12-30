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

/**
 * Handler: give this element IP addresses of the foreign agent
 * so that it can determine if home agent address in request is its own address (is an error!)
 */
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

/**
 * Generate a registration reply if foreign agent denies request
 */
WritablePacket* ForeignRequestProcess::makeReply(RegistrationRequest* request, int errcode) {

    int headroom =  sizeof(click_udp) + sizeof(click_ip) + sizeof(click_ether);
    int packetsize = sizeof(RegistrationReply);
    WritablePacket* packet = Packet::make(headroom,0,packetsize,0);
    if (packet == 0) click_chatter("cannot make packet!");
    memset(packet->data(), 0, packet->length());

    RegistrationReply* reply = (RegistrationReply*) (packet->data());

    reply->type = 3; //fixed
    reply->code = errcode; //Determined in other function
    reply->lifetime = request->lifetime; //Copy these fields from request
    reply->home_address = request->home_address;
    reply->home_agent = request->home_agent;
    reply->identification[0] = request->identification[0];
    reply->identification[1] = request->identification[1];
    return packet;
}
/**
 * Expects Registration Requests in IP
 *
 * Input 0: Registration Request
 *
 * Output 0: Request from Input 0, now with IP addresses and UDP ports changed to reach home agent
 * Output 1: Reply in case Request was denied
 */
void ForeignRequestProcess::push(int, Packet *p){

    WritablePacket* q = (WritablePacket*) p;
    click_ip* ip_header = (click_ip*) (q->data());
    click_udp* udp_header = (click_udp*) (ip_header+1);
    RegistrationRequest * req = (RegistrationRequest*) (udp_header+1);
    if (req->type != 1) { //Not what we expected, just push along
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
        click_chatter("Foreign agent received request with reserved bit set");
        Packet* reply = makeReply(req, 70);
        output(1).push(reply);
        return;
    }

    //Check if nonstandard encapsulation requested (not offered here)
    if ((req->flags & (1 << 3)) || (req->flags & (1 << 4)) || (req->flags & (1 << 5))) {
        click_chatter("Foreign agent received request with nonstandard encapsulation requested");
        Packet* reply = makeReply(req, 72);
        output(1).push(reply);
        return;
    }
    for (Vector<String>::iterator it = _addrs.begin(); it != _addrs.end(); it++) {
        if (*it == IPAddress(req->home_agent).unparse()) {
            //home address is interface of this foreign agent
            click_chatter("Foreign agent received request with its own IP address as home address");
            Packet* reply = makeReply(req, 136);
            output(1).push(reply);
            return;
        }
    }

    //Set IP addresses and UDP ports accordingly
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
