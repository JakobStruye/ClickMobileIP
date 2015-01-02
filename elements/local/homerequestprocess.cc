#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "homerequestprocess.hh"


CLICK_DECLS
HomeRequestProcess::HomeRequestProcess(){
requests = DEQueue<Packet*>();
}

HomeRequestProcess::~ HomeRequestProcess()
{}

int HomeRequestProcess::configure(Vector<String> &conf, ErrorHandler *errh) {
    if (cp_va_kparse(conf, this, errh, "LIFETIME", cpkM, cpInteger, &_lifetime, cpEnd) < 0) return -1;
    return 0;
}

/**
 * Handler to add home agent address to this element
 */
int HomeRequestProcess::addHomeAgent(const String& conf, Element* e, void* thunk, ErrorHandler* errh) {
    HomeRequestProcess* me = (HomeRequestProcess*) e;
    IPAddress new_addr;
    if (cp_va_kparse(conf, me, errh, "IP", cpkM, cpIPAddress, &new_addr,cpEnd) < 0) return -1;
    me->_home_agents.push_back(new_addr.unparse());
    return 0;
}

void HomeRequestProcess::add_handlers() {
    add_write_handler("addHomeAgent", &addHomeAgent, (void*) 0);
}

/**
 * Check if given IP is address of this home agent
 */
bool HomeRequestProcess::contains(String IP) {
    for (Vector<String>::iterator it = _home_agents.begin(); it != _home_agents.end(); it++) {
        if ((*it) == IP)
            return true;
    }
    return false;
}

/**
 * Generate a Reply based on given Request with given error code
 */
WritablePacket* HomeRequestProcess::makeReply(RegistrationRequest* req, int errcode) {
    //Set lifetime to minimum of requested and max offered lifetime
    int lifetime = ntohs(req->lifetime);
    if (lifetime > _lifetime)
        lifetime = _lifetime;

    int headroom = sizeof(click_udp) + sizeof(click_ip) + sizeof(click_ether);
    int packetsize = sizeof(RegistrationReply);
    WritablePacket* packet = Packet::make(headroom,0,packetsize,0);
    if (packet == 0) click_chatter("cannot make packet!");
    memset(packet->data(), 0, packet->length());
    RegistrationReply* format = (RegistrationReply*) packet->data();
    format->type = 3; //fixed
    format->code = errcode; //fixed
    format->lifetime = htons(lifetime);
    format->home_address = req->home_address;
    format->home_agent = req->home_agent;
    format->identification[0] = req->identification[0];
    format->identification[1] = req->identification[1];
    //format->identification[1] = 0; //FOR TESTING PURPOSES ONLY: Sets invalid identification
    return packet;
}
/**
 * Excpets IP packets
 *
 * Input 0: Expects valid Registration Request, creates a Registration Reply, stores Request
 * Input 1: Expects Reply just created and sent to Output 0, now with UDP and IP headers present
 *
 * Output 0: Reply created while handling packet from Input 0
 * Output 1: Reply from Input 1, now with correct IP addresses and UDP ports
 */

void HomeRequestProcess::push(int input, Packet *p){

    //incoming request
    if (input == 0) {
        click_chatter("Home Agent: Registration Request detected");
        click_ip* ip_header = (click_ip*) (p->data());
        click_udp* udp_header = (click_udp*) (ip_header+1);
        //Check UDP checksum (code based on CheckUDPHeader code)
        unsigned len = ntohs(udp_header->uh_ulen);
        unsigned csum = click_in_cksum((unsigned char *) udp_header, len);
        //Don't discard on csum == 0
        if (csum && click_in_cksum_pseudohdr(csum, ip_header, len) != 0) {
            click_chatter("Bad UDP checksum for registration request at home agent, discarded");
            return;
        }
        RegistrationRequest * req = (RegistrationRequest*) (udp_header+1);
        int errcode = 1; //Start with positive error code

        //Unrecognized home agent address
        if (!contains(IPAddress(req->home_agent).unparse())) {
            errcode = 136;
        }
        //Check if reserved bit is 0
        if (req->flags & (1 << 2)) {
            errcode = 134;
        }
        //Generate reply and send
        WritablePacket* q = makeReply(req, errcode);
        RegistrationReply* rep = (RegistrationReply*) (q->data());
        requests.push_back(p); //Store request for now
        click_chatter("Home Agent: Registration Reply created");
        output(0).push(q);
    }
    //reply with UDPIP set
    else if (input == 1) {
        WritablePacket* q = (WritablePacket*) p;
        click_ip* ip_header_reply = (click_ip*) (q->data());
        click_udp* udp_header_reply = (click_udp*) (ip_header_reply+1);
        RegistrationReply * rep = (RegistrationReply*) (udp_header_reply+1);

        Packet* request = requests.front(); //Grab the request from the queue
        requests.pop_front();
        click_ip* ip_header_request = (click_ip*) (request->data());
        click_udp* udp_header_request = (click_udp*) (ip_header_request+1);

        //Set IP and UDP fields of Reply based on Request fields and send
        ip_header_reply->ip_src = ip_header_request->ip_dst;
        ip_header_reply->ip_dst = ip_header_request->ip_src;
        udp_header_reply->uh_sport = udp_header_request->uh_dport;
        udp_header_reply->uh_dport = udp_header_request->uh_sport;
        click_chatter("Home Agent: Registration Reply with correct IP and UDP headers sent");
        output(1).push(q);

    }
}




CLICK_ENDDECLS
EXPORT_ELEMENT(HomeRequestProcess)




