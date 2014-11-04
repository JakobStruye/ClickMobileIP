#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "visitorlist.hh"
#include <iostream>
#include <cmath>

CLICK_DECLS
VisitorList::VisitorList(){
    visList = std::vector<VisitorListEntry*>();

}

VisitorList::~ VisitorList()
{}

int VisitorList::configure(Vector<String> &conf, ErrorHandler *errh) {
    if (cp_va_kparse(conf, this, errh, cpEnd) < 0) return -1;
    return 0;
}

VisitorListEntry* VisitorList::getEntry(uint32_t identification) {
    std::cout << "IN THE FISH" << identification << std::endl;
    for(int i = 0; i < visList.size(); i++)
        if (visList[i]->identification[1] == identification)
            return visList[i];

    return NULL;
}

void VisitorList::insertEntry(VisitorListEntry* entry) {
    visList.push_back(entry);
}

void VisitorList::deleteEntry(VisitorListEntry* entry) {
    std::vector<VisitorListEntry*>::iterator it = visList.begin();
    while (it != visList.end()) {
        if (*it == entry) {
            visList.erase(it);
            break;
        }
        it++;
    }
}

void VisitorList::push(int, Packet *p){
    WritablePacket* q = (WritablePacket*) p;
    click_ether* eth_header = (click_ether*) (q->data());
    click_ip* ip_header = (click_ip*) (eth_header+1);
    click_udp* udp_header = (click_udp*) (ip_header+1);
    RegistrationRequest* req = (RegistrationRequest*) (udp_header+1);
    if (req->type == 1) {
        VisitorListEntry* entry = new VisitorListEntry;
        for(int i = 0; i < 6; i++)
            entry->mobile_MAC[i] = eth_header->ether_shost[i];
        entry->ip_src = ip_header->ip_src;
        entry->ip_dst = ip_header->ip_dst;
        entry->port_src = udp_header->uh_sport;
        entry->home_agent = req->home_agent;
        entry->identification[0] = req->identification[0];
        entry->identification[1] = req->identification[1];
        entry->identification[0] = htonl(entry->identification[0]);
        entry->identification[1] = htonl(entry->identification[1]);
        entry->lifetime = req->lifetime;
        entry->remaining_lifetime = req->lifetime;
        insertEntry(entry);
        output(0).push(q);
    }
    else {
        RegistrationReply* reply = (RegistrationReply*) (udp_header+1);
        VisitorListEntry* entry = getEntry(reply->identification[1]);
        entry->lifetime = std::min((int) entry->lifetime, (int) reply->lifetime);
        for(int i = 0; i < 6; i++)
            eth_header->ether_dhost[i] = entry->mobile_MAC[i];
        ip_header->ip_src = entry->ip_dst;
        ip_header->ip_dst = entry->ip_src;
        udp_header->uh_dport = entry->port_src;
        click_chatter("HERE2");
        output(1).push(q);

    }

}




CLICK_ENDDECLS
EXPORT_ELEMENT(VisitorList)
