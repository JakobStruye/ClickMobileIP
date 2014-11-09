#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "visitorlist.hh"
#include <iostream>
#include <cmath>

CLICK_DECLS
VisitorList::VisitorList(){
    visList = std::list<VisitorListEntry*>();

}

VisitorList::~ VisitorList()
{}

int VisitorList::configure(Vector<String> &conf, ErrorHandler *errh) {
    if (cp_va_kparse(conf, this, errh, "IP", cpkM, cpIPAddress, &ipAddr,  cpEnd) < 0) return -1;
    return 0;
}

VisitorListEntry* VisitorList::getEntry(uint32_t identification) {
    for(std::list<VisitorListEntry*>::iterator it = visList.begin(); it != visList.end(); it++)
        if ((*it)->identification[1] == identification)
            return (*it);

    return NULL;
}

VisitorListEntry* VisitorList::getEntry(in_addr ip_src) {
    for(std::list<VisitorListEntry*>::iterator it = visList.begin(); it != visList.end(); it++)
        if ((*it)->ip_src == ip_src)
            return (*it);

    return NULL;
}

void VisitorList::insertEntry(VisitorListEntry* entry) {
    visList.push_back(entry);
}

void VisitorList::deleteEntry(VisitorListEntry* entry) {
    std::list<VisitorListEntry*>::iterator it = visList.begin();
    while (it != visList.end()) {
        if (*it == entry) {
            visList.erase(it);
            //TODO verify if unallocating here is safe
            delete entry;
            break;
        }
        it++;
    }
}

void VisitorList::printList() {
    click_chatter("Visitor List: \n");
    for (std::list<VisitorListEntry*>::iterator it = visList.begin(); it != visList.end(); it++) {

        click_chatter("MAC %i:%i:%i:%i:%i:%i", (*it)->mobile_MAC[0], (*it)->mobile_MAC[0], (*it)->mobile_MAC[1],
                (*it)->mobile_MAC[2], (*it)->mobile_MAC[3], (*it)->mobile_MAC[4], (*it)->mobile_MAC[5]);
        const char* ip_src = (IPAddress((*it)->ip_src).unparse()).c_str();
        click_chatter("src %s", ip_src);
        const char* ip_dst = (IPAddress((*it)->ip_dst).unparse()).c_str();
        click_chatter("dst %s", ip_dst);
        const char* home_agent = (IPAddress((*it)->home_agent).unparse()).c_str();
        click_chatter("home_agent %s", home_agent);
        click_chatter("identification %i %i", (*it)->identification[0], (*it)->identification[1]);
        click_chatter("lifetime %i", (*it)->lifetime);
        click_chatter("remaining lifetime %i", (*it)->remaining_lifetime);

    }

}

void VisitorList::push(int input, Packet *p){
    click_chatter("VISLISTSTART");
    WritablePacket* q = (WritablePacket*) p;
    click_ether* eth_header = (click_ether*) (q->data());
    click_ip* ip_header = (click_ip*) (eth_header+1);
    if (input == 2) {
        VisitorListEntry* entry = getEntry(ip_header->ip_dst);
        if (!entry)
            click_chatter("FOREIGN DOES NOT KNOW MOBILE NODE");
        for(int i = 0; i < 6; i++)
            eth_header->ether_dhost[i] = entry->mobile_MAC[i];
        click_chatter("DECAPSD ETH SET");
        output(2).push(q);
        return;
    }
    if ((ip_header->ip_dst != ipAddr && ip_header->ip_src != ipAddr)|| ip_header->ip_p != 17) {
        output(0).push(p); //not a registration request, pass along
        return;
    }

    click_udp* udp_header = (click_udp*) (ip_header+1);
    if (ntohs(udp_header->uh_dport) != 434) {
        output(0).push(p); //not a registration request, pass along
        return;
    }
    RegistrationRequest* req = (RegistrationRequest*) (udp_header+1);
    if (input == 0 && req->type == 1) {
        VisitorListEntry* entry = new VisitorListEntry;
        for(int i = 0; i < 6; i++)
            entry->mobile_MAC[i] = eth_header->ether_shost[i];
        entry->ip_src = ip_header->ip_src;
        entry->ip_dst = ip_header->ip_dst;
        entry->port_src = ntohs(udp_header->uh_sport);
        entry->home_agent = req->home_agent;
        entry->identification[0] = ntohl(req->identification[0]);
        entry->identification[1] = ntohl(req->identification[1]);
        entry->lifetime = ntohs(req->lifetime);
        entry->remaining_lifetime = ntohs(req->lifetime);

        insertEntry(entry);
        printList();
        output(0).push(q);
    }
    else if (input == 1){
        RegistrationReply* reply = (RegistrationReply*) (udp_header+1);
        VisitorListEntry* entry = getEntry(ntohl(reply->identification[1]));
        entry->lifetime = std::min(entry->lifetime, ntohs(reply->lifetime));
        for(int i = 0; i < 6; i++)
            eth_header->ether_dhost[i] = entry->mobile_MAC[i];
        ip_header->ip_src = entry->ip_dst;
        ip_header->ip_dst = entry->ip_src;
        udp_header->uh_dport = htons(entry->port_src);
        click_chatter("PORTS %i %i", ntohs(udp_header->uh_sport), ntohs(udp_header->uh_dport));
        output(1).push(q);

    }


}




CLICK_ENDDECLS
EXPORT_ELEMENT(VisitorList)
