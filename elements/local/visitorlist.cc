#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "visitorlist.hh"

CLICK_DECLS
VisitorList::VisitorList() : _timer(this){
    visList = Vector<VisitorListEntry*>();

}

VisitorList::~ VisitorList()
{}

int VisitorList::configure(Vector<String> &conf, ErrorHandler *errh) {
    if (cp_va_kparse(conf, this, errh, "IP", cpkM, cpIPAddress, &ipAddr,  cpEnd) < 0) return -1;
    return 0;
}

int VisitorList::initialize(ErrorHandler *errh) {
    _timer.initialize(this);
    _timer.schedule_after_msec(100);
    return 0;
}

/**
 * Decrement remaining lifetime of entries in visitor list every second, erase if 0
 */
void VisitorList::run_timer(Timer*) {
    Vector<VisitorListEntry*>::iterator it = visList.begin();
    while (it != visList.end()) {
        (*it)->remaining_lifetime--;
        if (!(*it)->remaining_lifetime) {
            click_chatter("Foreign agent: erasing entry from visitor list");
            it = visList.erase(it);
        }
        else {
            it++;
        }
    }
    _timer.reschedule_after_msec(1000);
}

/**
 * Look for visitor list entry based on lower 32bits of identification, return it if found
 */
VisitorListEntry* VisitorList::getEntry(uint32_t identification) {
    for(Vector<VisitorListEntry*>::iterator it = visList.begin(); it != visList.end(); it++)
        if ((*it)->identification[1] == identification)
            return (*it);

    return NULL;
}

/**
 * Look for visitor list entry based on source IP address, return it if found
 */
VisitorListEntry* VisitorList::getEntry(in_addr ip_src) {
    for(Vector<VisitorListEntry*>::iterator it = visList.begin(); it != visList.end(); it++)
        if ((*it)->ip_src == ip_src)
            return (*it);

    return NULL;
}

/**
 * Insert entry into visitor list
 */
void VisitorList::insertEntry(VisitorListEntry* entry) {
    visList.push_back(entry);
}

/**
 * Delete given entry from visitor list
 */
void VisitorList::deleteEntry(VisitorListEntry* entry) {
    Vector<VisitorListEntry*>::iterator it = visList.begin();
    while (it != visList.end()) {
        if (*it == entry) {
            visList.erase(it);
            delete entry;
            break;
        }
        it++;
    }
}

/**
 * Allows list to be printed (for debugging purposes)
 */
void VisitorList::printList() {
    click_chatter("Visitor List: \n");
    for (Vector<VisitorListEntry*>::iterator it = visList.begin(); it != visList.end(); it++) {

        click_chatter("MAC %i:%i:%i:%i:%i:%i", (*it)->mobile_MAC[0], (*it)->mobile_MAC[0], (*it)->mobile_MAC[1],  (*it)->mobile_MAC[2], (*it)->mobile_MAC[3], (*it)->mobile_MAC[4], (*it)->mobile_MAC[5]);
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

/*
 * Expects ethernet packets
 *
 * Input 0: Check for Registration requests, add entry in Visitor List
 * Input 1: Expects Registration Reply, updates Visitor List and sets Reply eth dst, IP src/dst, UDP ports
 * Input 2: Expects packet for registered mobile node (after detunneling), sets eth dhost
 *
 * Output 0: Packets from Input 0, unchanged
 * Output 1: Packets from Input 1, with aforementioned changes
 * Output 2: Packets from Input 2 with ether_dhost set
 */
void VisitorList::push(int input, Packet *p){
    WritablePacket* q = (WritablePacket*) p;
    click_ether* eth_header = (click_ether*) (q->data());
    click_ip* ip_header = (click_ip*) (eth_header+1);
    if (input == 2) {
        click_chatter("Foreign Agent: Detunneled packet received");
        VisitorListEntry* entry = getEntry(ip_header->ip_dst);
        if (!entry or !(entry->active)) {
            click_chatter("Foreign Agent: No (active) visitor list entry found for detunneled packet, discarded");
            return;
        }
        for(int i = 0; i < 6; i++) //Set dst ethnet address and deliver on local datalink
            eth_header->ether_dhost[i] = entry->mobile_MAC[i];
        click_chatter("Foreign Agent: dst MAC of detunneled packet set");
        output(2).push(q);
        return;
    }
    if ((ip_header->ip_dst != ipAddr && ip_header->ip_src != ipAddr)|| ip_header->ip_p != 17) {
        output(0).push(p); //not a registration request/reply, pass along
        return;
    }
    click_udp* udp_header = (click_udp*) (ip_header+1);


    if (ntohs(udp_header->uh_dport) != 434 && ntohs(udp_header->uh_sport) != 434) {
        output(0).push(p); //not a registration request/reply, pass along
        return;
    }
    RegistrationRequest* req = (RegistrationRequest*) (udp_header+1);
    if (input == 0 && req->type == 1) {
        //Must be registration request
        VisitorListEntry* oldEntry = getEntry(ip_header->ip_src);
        if (oldEntry) //Delete older entry for this node if it existed
            deleteEntry(oldEntry);

        //Generate new visitor list entry
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
        entry->active = false;

        insertEntry(entry);
        click_chatter("Foreign Agent: Visitor List entry created for Registration Request");
        output(0).push(q);
    }
    else if (input == 1){
        //Must be a reply
        RegistrationReply* reply = (RegistrationReply*) (udp_header+1);
        VisitorListEntry* entry = getEntry(ntohl(reply->identification[1]));
        //Reply not recognized, silently discard
        if (!entry)
            return;
        entry->active = true; //Activate entry (will now be used to deliver detunneled packets)
        //Set saved lifetime to minimum of that lifetime and lifetime in reply
        if (entry->lifetime > ntohs(reply->lifetime))
          entry->lifetime = ntohs(reply->lifetime);
        //Set headers for delivery on local datalink
        for(int i = 0; i < 6; i++)
            eth_header->ether_dhost[i] = entry->mobile_MAC[i];
        ip_header->ip_src = entry->ip_dst;
        ip_header->ip_dst = entry->ip_src;
        udp_header->uh_sport = htons(434);
        udp_header->uh_dport = htons(entry->port_src);
        if (reply->code == 1)
            click_chatter("Foreign Agent: Visitor List updated after receiving Registration Reply (accepted)");
        else {
            click_chatter("Foreign Agent: Visitor List updated after receiving Registration Reply (denied)");
            deleteEntry(entry);
        }
        click_chatter("Foreign Agent: Received Registration Reply modified");
        output(1).push(q);

    }
}


CLICK_ENDDECLS
EXPORT_ELEMENT(VisitorList)
