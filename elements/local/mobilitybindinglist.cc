#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "mobilitybindinglist.hh"
#include <iostream>
#include <cmath>

CLICK_DECLS
MobilityBindingList::MobilityBindingList(){
    mobilityList = std::list<MobilityBindingListEntry*>();

}

MobilityBindingList::~ MobilityBindingList()
{}

int MobilityBindingList::configure(Vector<String> &conf, ErrorHandler *errh) {
    if (cp_va_kparse(conf, this, errh, cpEnd) < 0) return -1;
    return 0;
}

MobilityBindingListEntry* MobilityBindingList::getEntry(in_addr home_address) {
    for(std::list<MobilityBindingListEntry*>::iterator it = mobilityList.begin(); it != mobilityList.end(); it++)
        if ((*it)->home_address == home_address)
            return (*it);

    return NULL;
}

void MobilityBindingList::insertEntry(MobilityBindingListEntry* entry) {
    mobilityList.push_back(entry);
}

void MobilityBindingList::deleteEntry(MobilityBindingListEntry* entry) {
    std::list<MobilityBindingListEntry*>::iterator it = mobilityList.begin();
    while (it != mobilityList.end()) {
        if (*it == entry) {
            mobilityList.erase(it);
            //TODO verify if unallocating here is safe
            delete entry;
            break;
        }
        it++;
    }
}

void MobilityBindingList::printList() {
    click_chatter("Mobility Binding List: \n");
    for (std::list<MobilityBindingListEntry*>::iterator it = mobilityList.begin(); it != mobilityList.end(); it++) {
        const char* home_address = (IPAddress((*it)->home_address).unparse()).c_str();
        click_chatter("home_address %s", home_address);
        const char* care_of_address = (IPAddress((*it)->care_of_address).unparse()).c_str();
        click_chatter("care_of_address %s", care_of_address);
        click_chatter("identification %i %i", (*it)->identification[0], (*it)->identification[1]);
        click_chatter("remaining lifetime %i", (*it)->remaining_lifetime);

    }
}

/*
 * Expects IP packets
 *
 * Input 0: Expects Registration Request (valid), creates Mobility Binding
 * Input 1: Expects packet to be tunneled with outer header present
 * Input 2: Expects any packet but Registration, checks if should be tunneled
 *
 * Output 0: Packet from Input 1 with IP addresses set
 * Output 1: Unchanged packets from Input 2, to be tunneled
 * Output 2: Unchanged packets from Input 0
 * Output 3: Unchanged packets frfom Input 2, not to be tunneled
 */

void MobilityBindingList::push(int input, Packet *p){
    WritablePacket* q = (WritablePacket*) p;

    if (input == 0) {
        click_ip* ip_header = (click_ip*) (q->data());
        if (ip_header->ip_p == 17) { //UDP
            click_udp* udp_header = (click_udp*) (ip_header+1);

            //click_chatter("MOBBDIND %i",ntohs(udp_header->uh_dport));
            if (ntohs(udp_header->uh_dport) == 434) { //Registration

                //click_chatter("Mob got req");

                RegistrationRequest* req = (RegistrationRequest*) (udp_header+1);
                //Only one binding per mobile node allowed, so all cases
                //break down to erasing the entry for that node
                //Possibly, an entry with only a different lifetime will be added back
                MobilityBindingListEntry* entry = getEntry(req->home_address);
                if (entry)
                    deleteEntry(entry);
                //Nothing more to be done if lifetime == 0
                if (ntohs(req->lifetime) != 0) {
                    MobilityBindingListEntry* newEntry = new MobilityBindingListEntry;
                    newEntry->home_address = req->home_address;
                    newEntry->care_of_address = req->care_of_address;
                    newEntry->identification[0] = ntohl(req->identification[0]);
                    newEntry->identification[1] = ntohl(req->identification[1]);
                    newEntry->remaining_lifetime = ntohs(req->lifetime);
                    insertEntry(newEntry);
                }
                //printList();
                //Propagate unchanged packet
                output(2).push(p);
                return;
            }
        }
    }
    else if (input == 2) {
        //Not a registration
        click_ip* ip_header = (click_ip*) (q->data());
        MobilityBindingListEntry* entry = getEntry(ip_header->ip_dst);
        //click_chatter("CHECKING IF TO BE ENCAPSD");
        if (entry) //to be encapsulated
            output(1).push(p);
        else
            output(3).push(p);
    }
    else if (input == 1) {
        click_ip* ip_outer_header = (click_ip*) q->data();
        click_ip* ip_inner_header = (click_ip*) (ip_outer_header+1);
        MobilityBindingListEntry* entry = getEntry(ip_inner_header->ip_dst);
        ip_outer_header->ip_dst = entry->care_of_address;
        ip_outer_header->ip_src = ip_inner_header->ip_dst;
        output(0).push(q);

    }
}




CLICK_ENDDECLS
EXPORT_ELEMENT(MobilityBindingList)
