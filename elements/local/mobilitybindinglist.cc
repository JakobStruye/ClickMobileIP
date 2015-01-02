#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "mobilitybindinglist.hh"


CLICK_DECLS
MobilityBindingList::MobilityBindingList() : _timer(this){
    mobilityList = Vector<MobilityBindingListEntry*>();

}

MobilityBindingList::~ MobilityBindingList()
{}

int MobilityBindingList::configure(Vector<String> &conf, ErrorHandler *errh) {
    if (cp_va_kparse(conf, this, errh, cpEnd) < 0) return -1;
    return 0;
}

int MobilityBindingList::initialize(ErrorHandler *errh) {
    _timer.initialize(this);
    _timer.schedule_after_msec(50);
    return 0;
}

/**
 * Reduce remaining lifetime of all mobility bindings every second, erase if 0
 */
void MobilityBindingList::run_timer(Timer *) {
    Vector<MobilityBindingListEntry*>::iterator it = mobilityList.begin();
    while(it != mobilityList.end()) {
        (*it)->remaining_lifetime--;
        if (!(*it)->remaining_lifetime) {
            click_chatter("Home agent: erasing entry from mobile bindings list");
            it = mobilityList.erase(it);
        }
        else {
            it++;
        }
    }
    _timer.reschedule_after_msec(1000);
}

/**
 * Check if given IP address has binding, return binding if found
 */
MobilityBindingListEntry* MobilityBindingList::getEntry(in_addr home_address) {
    for(Vector<MobilityBindingListEntry*>::iterator it = mobilityList.begin(); it != mobilityList.end(); it++)
        if ((*it)->home_address == home_address)
            return (*it);

    return NULL;
}

/**
 * Add a new binding
 */
void MobilityBindingList::insertEntry(MobilityBindingListEntry* entry) {
    mobilityList.push_back(entry);
}

/**
 * Remove given existing binding
 */
void MobilityBindingList::deleteEntry(MobilityBindingListEntry* entry) {
    Vector<MobilityBindingListEntry*>::iterator it = mobilityList.begin();
    while (it != mobilityList.end()) {
        if (*it == entry) {
            mobilityList.erase(it);
            delete entry;
            break;
        }
        it++;
    }
}

/**
 * Allows list to be printed (for debugging purposes)
 */
void MobilityBindingList::printList() {
    click_chatter("Mobility Binding List: \n");
    for (Vector<MobilityBindingListEntry*>::iterator it = mobilityList.begin(); it != mobilityList.end(); it++) {
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
 * Input 1: Expects Registration Reply, will remove binding if reply indicates request denied
 * Input 2: Expects any packet but Registration, checks if should be tunneled
 * Input 3: Expects packet to be tunneled with outer header present
 *
 * Output 0: Unchanged packets from Input 0
 * Output 1: Unchanged packets from Input 1
 * Output 2: Unchanged packets from Input 2, to be tunneled
 * Output 3: Unchanged packets from Input 2, not to be tunneled
 * Output 4: Packet from Input 3 with IP addresses set
 */

void MobilityBindingList::push(int input, Packet *p){
    WritablePacket* q = (WritablePacket*) p;

    if (input == 0) { //Should be request
        click_ip* ip_header = (click_ip*) (q->data());
        if (ip_header->ip_p == 17) { //UDP
            click_udp* udp_header = (click_udp*) (ip_header+1);

            if (ntohs(udp_header->uh_dport) == 434) { //Registration


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
                click_chatter("Home Agent: Mobility Binding created");
                //Propagate unchanged packet
                output(0).push(p);
                return;
            }
        }
    }
    else if (input == 1) { //Should be reply
        RegistrationReply* rep = (RegistrationReply*) (q->data());
        if (rep->code != 1) { //If reply indicates denied, remove that binding
            MobilityBindingListEntry* entry = getEntry(rep->home_address);
            deleteEntry(entry);
            click_chatter("Home Agent: new mobility binding removed, request not accepted");
        }
        output(1).push(q);
    }
    else if (input == 2) { //Expects anything but registration
        click_ip* ip_header = (click_ip*) (q->data());
        MobilityBindingListEntry* entry = getEntry(ip_header->ip_dst);
        if (entry) { //if binding present for this dst address, needs encapsulation
            click_chatter("Home Agent: Packet to be tunneled detected");
            output(2).push(p);
        }
        else
            output(3).push(p);
    }
    else if (input == 3) { //Expects encapsulated packet
        click_ip* ip_outer_header = (click_ip*) q->data();
        click_ip* ip_inner_header = (click_ip*) (ip_outer_header+1);
        //Grab binding, should exist
        MobilityBindingListEntry* entry = getEntry(ip_inner_header->ip_dst);
        ip_outer_header->ip_dst = entry->care_of_address; //Set IP addresses
        ip_outer_header->ip_src = ip_inner_header->ip_dst;
        click_chatter("Home Agent: Outer IP header of ip-in-ip packet set");
        output(4).push(q);

    }

}




CLICK_ENDDECLS
EXPORT_ELEMENT(MobilityBindingList)
