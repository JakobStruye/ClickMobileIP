#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "registrationrequestsender.hh"
#include <iostream>

CLICK_DECLS
RegistrationRequestSender::RegistrationRequestSender() :
        _timer(this), gateway(IPAddress("192.168.3.254")), _isRegistered(false) { //TODO set right default gw
    _pendingRegistrations = Vector<PendingRegistration*>();
    _remaining_lifetime = 0;

    _home_address = IPAddress("192.168.2.1").in_addr();
    _home_agent = IPAddress("192.168.2.254").in_addr();
    _care_of_address = IPAddress("0.0.0.0").in_addr(); //placeholder
}

RegistrationRequestSender::~RegistrationRequestSender() {
}

int RegistrationRequestSender::configure(Vector<String> &conf,
        ErrorHandler *errh) {
    if (cp_va_kparse(conf, this, errh, cpEnd) < 0)
        return -1;
    return 0;
}

int RegistrationRequestSender::initialize(ErrorHandler *errh) {
    _timer.initialize(this);
    _timer.schedule_after_msec(100);
    return 0;
}

PendingRegistration* RegistrationRequestSender::getEntry(
        uint32_t identification) {
    for (Vector<PendingRegistration*>::iterator it =
            _pendingRegistrations.begin(); it != _pendingRegistrations.end();
            it++)
        if ((*it)->identification[1] == identification)
            return (*it);

    return NULL;
}

void RegistrationRequestSender::deleteEntry(PendingRegistration* entry) {
    for (Vector<PendingRegistration*>::iterator it =
            _pendingRegistrations.begin(); it != _pendingRegistrations.end();
            it++) {
        if ((*it) == entry) {
            _pendingRegistrations.erase(it);
            break;
        }
    }
    return;
}

String RegistrationRequestSender::getGateway(Element* e, void* thunk) {
    RegistrationRequestSender* me = (RegistrationRequestSender*) e;
    //click_chatter("GATEWAY IS %s", me->gateway.unparse().c_str());
    return me->gateway.unparse();
}

void RegistrationRequestSender::add_handlers() {
    add_read_handler("gateway", &getGateway, (void*) 0);
}

Packet* RegistrationRequestSender::makePacket(in_addr care_of) {
    int packetsize = sizeof(RegistrationRequest);
    int headroom = sizeof(click_udp) + sizeof(click_ip) + sizeof(click_ether);
    WritablePacket* packet = Packet::make(headroom, 0, packetsize, 0);
    if (packet == 0)
        //click_chatter("cannot make packet!");
        memset(packet->data(), 0, packet->length());
    RegistrationRequest* format = (RegistrationRequest*) packet->data();
    format->type = 1; //fixed
    /*format->flags[0] = 0; //S
     format->flags[1] = 0; //B
     format->flags[2] = 0; //D
     format->flags[3] = 0; //M
     format->flags[4] = 0; //G
     format->flags[5] = 0; //r, should be 0
     format->flags[6] = 0; //T
     format->flags[7] = 0; //x, should be 0 but will be ignored */
    format->flags = 0; //all flags 0
    if (care_of == _home_agent)
        format->lifetime = htons(0);
    else
        format->lifetime = htons(300);
    format->home_address = _home_address;
    format->home_agent = _home_agent;
    format->care_of_address = care_of;
    format->identification[0] = htonl(1000);
    format->identification[1] = htonl(1100);

    if (care_of == _home_agent) {
        //click_chatter("Mobile Node: DEregistration request created");
    } else {
        //click_chatter("Mobile Node: Registration request created");
    }

    return packet;
}

SavedAdvertisement* RegistrationRequestSender::getEntry(in_addr care_of) {
    for (Vector<SavedAdvertisement*>::iterator it =
            _savedAdvertisements.begin(); it != _savedAdvertisements.end();
            it++)
        if ((*it)->care_of_address == care_of)
            return (*it);

    return NULL;
}

void RegistrationRequestSender::run_timer(Timer *) {
    //click_chatter("MOBILE TIMER GO");
    Vector<PendingRegistration*>::iterator it = _pendingRegistrations.begin();
    while (it != _pendingRegistrations.end()) {
        (*it)->remaining_lifetime--;
        //For lifetimes of at least 45, reregister 15secs before timeout
        if ((*it)->lifetime > 45 && (*it)->remaining_lifetime == 15) {
            //TODO reregister
        }
        //integer division truncates result to int (on purpose here)
        //Reregister lifetime/3 before timeout if lifetime < 15
        else if ((*it)->lifetime / 3 == (*it)->remaining_lifetime) {
            //TODO reregister
        }
        if (!((*it)->remaining_lifetime)) {
            it = _pendingRegistrations.erase(it);
        } else {
            it++;
        }
    }
    Vector<SavedAdvertisement*>::iterator it2 = _savedAdvertisements.begin();
    while (it2 != _savedAdvertisements.end()) {
        (*it2)->remaining_lifetime--;
        //click_chatter("SAVED ADVERTISEMENT %s HAS LEFT %i", IPAddress((*it2)->care_of_address).unparse().c_str(), (*it2)->remaining_lifetime);
        //TODO IF 0
        if (!((*it2)->remaining_lifetime)) {
            it2 = _savedAdvertisements.erase(it2);
        } else {
            it2++;
        }
    }
    //TODO UNTESTED
    if (_isRegistered && !getEntry(_care_of_address)) {
        //click_chatter("Registration timeout detected at mobile node (no more advertisements)");
        //Agent it is registered to no longer in reach
        _isRegistered = false;
        if (_savedAdvertisements.size()) {
            SavedAdvertisement* advertisement = _savedAdvertisements[0];
            Packet* p = makePacket(advertisement->care_of_address);
            gateway = IPAddress(advertisement->care_of_address);
            PendingRegistration* entry = new PendingRegistration();
            entry->mobile_MAC[0] = 0;
            entry->mobile_MAC[1] = 80;
            entry->mobile_MAC[2] = 186;
            entry->mobile_MAC[3] = 133;
            entry->mobile_MAC[4] = 132;
            entry->mobile_MAC[5] = 193;
            entry->dst = advertisement->care_of_address;
            entry->care_of_address = advertisement->care_of_address;
            entry->identification[0] = 1000;
            entry->identification[1] = 1100;
            entry->lifetime = 300; //TODO PLACEHOLDER
            _pendingRegistrations.push_back(entry);
            //click_chatter("Mobile Node: Pending Registration entry created");

            output(0).push(p);

        }
    }
    //TODO remove once advertisements are implemented
//    if (isHome)
//        gateway = IPAddress("192.168.2.254");
//    else
//        gateway = IPAddress("192.168.3.254");
//    if (Packet *q = makePacket()) {
//
//        PendingRegistration* entry = new PendingRegistration();
//        entry->mobile_MAC[0] = 0;
//        entry->mobile_MAC[1] = 80;
//        entry->mobile_MAC[2] = 186;
//        entry->mobile_MAC[3] = 133;
//        entry->mobile_MAC[4] = 132;
//        entry->mobile_MAC[5] = 193;
//        if (isHome)
//            entry->dst = IPAddress("192.168.2.254").in_addr();
//        else
//            entry->dst = IPAddress("192.168.3.254").in_addr();
//        if (isHome)
//            entry->care_of_address = IPAddress("192.168.2.254").in_addr();
//        else
//            entry->care_of_address = IPAddress("192.168.3.254").in_addr();
//        entry->identification[0] = 1000;
//        entry->identification[1] = 1100;
//        if (isHome)
//            entry->lifetime = 0;
//        else
//            entry->lifetime = 300;
//        entry->remaining_lifetime = entry->lifetime;
//        _pendingRegistrations.push_back(entry);
//        isHome = (!isHome);
//        //click_chatter("Mobile Node: Pending Registration entry created");
//        output(0).push(q);
//    }
    _timer.reschedule_after_msec(1000);
}

/*
 * Expects Registration Replies to its Requests in IP
 *
 * Input 0: Registration Reply to a previously sent Request (allows for other packets, won't change them or crash)
 *           or Agent Advertisements
 *
 * Output 0: (in run_timer) new Registration Request
 * Output 1: Unchanged packets from Input 0
 */
void RegistrationRequestSender::push(int, Packet *p) {
    click_ether* ether_header = (click_ether*) p->data();
    click_ip* ip_header = (click_ip*) (ether_header + 1);
    if (ip_header->ip_p == 17) {
        click_udp* udp_header = (click_udp*) (ip_header + 1);
        if (ntohs(udp_header->uh_sport) == 434) {
            //Check UDP checksum (code based on CheckUDPHeader code)
            unsigned len = ntohs(udp_header->uh_ulen);
            unsigned csum = click_in_cksum((unsigned char *) udp_header, len);
            //Don't discard on csum == 0
            if (csum && click_in_cksum_pseudohdr(csum, ip_header, len) != 0) {
                //click_chatter("Bad UDP checksum for registration reply at mobile node, discarded");
                return;
            }

            RegistrationReply* rep = (RegistrationReply*) (udp_header + 1);
            PendingRegistration* entry = getEntry(
                    ntohl(rep->identification[1]));
            //If no pending reply with these lower 32bits of identification found, discard
            if (!entry) {
                //click_chatter("Bad low-order 32bits identification in registration reply, discarded");
                return;
            }
            switch (rep->code) {
            case 0:
            case 1:
                //Accepted
                gateway = IPAddress(entry->dst);
                _isRegistered = true;
                _care_of_address = entry->care_of_address;
                _remaining_lifetime = entry->remaining_lifetime
                        - (entry->lifetime - ntohs(rep->lifetime));
                deleteEntry(entry);
                //delete entry;
                //click_chatter("Mobile Node: Registration Reply received (Request accepted)");
                break;
            case 64:
                //click_chatter("Mobile Node: Registration Request denied by Foreign Agent(reason unspecified)");
                break;
            case 70:
                //click_chatter("Mobile Node: Registration Request denied by Foreign Agent (poorly formed Request)");
                break;
            case 71:
                //click_chatter("Mobile Node: Registration Request denied by Foreign Agent (poorly formed Reply)");
                break;
            case 72:
                //click_chatter("Mobile Node: Registration Request denied by Foreign Agent (requested encapsulation unavailable)");
                break;
            case 80:
                //click_chatter("Mobile Node: Registration Request denied by Foreign Agent (home network unreachable)");
                break;
            case 128:
                //click_chatter("Mobile Node: Registration Request denied by Home Agent (reason unspecified)");
                break;
            case 134:
                //click_chatter("Mobile Node: Registration Request denied by Home Agent (poorly formed Request)");
                break;
            case 135:
                //click_chatter("Mobile Node: Registration Request denied by Home Agent (too many simultaneous mobility bindings)");
                break;
            case 136:
                //click_chatter("Mobile Node: Registration Request denied by Home Agent (unknown home agent address)");
                break;
            default:
                //click_chatter("Mobile Node: Registration Request denied (error code unknown)");
                break;
        }
        output(1).push(p);
        return;
    }
    output(1).push(p);
    return;

}

//Check if ICMP
if (ip_header->ip_p == 1) {
    click_icmp* icmp_header = (click_icmp*) (ip_header + 1);
    //Check if agent advertisement
    if (icmp_header->icmp_type == 9 && (ntohs(ip_header->ip_len) > 36)) {
        //click_chatter("Advertisement received");
        ICMPAgentAdvertisement* advertisement =
                (ICMPAgentAdvertisement*) (p->data() + 38);
        //TODO process: refresh lifetime, store if different network, request, check seq_nr, detect movement (through timer), ...
        SavedAdvertisement* entry = getEntry(advertisement->care_of_address);
        if (entry) {
            //Assume advertised lifetime never changes
            entry->remaining_lifetime = entry->lifetime;
        } else {
            SavedAdvertisement* entry = new SavedAdvertisement();
            entry->lifetime = ntohs(advertisement->lifetime);
            entry->remaining_lifetime = ntohs(advertisement->lifetime);
            entry->registration_lifetime = ntohs(
                    advertisement->registration_lifetime);
            entry->care_of_address = advertisement->care_of_address;
            entry->latest_seq_number = ntohs(advertisement->seq_number);
            _savedAdvertisements.push_back(entry);
        }
        if (!_isRegistered) {
            Packet* request = makePacket(advertisement->care_of_address);

            gateway = IPAddress(advertisement->care_of_address);
            PendingRegistration* entry = new PendingRegistration();
            entry->mobile_MAC[0] = 0;
            entry->mobile_MAC[1] = 80;
            entry->mobile_MAC[2] = 186;
            entry->mobile_MAC[3] = 133;
            entry->mobile_MAC[4] = 132;
            entry->mobile_MAC[5] = 193;
            entry->dst = advertisement->care_of_address;
            entry->care_of_address = advertisement->care_of_address;
            entry->identification[0] = 1000;
            entry->identification[1] = 1100;
            entry->lifetime = 300; //TODO PLACEHOLDER
            _pendingRegistrations.push_back(entry);
            //click_chatter("Mobile Node: Pending Registration entry created");

            output(0).push(request);
            return;
        }
    }
    output(1).push(p);
    return;
}
output(1).push(p);
return;

}

CLICK_ENDDECLS
EXPORT_ELEMENT(RegistrationRequestSender)
