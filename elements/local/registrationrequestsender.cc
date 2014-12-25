#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "registrationrequestsender.hh"

CLICK_DECLS
RegistrationRequestSender::RegistrationRequestSender() :
        _timer(this), gateway(IPAddress("0.0.0.0")), _isRegistered(false),
        _hasReregistered(false) {
    _pendingRegistrations = Vector<PendingRegistration*>();
    _remaining_lifetime = 0;

    _home_address = IPAddress("192.168.2.1").in_addr();
    _home_agent = IPAddress("192.168.2.254").in_addr();
    _care_of_address = IPAddress("0.0.0.0").in_addr(); //placeholder
    //Both parts of identification start off as uint32_t representation of home address
    //lower always decrements, upper increments
    //It should result in unique identifications, and more complicated methods are unneeded
    //as no security is implemented
    _lowerIdentification = IPAddress(_home_address).addr();
    _upperIdentification = IPAddress(_home_address).addr();
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
    return me->gateway.unparse();
}

void RegistrationRequestSender::add_handlers() {
    add_read_handler("gateway", &getGateway, (void*) 0);
}

Packet* RegistrationRequestSender::makePacket(in_addr care_of, int lifetime) {
    int packetsize = sizeof(RegistrationRequest);
    int headroom = sizeof(click_udp) + sizeof(click_ip) + sizeof(click_ether);
    WritablePacket* packet = Packet::make(headroom, 0, packetsize, 0);
    if (packet == 0)
        click_chatter("cannot make packet!");
        memset(packet->data(), 0, packet->length());
    RegistrationRequest* format = (RegistrationRequest*) packet->data();
    format->type = 1; //fixed
    format->flags = 0; //all flags 0
    format->lifetime = htons(lifetime);
    format->home_address = _home_address;
    format->home_agent = _home_agent;
    format->care_of_address = care_of;
    format->identification[0] = htonl(_upperIdentification);
    format->identification[1] = htonl(_lowerIdentification);
    _upperIdentification++;
    _lowerIdentification--;

    if (care_of == _home_agent) {
        click_chatter("Mobile Node: DEregistration request created");
    } else {
        click_chatter("Mobile Node: Registration request created");
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

void RegistrationRequestSender::deleteAdvertisement(in_addr care_of) {
    for (Vector<SavedAdvertisement*>::iterator it = _savedAdvertisements.begin(); it != _savedAdvertisements.end(); it++) {
        if ((*it)->care_of_address == care_of) {
            _savedAdvertisements.erase(it);
            return;
        }
    }
    return;
}

void RegistrationRequestSender::run_timer(Timer *) {

    //Decrease remaining lifetime of pending registratoins, remove if 0
    Vector<PendingRegistration*>::iterator it = _pendingRegistrations.begin();
    while (it != _pendingRegistrations.end()) {
        (*it)->remaining_lifetime--;
        if (!((*it)->remaining_lifetime)) {
            it = _pendingRegistrations.erase(it);
        } else {
            it++;
        }
    }
    //Decrease remaining lifetime of saved advertisements, remove if 0
    Vector<SavedAdvertisement*>::iterator it2 = _savedAdvertisements.begin();
    while (it2 != _savedAdvertisements.end()) {
        (*it2)->remaining_lifetime--;
        if (!((*it2)->remaining_lifetime)) {
            it2 = _savedAdvertisements.erase(it2);
        } else {
            it2++;
        }
    }
    //Check if still receiving advertisements for agent registered to
    if (_isRegistered && !getEntry(_care_of_address)) {
        click_chatter("Registration timeout detected at mobile node (no more advertisements)");
        //Agent it is registered to no longer in reach
        _isRegistered = false;
        //Any other advertisements still coming in?
        if (_savedAdvertisements.size()) {
            //Register using another advertisement
            SavedAdvertisement* advertisement = _savedAdvertisements[0];
            int lifetime = 0;
            if (advertisement->care_of_address != _home_agent)
                lifetime = advertisement->registration_lifetime;
            Packet* p = makePacket(advertisement->care_of_address, lifetime);
            RegistrationRequest* req = (RegistrationRequest*) (p->data());
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
            entry->identification[0] = ntohl(req->identification[0]);
            entry->identification[1] = ntohl(req->identification[1]);
            entry->lifetime = lifetime;
            entry->remaining_lifetime = lifetime;
            _pendingRegistrations.push_back(entry);
            click_chatter("Mobile Node: Pending Registration entry created");

            output(0).push(p);

        }
    }
    if (_remaining_lifetime) {
        _remaining_lifetime--;
        if (!_remaining_lifetime) {
            //Registration timeout
            click_chatter("Registration has timed out");
            _isRegistered = false;
            _care_of_address = IPAddress("0.0.0.0").in_addr();
        }
        else if (_remaining_lifetime <= 10 && !_hasReregistered && _isRegistered) {
            _hasReregistered = true;
            SavedAdvertisement* advertisement = getEntry(_care_of_address);
            int lifetime = advertisement->registration_lifetime;
            Packet* p = makePacket(advertisement->care_of_address, lifetime);
            RegistrationRequest* req = (RegistrationRequest*) (p->data());
            PendingRegistration* entry = new PendingRegistration();
            entry->mobile_MAC[0] = 0;
            entry->mobile_MAC[1] = 80;
            entry->mobile_MAC[2] = 186;
            entry->mobile_MAC[3] = 133;
            entry->mobile_MAC[4] = 132;
            entry->mobile_MAC[5] = 193;
            entry->dst = advertisement->care_of_address;
            entry->care_of_address = advertisement->care_of_address;
            entry->identification[0] = ntohl(req->identification[0]);
            entry->identification[1] = ntohl(req->identification[1]);
            entry->lifetime = lifetime;
            entry->remaining_lifetime = lifetime;
            _pendingRegistrations.push_back(entry);
            click_chatter("Mobile Node: Pending REregistration entry created (low remaining registration lifetime) ");

            output(0).push(p);

        }
    }
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
                click_chatter("Bad UDP checksum for registration reply at mobile node, discarded");
                return;
            }

            RegistrationReply* rep = (RegistrationReply*) (udp_header + 1);
            PendingRegistration* entry = getEntry(
                    ntohl(rep->identification[1]));
            //If no pending reply with these lower 32bits of identification found, discard
            if (!entry) {
                click_chatter("Bad low-order 32bits identification in registration reply, discarded");
                return;
            }
            switch (rep->code) {
            case 0:
            case 1:
                //Accepted
                gateway = IPAddress(entry->dst);
                _isRegistered = true;
                _hasReregistered = false;
                _care_of_address = entry->care_of_address;
                _remaining_lifetime = entry->remaining_lifetime
                        - (entry->lifetime - ntohs(rep->lifetime));
                deleteEntry(entry);
                //delete entry;
                click_chatter("Mobile Node: Registration Reply received (Request accepted)");
                break;
            case 64:
                click_chatter("Mobile Node: Registration Request denied by Foreign Agent(reason unspecified)");
                break;
            case 70:
                click_chatter("Mobile Node: Registration Request denied by Foreign Agent (poorly formed Request)");
                break;
            case 71:
                click_chatter("Mobile Node: Registration Request denied by Foreign Agent (poorly formed Reply)");
                break;
            case 72:
                click_chatter("Mobile Node: Registration Request denied by Foreign Agent (requested encapsulation unavailable)");
                break;
            case 80:
                click_chatter("Mobile Node: Registration Request denied by Foreign Agent (home network unreachable)");
                break;
            case 128:
                click_chatter("Mobile Node: Registration Request denied by Home Agent (reason unspecified)");
                break;
            case 134:
                click_chatter("Mobile Node: Registration Request denied by Home Agent (poorly formed Request)");
                break;
            case 135:
                click_chatter("Mobile Node: Registration Request denied by Home Agent (too many simultaneous mobility bindings)");
                break;
            case 136:
                click_chatter("Mobile Node: Registration Request denied by Home Agent (unknown home agent address)");
                break;
            default:
                click_chatter("Mobile Node: Registration Request denied (error code unknown)");
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
        click_chatter("Advertisement received");
        ICMPAgentAdvertisement* advertisement = (ICMPAgentAdvertisement*) (p->data() + 38);
        SavedAdvertisement* oldEntry = getEntry(advertisement->care_of_address);
        uint16_t previous_seq_number = 0;
        if (oldEntry) {
            previous_seq_number = oldEntry->latest_seq_number;
            deleteAdvertisement(oldEntry->care_of_address);
        }
        SavedAdvertisement* entry = new SavedAdvertisement();
        entry->lifetime = ntohs(advertisement->lifetime);
        entry->remaining_lifetime = ntohs(advertisement->lifetime);
        entry->registration_lifetime = ntohs(advertisement->registration_lifetime);
        entry->care_of_address = advertisement->care_of_address;
        entry->latest_seq_number = ntohs(advertisement->seq_number);
        if (entry->latest_seq_number < 256 && previous_seq_number > entry->latest_seq_number) {
            //Assume agent has reset, reregister
            click_chatter("Reset agent detected through sequence numbers, reregistering!");
            _isRegistered = false;
        }
        _savedAdvertisements.push_back(entry);
        if (!_isRegistered) {
            int lifetime = 0;
            if (advertisement->care_of_address != _home_agent)
                lifetime = ntohs(advertisement->registration_lifetime);
            Packet* request = makePacket(advertisement->care_of_address, lifetime);
            RegistrationRequest* req = (RegistrationRequest*) request->data();
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
            entry->identification[0] = ntohl(req->identification[0]);
            entry->identification[1] = ntohl(req->identification[1]);
            entry->lifetime = lifetime;
            entry->remaining_lifetime = lifetime;
            _pendingRegistrations.push_back(entry);
            click_chatter("Mobile Node: Pending Registration entry created");
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
