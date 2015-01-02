#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "registrationrequestsender.hh"

CLICK_DECLS
RegistrationRequestSender::RegistrationRequestSender() :
        _timer(this), gateway(IPAddress("0.0.0.0")), _isRegistered(false),
        _hasReregistered(false) {
    _pendingRegistrations = Vector<PendingRegistration*>();
    _remaining_lifetime = 0; //Indicates not currently registered

    _care_of_address = IPAddress("0.0.0.0").in_addr(); //placeholder
}

RegistrationRequestSender::~RegistrationRequestSender() {
}

int RegistrationRequestSender::configure(Vector<String> &conf,
        ErrorHandler *errh) {
    IPAddress homeaddr;
    IPAddress homeagent;
    if (cp_va_kparse(conf, this, errh, "HOMEADDRESS", cpkM, cpIPAddress, &homeaddr,
            "HOMEAGENT", cpkM, cpIPAddress, &homeagent, cpEnd) < 0)
        return -1;
    _home_agent = homeagent.in_addr();
    _home_address = homeaddr.in_addr();

    //Both parts of identification start off as uint32_t representation of home address
    //lower always decrements, upper increments
    //It should result in unique identifications, and more complicated methods are unneeded
    //as no security is implemented

    _lowerIdentification = IPAddress(_home_address).addr();
    _upperIdentification = IPAddress(_home_address).addr();

    return 0;
}

int RegistrationRequestSender::initialize(ErrorHandler *errh) {
    _timer.initialize(this);
    _timer.schedule_after_msec(100);
    return 0;
}

/**
 * Tries to find pending registration for given lower 32 bits of identification, returns it if found
 */
PendingRegistration* RegistrationRequestSender::getRegistration(
        uint32_t identification) {
    for (Vector<PendingRegistration*>::iterator it =
            _pendingRegistrations.begin(); it != _pendingRegistrations.end();
            it++)
        if ((*it)->identification[1] == identification)
            return (*it);

    return NULL;
}

/**
 * Deletes given pending registration
 */
void RegistrationRequestSender::deleteRegistration(PendingRegistration* entry) {
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

/**
 * Tries to find saved advertisement for given care of address, returns it if found
 */
SavedAdvertisement* RegistrationRequestSender::getAdvertisement(in_addr care_of) {
    for (Vector<SavedAdvertisement*>::iterator it =
            _savedAdvertisements.begin(); it != _savedAdvertisements.end();
            it++)
        if ((*it)->care_of_address == care_of)
            return (*it);

    return NULL;
}


/**
 * Deletes advertisement for given care of address
 */
void RegistrationRequestSender::deleteAdvertisement(in_addr care_of) {
    for (Vector<SavedAdvertisement*>::iterator it = _savedAdvertisements.begin(); it != _savedAdvertisements.end(); it++) {
        if ((*it)->care_of_address == care_of) {
            _savedAdvertisements.erase(it);
            return;
        }
    }
    return;
}

/**
 * Handler that returns string IP of current first hop router
 */
String RegistrationRequestSender::getGateway(Element* e, void* thunk) {
    RegistrationRequestSender* me = (RegistrationRequestSender*) e;
    return me->gateway.unparse();
}

void RegistrationRequestSender::add_handlers() {
    add_read_handler("gateway", &getGateway, (void*) 0);
}

/**
 * Generates Registration Request with given care of address and lifetime
 */
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
    //format->flags = 4; //FOR TESTING PURPOSES ONLY: Registration bit 1
    //format->flags = 32; //FOR TESTING PURPOSES ONLY: Request special encapsulation
    format->lifetime = htons(lifetime);
    format->home_address = _home_address;
    format->home_agent = _home_agent;
    //format->home_agent = IPAddress("192.168.3.254").in_addr(); //FOR TESTING PURPOSES ONLY: Sets home_agent to foreign agent address
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


/*
 * Input 0: Registration Reply to a previously sent Request or Agent Advertisements
 *  (allows for other packets, won't change them or crash)
 *
 * Output 0: (in run_timer) new Registration Request
 * Output 1: Unchanged packets from Input 0
 */
void RegistrationRequestSender::push(int, Packet *p) {
    click_ether* ether_header = (click_ether*) p->data();
    click_ip* ip_header = (click_ip*) (ether_header + 1);

    if (ip_header->ip_p == 17) { //could be Reply
        click_udp* udp_header = (click_udp*) (ip_header + 1);

        if (ntohs(udp_header->uh_sport) == 434) { //Must be reply
            //Check UDP checksum (code based on CheckUDPHeader code)
            unsigned len = ntohs(udp_header->uh_ulen);
            unsigned csum = click_in_cksum((unsigned char *) udp_header, len);
            //Don't discard on csum == 0
            if (csum && click_in_cksum_pseudohdr(csum, ip_header, len) != 0) {
                click_chatter("Bad UDP checksum for registration reply at mobile node, discarded");
                return;
            }

            RegistrationReply* rep = (RegistrationReply*) (udp_header + 1);
            PendingRegistration* entry = getRegistration(
                    ntohl(rep->identification[1]));
            //If no pending reply with these lower 32bits of identification found, discard
            if (!entry) {
                click_chatter("Bad low-order 32bits identification in registration reply, discarded");
                return;
            }
            switch (rep->code) { //Handle according to error code
            case 0:
            case 1:
                //Accepted
                gateway = IPAddress(entry->dst);
                _isRegistered = true;
                _hasReregistered = false;
                //_hasReregistered = true; //FOR TESTING PURPOSES ONLY: Also set RLIFETIME to low value in script to see what happens w/o reregistration
                _care_of_address = entry->care_of_address;
                _remaining_lifetime = entry->remaining_lifetime - (entry->lifetime - ntohs(rep->lifetime));
                deleteRegistration(entry);
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

if (ip_header->ip_p == 1) { //Might be agent advertisement
    click_icmp* icmp_header = (click_icmp*) (ip_header + 1);

    if (icmp_header->icmp_type == 9 && (ntohs(ip_header->ip_len) > 36)) {
        //Must be agent advertisement
        click_chatter("Advertisement received");
        ICMPAgentAdvertisement* advertisement = (ICMPAgentAdvertisement*) (p->data() + 38);
        //Check if other advertisements (not yet timed out) have been received
        SavedAdvertisement* oldEntry = getAdvertisement(advertisement->care_of_address);
        uint16_t previous_seq_number = 0;
        if (oldEntry) { //Grab seq number of previous entry and remove that entry
            previous_seq_number = oldEntry->latest_seq_number;
            deleteAdvertisement(oldEntry->care_of_address);
        }
        //Save the advertisement's relevant information
        SavedAdvertisement* entry = new SavedAdvertisement();
        entry->lifetime = ntohs(advertisement->lifetime);
        entry->remaining_lifetime = ntohs(advertisement->lifetime);
        entry->registration_lifetime = ntohs(advertisement->registration_lifetime);
        entry->care_of_address = advertisement->care_of_address;
        entry->latest_seq_number = ntohs(advertisement->seq_number);
        //Compare sequence numbers of two latest advertisements from same agent
        //If the latest has the lower seq number and it's under 256 the agent must have reset
        if (entry->latest_seq_number < 256 && previous_seq_number > entry->latest_seq_number) {
            //Assume agent has reset, reregister
            click_chatter("Reset agent detected through sequence numbers, reregistering!");
            _isRegistered = false;
        }
        _savedAdvertisements.push_back(entry);

        if (!_isRegistered) {
            //Advertisement received while not registered, register immediately!

            //lifetime is max allowed by advertisement, or 0 if registering to home agent
            int lifetime = 0;
            if (advertisement->care_of_address != _home_agent)
                lifetime = ntohs(advertisement->registration_lifetime);
            Packet* request = makePacket(advertisement->care_of_address, lifetime);
            RegistrationRequest* req = (RegistrationRequest*) request->data();
            gateway = IPAddress(advertisement->care_of_address);
            PendingRegistration* entry = new PendingRegistration();
            //MAC address hardcoded, it is never used (but should be saved according to RFC)
            //Rest of data is dynamic
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


/**
 * Decrement all remaining lifetimes, remove those hitting 0 and handle accordingly
 *
 * Initiates reregistration when registration is near timeout
 * Initiates registration to another agent when registration times out
 */
void RegistrationRequestSender::run_timer(Timer *) {

    //Decrease remaining lifetime of pending registrations, remove if 0
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
    if (_isRegistered && !getAdvertisement(_care_of_address)) {
        click_chatter("Registration timeout detected at mobile node (no more advertisements)");
        //Agent it is registered to no longer in reach
        _isRegistered = false;
        //Any other advertisements still coming in?
        if (_savedAdvertisements.size()) {
            //Register using another advertisement
            SavedAdvertisement* advertisement = _savedAdvertisements[0];
            //Lifetime is max advertised (or 0 if at home)
            int lifetime = 0;
            if (advertisement->care_of_address != _home_agent)
                lifetime = advertisement->registration_lifetime;
            Packet* p = makePacket(advertisement->care_of_address, lifetime);
            RegistrationRequest* req = (RegistrationRequest*) (p->data());

            //Set new default gateway to router trying to register to
            //Setting it now already will allow for easy routing of request
            gateway = IPAddress(advertisement->care_of_address);

            PendingRegistration* entry = new PendingRegistration();
            //MAC address is hardcoded here as it's never actually used (the rest is dynamic)
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
    //Decrement remaining lifetime of current registration (if one exists)
    if (_remaining_lifetime) {
        _remaining_lifetime--;
        if (!_remaining_lifetime) {
            //Registration timeout
            click_chatter("Registration has timed out");
            _isRegistered = false;
            _care_of_address = IPAddress("0.0.0.0").in_addr();
        }
        else if (_remaining_lifetime <= 10 && !_hasReregistered && _isRegistered) {
            //Low remaining lifetime and no attempt to reregister has been made -> make one
            _hasReregistered = true;

            //Fetch advertisement for router currently registered to and reregister using it
            SavedAdvertisement* advertisement = getAdvertisement(_care_of_address);
            //No need to check if home agent: those registrations start at lifetime == 0 and won't time out
            int lifetime = advertisement->registration_lifetime;
            Packet* p = makePacket(advertisement->care_of_address, lifetime);
            RegistrationRequest* req = (RegistrationRequest*) (p->data());
            PendingRegistration* entry = new PendingRegistration();
            //Again, hardcoded as it won't be used
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


CLICK_ENDDECLS
EXPORT_ELEMENT(RegistrationRequestSender)
