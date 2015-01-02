#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "agentadvertisementsender.hh"

CLICK_DECLS
AgentAdvertisementSender::AgentAdvertisementSender() :
        _timer(this), _seq_number(0) {

}

AgentAdvertisementSender::~AgentAdvertisementSender() {
}

int AgentAdvertisementSender::configure(Vector<String> &conf,
        ErrorHandler *errh) {
    if (cp_va_kparse(conf, this, errh, "IP", cpkM, cpIPAddress, &_address, "HOME", cpkM, cpBool, &_isHomeAgent,
            "FOREIGN", cpkM, cpBool, &_isForeignAgent, "RLIFETIME", cpkM, cpInteger, &_registration_lifetime,
            "LIFETIME", cpkM, cpInteger, &_lifetime, "INTERVAL", cpkM, cpInteger, &_interval, cpEnd) < 0)
        return -1;
    return 0;
}

int AgentAdvertisementSender::initialize(ErrorHandler *errh) {
    _timer.initialize(this);
    _timer.schedule_after_msec(100);
    return 0;
}

/**
 * Generates an agent advertisement
 */
Packet* AgentAdvertisementSender::makePacket() {
    int packetsize = sizeof(ICMPAgentAdvertisement) + sizeof(click_icmp) - 4;  //subtract ICMP padding
    int headroom = sizeof(click_ip) + sizeof(click_ether);
    WritablePacket* packet = Packet::make(headroom, 0, packetsize, 0);
    if (packet == 0)
        click_chatter("cannot make packet!");
    memset(packet->data(), 0, packet->length());
    click_icmp* icmp_header = (click_icmp*) packet->data();
    icmp_header->icmp_type = 9; //type and code fixed for agent advertisement
    icmp_header->icmp_code = 0;
    icmp_header->icmp_cksum = 0; //to be set later (or not; cksum==0 gets accepted)
    ICMPAgentAdvertisement* advertisement =
            (ICMPAgentAdvertisement*) (packet->data() + 4);
    advertisement->num_addrs = 1; //Only supports 1 address
    advertisement->addr_entry_size = 2; //always 2: address and preference level
    advertisement->lifetime = htons(_lifetime); //Determined by user of element
    advertisement->address = _address; //Determined by user of element
    advertisement->preference_level = htonl(2147483647); //highest 32bit signed 2s complement (isn't used)
    advertisement->type = 16;    //Type and length fixed
    advertisement->length = 10;
    advertisement->seq_number = htons(_seq_number); //Starts at 0, increments, when overflowing is set to 256
    advertisement->registration_lifetime = htons(_registration_lifetime); //Determined by user of element
    if (_isHomeAgent)
        advertisement->flags = 32; //00100000 (only home agent flag set)
    else if (_isForeignAgent)
        advertisement->flags = 144;  //10010000 (only registration required and foreign agent flag set)
    advertisement->reserved = 0; //Unused
    advertisement->care_of_address = _address; //Same address as for router advertisement part

    icmp_header->icmp_cksum = click_in_cksum( //set checksum
            (const unsigned char *) icmp_header, packet->length());

    return packet;
}

/**
 * Dummy function: unused but needed to compile
 */
void AgentAdvertisementSender::push(int, Packet *p) {
    output(0).push(p);
}


/*
 * Generate and send advertisement, change sequence number
 */
void AgentAdvertisementSender::run_timer(Timer *) {
    if (Packet *q = makePacket()) {
        click_chatter("Sending advertisement");
        output(0).push(q);
        if (_seq_number == 65536)
            _seq_number = 256;
        else
            _seq_number++;

        //_interval = 500;  //FOR TESTING PURPOSES ONLY: Tests reregistration on Agent reset detected through sequence numbers
        //if (_seq_number > 1)
        //    _seq_number = 0;



    }
    _timer.reschedule_after_msec(_interval);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(AgentAdvertisementSender)
