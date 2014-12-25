#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "agentadvertisementsender.hh"
#include <iostream>

CLICK_DECLS
AgentAdvertisementSender::AgentAdvertisementSender() :
        _timer(this), _seq_number(0) {

}

AgentAdvertisementSender::~AgentAdvertisementSender() {
}

int AgentAdvertisementSender::configure(Vector<String> &conf,
        ErrorHandler *errh) {
    if (cp_va_kparse(conf, this, errh, "IP", cpkM, cpIPAddress, &_address, "HOME", cpkM, cpBool, &_isHomeAgent,
            "FOREIGN", cpkM, cpBool, &_isForeignAgent, "RLIFETIME", cpkM, cpInteger, &_registration_lifetime, cpEnd) < 0)
        return -1;
    return 0;
}

int AgentAdvertisementSender::initialize(ErrorHandler *errh) {
    _timer.initialize(this);
    _timer.schedule_after_msec(100);
    return 0;
}

Packet* AgentAdvertisementSender::makePacket() {
    int packetsize = sizeof(ICMPAgentAdvertisement) + sizeof(click_icmp) - 4;
    int headroom = sizeof(click_ip) + sizeof(click_ether); //subtract padding
    WritablePacket* packet = Packet::make(headroom, 0, packetsize, 0);
    if (packet == 0)
        click_chatter("cannot make packet!");
    memset(packet->data(), 0, packet->length());
    click_icmp* icmp_header = (click_icmp*) packet->data();
    icmp_header->icmp_type = 9;
    icmp_header->icmp_code = 0;
    icmp_header->icmp_cksum = 0;
    ICMPAgentAdvertisement* advertisement =
            (ICMPAgentAdvertisement*) (packet->data() + 4);
    advertisement->num_addrs = 1;
    advertisement->addr_entry_size = 2;
    advertisement->lifetime = htons(_lifetime);
    advertisement->address = _address;
    advertisement->preference_level = htonl(2147483647); //highest 32bit signed 2s complement
    advertisement->type = 16;
    advertisement->length = 10;
    advertisement->seq_number = htons(_seq_number);
    advertisement->registration_lifetime = htons(_registration_lifetime);
    if (_isHomeAgent)
        advertisement->flags = 32; //00100000
    else if (_isForeignAgent)
        advertisement->flags = 144;  //10010000
    advertisement->reserved = 0;
    advertisement->care_of_address = _address;

    icmp_header->icmp_cksum = click_in_cksum(
            (const unsigned char *) icmp_header, packet->length());

    return packet;
}

void AgentAdvertisementSender::push(int, Packet *p) {
    output(0).push(p);
}

void AgentAdvertisementSender::run_timer(Timer *) {
    if (Packet *q = makePacket()) {
        click_chatter("Timer is go");
        output(0).push(q);
        if (_seq_number == 65536)
            _seq_number = 256;
        else
            _seq_number++;
    }
    _timer.reschedule_after_msec(3000);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(AgentAdvertisementSender)
