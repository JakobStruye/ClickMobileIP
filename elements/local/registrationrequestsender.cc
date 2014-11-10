#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "registrationrequestsender.hh"
#include <iostream>

CLICK_DECLS
RegistrationRequestSender::RegistrationRequestSender() : _timer(this), gateway(IPAddress("192.168.3.254")), isHome(false){  //TODO set right default gw
	_pendingRegistrations = std::list<PendingRegistration*>();
}

RegistrationRequestSender::~ RegistrationRequestSender()
{}

int RegistrationRequestSender::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(conf, this, errh, cpEnd) < 0) return -1;
	return 0;
}

int RegistrationRequestSender::initialize(ErrorHandler *errh)
{
  _timer.initialize(this);
    _timer.schedule_after_msec(100);
    return 0;
}


PendingRegistration* RegistrationRequestSender::getEntry(uint32_t identification) {
    for(std::list<PendingRegistration*>::iterator it = _pendingRegistrations.begin(); it != _pendingRegistrations.end(); it++)
        if ((*it)->identification[1] == identification)
            return (*it);

    return NULL;
}

void RegistrationRequestSender::deleteEntry(PendingRegistration* entry) {
    for(std::list<PendingRegistration*>::iterator it = _pendingRegistrations.begin(); it != _pendingRegistrations.end(); it++) {
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



Packet* RegistrationRequestSender::makePacket() {
	int packetsize = sizeof(RegistrationRequest);
	int headroom = sizeof(click_udp) + sizeof(click_ip) + sizeof(click_ether);
	WritablePacket* packet = Packet::make(headroom,0,packetsize,0);
	if (packet == 0) click_chatter("cannot make packet!");
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
	if (isHome)
	    format->lifetime = htons(0);
	else
	    format->lifetime = htons(300);
    format->home_address = IPAddress("192.168.2.1").in_addr();
    format->home_agent = IPAddress("192.168.2.254").in_addr();
    if (isHome)
        format->care_of_address = IPAddress("192.168.2.254").in_addr();
    else
        format->care_of_address = IPAddress("192.168.3.254").in_addr();
    format->identification[0] = htonl(1000);
    format->identification[1] = htonl(1100);

	return packet;
}

void RegistrationRequestSender::run_timer(Timer *) {
  if (isHome)
      gateway = IPAddress("192.168.2.254");
  else
      gateway = IPAddress("192.168.3.254");
  if (Packet *q = makePacket()) {
        //click_chatter("Timer is go");
        PendingRegistration* entry = new PendingRegistration();
        entry->mobile_MAC[0] = 0;
        entry->mobile_MAC[1] = 80;
        entry->mobile_MAC[2] = 186;
        entry->mobile_MAC[3] = 133;
        entry->mobile_MAC[4] = 132;
        entry->mobile_MAC[5] =  193;
        if (isHome)
            entry->dst = IPAddress("192.168.2.254").in_addr();
        else
            entry->dst = IPAddress("192.168.3.254").in_addr();
        if (isHome)
            entry->care_of_address = IPAddress("192.168.2.254").in_addr();
        else
            entry->care_of_address = IPAddress("192.168.3.254").in_addr();
        entry->identification[0] = 1000;
        entry->identification[1] = 1100;
        if (isHome)
            entry->lifetime = 0;
        else
            entry->lifetime = 300;
        entry->remaining_lifetime = entry->lifetime;
        _pendingRegistrations.push_back(entry);
        isHome = (!isHome);
        output(0).push(q); }
  _timer.reschedule_after_msec(5000);
}
	

void RegistrationRequestSender::push(int, Packet *p){
    click_ip* ip_header = (click_ip*) p->data();
    if (ip_header->ip_p != 17) {
        output(1).push(p);
        return;
    }
    click_udp* udp_header = (click_udp*) (ip_header+1);
    if (ntohs(udp_header->uh_sport) != 434) {
        output(1).push(p);
        return;
    }

    RegistrationReply* rep = (RegistrationReply*) (udp_header+1);
    PendingRegistration* entry = getEntry(ntohl(rep->identification[1]));
    gateway = IPAddress(entry->dst);
    deleteEntry(entry);
    delete entry;
	//click_chatter("ACCEPTED");
	output(1).push(p);
}




CLICK_ENDDECLS
EXPORT_ELEMENT(RegistrationRequestSender)
