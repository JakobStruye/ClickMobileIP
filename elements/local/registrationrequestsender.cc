#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "registrationrequestsender.hh"
#include <iostream>

CLICK_DECLS
RegistrationRequestSender::RegistrationRequestSender(){
	
}

RegistrationRequestSender::~ RegistrationRequestSender()
{}

int RegistrationRequestSender::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(conf, this, errh, cpEnd) < 0) return -1;
	return 0;
}




Packet* RegistrationRequestSender::makePacket() {
	int packetsize = sizeof(RegistrationRequest);
	int headroom = sizeof(click_udp) + sizeof(click_ip) + sizeof(click_ether);
	WritablePacket* packet = Packet::make(headroom,0,packetsize,0);
	if (packet == 0) click_chatter("cannot make packet!");
	memset(packet->data(), 0, packet->length());
	RegistrationRequest* format = (RegistrationRequest*) packet->data();
	format->type = 1; //fixed
    format->flags[0] = 0; //S
    format->flags[1] = 0; //B
    format->flags[2] = 0; //D
    format->flags[3] = 0; //M
    format->flags[4] = 0; //G
    format->flags[5] = 0; //r, should be 0
    format->flags[6] = 0; //T
    format->flags[7] = 0; //x, should be 0 but will be ignored
    format->lifetime = htons(300);
    format->home_address = IPAddress("192.168.1.1").in_addr(); //192.168.1.1
    format->home_agent = IPAddress("192.168.1.2").in_addr(); //192.168.1.2
    format->care_of_address = IPAddress("192.168.2.1").in_addr(); //192.168.2.1
    format->identification[0] = htonl(1000);
    format->identification[1] = htonl(1100);

	return packet;
}
	

void RegistrationRequestSender::push(int, Packet *p){
	Packet* req = makePacket();
	output(0).push(req);
}




CLICK_ENDDECLS
EXPORT_ELEMENT(RegistrationRequestSender)
