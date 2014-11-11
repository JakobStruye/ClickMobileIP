#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "agentsolicitationsender.hh"
#include <iostream>

CLICK_DECLS
AgentSolicitationSender::AgentSolicitationSender() : _timer(this){
	
}

AgentSolicitationSender::~ AgentSolicitationSender()
{}

int AgentSolicitationSender::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(conf, this, errh, cpEnd) < 0) return -1;
	return 0;
}

int
AgentSolicitationSender::initialize(ErrorHandler *errh)
{
  _timer.initialize(this);
	_timer.schedule_after_msec(100);
	return 0;
}


Packet* AgentSolicitationSender::makePacket() {
	int packetsize = sizeof(ICMPAgentSolicitation);
	int headroom = sizeof(click_ip) + sizeof(click_icmp) + sizeof(click_ether);
	WritablePacket* packet = Packet::make(headroom,0,packetsize,0);
	if (packet == 0) click_chatter("cannot make packet!");
	memset(packet->data(), 0, packet->length());
	ICMPAgentSolicitation* format = (ICMPAgentSolicitation*) packet->data();
	format->reserved = htonl(0);
	return packet;
}
	

void AgentSolicitationSender::push(int, Packet *p){
	click_chatter("Generated solicitation");
	
	output(0).push(p);
}

void AgentSolicitationSender::run_timer(Timer *) {
  if (Packet *q = makePacket()) {
		click_chatter("Timer is go");
		std::cout << "Printed" << std::endl;
		output(0).push(q); }
  _timer.reschedule_after_msec(3000);
}


CLICK_ENDDECLS
//EXPORT_ELEMENT(AgentSolicitationSender)
