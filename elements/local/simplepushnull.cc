#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/udp.h>

#include "simplepushnull.hh"

CLICK_DECLS
SimplePushNull::SimplePushNull()
{}

SimplePushNull::~ SimplePushNull()
{}

int SimplePushNull::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(conf, this, errh, cpEnd) < 0) return -1;
	return 0;
}

void SimplePushNull::push(int, Packet *p){
    click_ip* ip_header = (click_ip*) p->data();
    click_udp* udp_header = (click_udp*) (ip_header+1);
	click_chatter("Push works %i", udp_header->uh_sport);
	output(0).push(p);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(SimplePushNull)
