#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "replyprinter.hh"
#include <iostream>

CLICK_DECLS
ReplyPrinter::ReplyPrinter(){

}

ReplyPrinter::~ ReplyPrinter()
{}

int ReplyPrinter::configure(Vector<String> &conf, ErrorHandler *errh) {
    if (cp_va_kparse(conf, this, errh, cpEnd) < 0) return -1;
    return 0;
}

/*
 * FOR TESTING PURPOSES ONLY
 * Expects non-encapsulated Reply
 *
 * Input 0: Reply, to be printed
 *
 * Output 0: Unchanged Reply
 */
void ReplyPrinter::push(int, Packet *p){
    WritablePacket* q = (WritablePacket*) p;
    RegistrationReply* reply = (RegistrationReply*) (q->data());
    click_chatter("REPLY");
    click_chatter("type %i", reply->type);
    click_chatter("code %i", reply->code);
    click_chatter("lifetime %i", reply->lifetime);
    const char* home_address = IPAddress(reply->home_address).unparse().c_str();
    click_chatter("home_address %s", home_address);
    const char* home_agent = IPAddress(reply->home_agent).unparse().c_str();
    click_chatter("home_agent %s", home_agent);
    click_chatter("identification %i %i", reply->identification[0], reply->identification[1]);
    output(0).push(q);
}




CLICK_ENDDECLS
//EXPORT_ELEMENT(ReplyPrinter)




