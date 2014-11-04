ICMPPingSource(1.0.0.0, 1.0.0.1) -> 
RegistrationRequestSender -> 
Print(MAXLENGTH 192) -> 
UDPIPEncap(192.168.1.1, 1235, 192.168.2.1, 1234) -> 
Print(MAXLENGTH 192) -> 
EtherEncap(0x0800, 1:1:1:1:1:1, 2:2:2:2:2:2) -> 
Strip(14) -> 
ForeignRequestProcess() -> 
IPPrint(MAXLENGTH 256) -> 
HomeRequestProcess() -> 
Print(MAXLENGTH 192, HEADROOM 1) -> 
Discard
