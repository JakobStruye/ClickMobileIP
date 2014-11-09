vis :: VisitorList();
mob :: MobilityBindingList();


ICMPPingSource(1.0.0.0, 1.0.0.1) -> 
RegistrationRequestSender -> 
//Print(MAXLENGTH 192) -> 
UDPIPEncap(192.168.1.1, 4321, 192.168.2.1, 1234) -> 
//Print(MAXLENGTH 192) -> 
EtherEncap(0x0800, 1:1:1:1:1:1, 2:2:2:2:2:2) -> 
[0]vis[0] ->
Strip(14) -> 
ForeignRequestProcess() -> 
//IPPrint(MAXLENGTH 256) -> 
[0]mob[0] ->
HomeRequestProcess() -> 
UDPIPEncap(192.168.1.2, 1234, 192.168.2.1, 1000) ->
//Print(MAXLENGTH 192, HEADROOM 1) -> 
ForeignReplyProcess() ->
EtherEncap(0x0800, 3:3:3:3:3:3, 4:4:4:4:4:4) ->
[1]vis[1] ->
//Print(MAXLENGTH 192, HEADROOM 1) -> 
Strip(14) ->
IPPrint(MAXLENGTH 256) ->
SimplePushNull() ->
Strip(28) ->
//ReplyPrinter() ->
Discard

mob[1] ->
IPEncap(ipip, 1.1.1.1, 2.2.2.2) ->
enc::Encapsulator(SRC 192.168.1.2)[0] ->
[1]mob

enc[1] ->
Discard
