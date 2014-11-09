ICMPPingSource(1.0.0.0, 1.0.0.1) -> 
RegistrationRequestSender -> 
UDPIPEncap(192.168.1.1, 1235, 192.168.2.1, 1234) -> 
IPPrint(ID 1, TTL 1, TOS 1, LENGTH 1) ->
IPEncap(ipip, 192.168.3.1, 192.168.4.1) -> 
IPPrint(ID 1, TTL 1, TOS 1, LENGTH 1) ->
Discard

