
///===========================================================================///
/// An IP router with 1 interface.
///===========================================================================///

elementclass MobileNode 
{
$addr_info, $gateway
|

  udpipenc :: UDPIPEncap($addr_info:ip, 1234, 192.168.3.254, 434)
  request :: RegistrationRequestSender(HOMEADDRESS 192.168.2.1, HOMEAGENT 192.168.2.254);
  

	// Shared IP input path and routing table
	ip :: Strip(14)
	-> CheckIPHeader
	-> rt :: LinearIPLookup(
		$addr_info:ip/32 0,
		$addr_info:ipnet 1,
    255.255.255.255/255.255.255.255 0,
		0.0.0.0/0.0.0.0 $gateway 1);

	
	// ARP responses are copied to each ARPQuerier and the host.
	arpt :: Tee(1);
	
	// Input and output paths for eth0
	c0 :: Classifier(12/0806 20/0001, 12/0806 20/0002, -);
	input[0] -> HostEtherFilter($addr_info:eth) -> c0;
	c0[0] -> ar0 :: ARPResponder($addr_info) -> [0]output;
	arpq0 :: ARPQuerier($addr_info) -> ToDump("test.dump") -> [0]output;
	c0[1] -> arpt;
	arpt[0] -> [1]arpq0;
	c0[2] -> Paint(1) -> ip;

  request[0] //Only outputs newly generated Registration Requests
  //Modify udpipenc to that it sets IP dst addresses to that of the Agent trying to register to
  -> Script (TYPE PACKET, set dstaddr $(request.gateway), write udpipenc.dst $dstaddr)  
  //Set the default gateway (to properly route the Request)
  -> Script(TYPE PACKET, set gw $(request.gateway), write rt.remove 0.0.0.0/0.0.0.0, write rt.add 0.0.0.0/0.0.0.0 $gw 1)
  -> udpipenc
  -> rt
		
	// Local delivery
	rt[0] ->
  Unstrip(14) ->
  [0]request[1] -> //RegistrationRequestSender will receive and process advertisements and replies here (this output is for all but Requests)
  Strip(14) ->
  //Change the routing table according to new Reply (will leave it unchanged if it was not a Reply)
  Script(TYPE PACKET, set gw $(request.gateway), write rt.remove 0.0.0.0/0.0.0.0, write rt.add 0.0.0.0/0.0.0.0 $gw 1) ->
  //To ICMPPingResponder (RegistrationReply and other non ICMPPingRequests will be discarded there)
  [1]output; 
	
	// Forwarding path for eth0
	rt[1] -> DropBroadcasts
	-> gio0 :: IPGWOptions($addr_info)
	-> FixIPSrc($addr_info)
	-> dt0 :: DecIPTTL
	-> fr0 :: IPFragmenter(1500)
	-> [0]arpq0;
	dt0[1] -> ICMPError($addr_info, timeexceeded) -> rt;
	fr0[1] -> ICMPError($addr_info, unreachable, needfrag) -> rt;
	gio0[1] -> ICMPError($addr_info, parameterproblem) -> rt;
	
}
