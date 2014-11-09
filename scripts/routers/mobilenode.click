
///===========================================================================///
/// An IP router with 1 interface.
///===========================================================================///

elementclass MobileNode 
{
$addr_info, $gateway
|
	// Shared IP input path and routing table
	ip :: Strip(14)
	//-> IPPrint("test")
	-> CheckIPHeader
	-> rt :: LinearIPLookup(
		$addr_info:ip/32 0,
		$addr_info:ipnet 1,
		0.0.0.0/0.0.0.0 $gateway 1);
	
	// ARP responses are copied to each ARPQuerier and the host.
	arpt :: Tee(1);
	
	// Input and output paths for eth0
	c0 :: Classifier(12/0806 20/0001, 12/0806 20/0002, -);
	input[0] -> HostEtherFilter($addr_info:eth) -> c0;
	c0[0] -> ar0 :: ARPResponder($addr_info) -> [0]output;
	arpq0 :: ARPQuerier($addr_info) -> [0]output;
	c0[1] -> arpt;
	arpt[0] -> [1]arpq0;
	c0[2] -> Paint(1) -> ip;

  //Generate registration requests
  request :: RegistrationRequestSender();
  request[0] ->  UDPIPEncap($addr_info:ip, 1234, 192.168.3.254, 434)
  -> EtherEncap(0x0800, $addr_info, 00:50:BA:85:84:C1)
  -> [0]output;
		
	// Local delivery
	rt[0] ->
  [0]request[1] ->
  //Script(TYPE PACKET, write rt.remove 0.0.0.0/0.0.0.0) ->
  //Script(TYPE PACKET, write rt.add 0.0.0.0/0.0.0.0 1.0.0.0 ) ->
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
