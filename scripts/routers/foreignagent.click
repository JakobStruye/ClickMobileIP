
///===========================================================================///
/// An IP router with 2 interfaces.
///===========================================================================///

elementclass ForeignAgent 
{
$private_address, $public_address, $default_gateway
|
  vis :: VisitorList(IP $private_address);
  advertise :: AgentAdvertisementSender(IP 192.168.3.254, HOME 0, FOREIGN 1, RLIFETIME 300, LIFETIME 4, INTERVAL 3000);
  forreq :: ForeignRequestProcess();

  Script(write forreq.addOwnIP IP $private_address:ip)
  Script(write forreq.addOwnIP IP $public_address:ip)


	// Shared IP input path and routing table
	ip :: Strip(14)
	-> CheckIPHeader
	-> rt :: StaticIPLookup(
		$private_address:ip/32 0,
		$public_address:ip/32 0,
		$private_address:ipnet 1,
		$public_address:ipnet $default_gateway 2);
	
	// ARP responses are copied to each ARPQuerier and the host.
	arpt :: Tee(2);
	
	// Input and output paths for eth0
	c0 :: Classifier(12/0806 20/0001, 12/0806 20/0002, -);
	input[0] -> HostEtherFilter($private_address:eth) -> c0;
	c0[0] -> ar0 :: ARPResponder($private_address) -> [0]output;
	arpq0 :: ARPQuerier($private_address) -> [0]output;
	c0[1] -> arpt;
	arpt[0] -> [1]arpq0;
	c0[2] 
  -> [0]vis[0]  //Will add VisitorList entry in case of Request
  -> Paint(1) -> ip;
	
	// Input and output paths for eth1
	c1 :: Classifier(12/0806 20/0001, 12/0806 20/0002, -);
	input[1] -> HostEtherFilter($public_address:eth) -> c1;
	c1[0] -> ar1 :: ARPResponder($public_address) -> [1]output;
	arpq1 :: ARPQuerier($public_address) -> [1]output;
	c1[1] -> arpt;
	arpt[1] -> [1]arpq1;
	c1[2] ->  Paint(2) -> ip;
	
	// Local delivery
  //First check for tunneled packets and decapsulate
	rt[0] -> findencap::IPClassifier(ip proto 4, -);

  //Tunneled packets
  findencap[0]
  -> Strip(20) //strip outer IP header
  -> CheckIPHeader
  -> DecIPTTL
  -> EtherEncap(0x0800, $private_address:ether, 2:2:2:2:2:2)   //Placeholder dst address
  -> [2]vis[2]   //Sets ethernet dst
  -> [0]output;

  //Not a tunneled packet
  findencap[1] 
  //Check if Registration Reply or Request
  -> forrep::ForeignReplyProcess[0] //on this output if not Reply
  //Must be Request then, change IP addresses and UDP ports
  -> forreq[0]
  -> GetIPAddress(IP dst) 
  -> SetIPChecksum -> SetUDPChecksum -> rt; 

  //Registration Reply
  forrep[1] 
  -> GetIPAddress(IP dst) 
	-> gioReply :: IPGWOptions($public_address)
	-> FixIPSrc($public_address)
	-> dtReply :: DecIPTTL
	-> frReply :: IPFragmenter(1500)
  -> EtherEncap(0x0800, $private_address:ether, 1:1:1:1:1:1) //Placeholder dst address
  -> [1]vis[1]    //Set Ethernet dst, UDP src/dst, UDP ports
  -> Strip(14)
  -> SetIPChecksum
  -> SetUDPChecksum
  -> Unstrip(14)
  -> [0]output;
  
  //Fixes error of nonexistent output
  Idle -> [2]output

  //Automatically generated advertisements
  advertise
  -> IPEncap(1, $private_address:ip, 255.255.255.255, TTL 1) //Broadcast
  -> SetIPChecksum
  -> EtherEncap(0x0800, $private_address:eth, FF:FF:FF:FF:FF:FF) //Broadcast
  -> [0]output;	

  //Forwarding replies (if request denied) generated here
  forreq[1]
  -> UDPIPEncap($private_address:ip, 434, 2.2.2.2, 434) //All values placeholder
  -> EtherEncap(0x0800, $private_address:ether, 1:1:1:1:1:1) //Placeholder dst address
  -> [1]vis   //Set Ethernet dst, UDP src/dst, UDP ports


	// Forwarding path for eth0
	rt[1] -> DropBroadcasts
	-> cp0 :: PaintTee(1)
	-> gio0 :: IPGWOptions($private_address)
	-> FixIPSrc($private_address)
	-> dt0 :: DecIPTTL
	-> fr0 :: IPFragmenter(1500)
	-> [0]arpq0;
	dt0[1] -> ICMPError($private_address, timeexceeded) -> rt;
	fr0[1] -> ICMPError($private_address, unreachable, needfrag) -> rt;
	gio0[1] -> ICMPError($private_address, parameterproblem) -> rt;
	cp0[1] -> ICMPError($private_address, redirect, host) -> rt;
	
	// Forwarding path for eth1
	rt[2] -> DropBroadcasts
	-> cp1 :: PaintTee(2)
	-> gio1 :: IPGWOptions($public_address)
	-> FixIPSrc($public_address)
	-> dt1 :: DecIPTTL
	-> fr1 :: IPFragmenter(1500)
	-> [0]arpq1;
	dt1[1] -> ICMPError($public_address, timeexceeded) -> rt;
	fr1[1] -> ICMPError($public_address, unreachable, needfrag) -> rt;
	gio1[1] -> ICMPError($public_address, parameterproblem) -> rt;
	cp1[1] -> ICMPError($public_address, redirect, host) -> rt;

}
