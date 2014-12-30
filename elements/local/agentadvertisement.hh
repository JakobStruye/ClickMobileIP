#ifndef ICMPAGENTADVERTISEMENT_HH_
#define ICMPAGENTADVERTISEMENT_HH_

/**
 * This includes both the regular router advertisement and the mobility agent advertisement extension
 */
struct ICMPAgentAdvertisement {
	uint8_t num_addrs;
	uint8_t addr_entry_size;
	uint16_t lifetime;
	struct in_addr address;
	uint32_t preference_level;
	uint8_t type;
	uint8_t length;
	uint16_t seq_number;
	uint16_t registration_lifetime;
	uint8_t flags;
	uint8_t reserved;
	struct in_addr care_of_address;
};

#endif
