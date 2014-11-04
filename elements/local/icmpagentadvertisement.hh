struct ICMPAgentAdvertisement {
	uint8_t num_addrs;
	uint8_t addr_entry_size;
	uint16_t lifetime;
	uint32_t address;
	uint32_t preference_level;
	uint8_t type;
	uint8_t length;
	uint16_t seq_number;
	uint16_t registration_lifetime;
	bool flags[8];
	uint8_t reserved;
	uint32_t care_of_address;
};
