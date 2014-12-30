#ifndef SAVEDADVERTISEMENT_HH_
#define SAVEDADVERTISEMENT_HH_

/**
 * Struct containing relevant info of advertisement at mobile node
 */
struct SavedAdvertisement {
	uint16_t lifetime; //This is the lifetime of the advertisement, NOT  for registration
	uint16_t remaining_lifetime;
	uint16_t registration_lifetime;
	struct in_addr care_of_address;
	uint16_t latest_seq_number;
};

#endif
