#ifndef REGISTRATIONREQUEST_HH
#define REGISTRATIONREQUEST_HH

struct RegistrationRequest {
	uint8_t type;
	bool flags[8];
	uint16_t lifetime;
	struct in_addr home_address;
	struct in_addr home_agent;
	struct in_addr care_of_address;
	uint32_t identification[2];
};

#endif
