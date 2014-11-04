#ifndef REGISTRATIONREPLY_HH_
#define REGISTRATIONREPLY_HH_

struct RegistrationReply {
    uint8_t type;
    uint8_t code;
    uint16_t lifetime;
    struct in_addr home_address;
    struct in_addr home_agent;
    uint32_t identification[2];
};

#endif
