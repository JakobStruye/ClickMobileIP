#ifndef PENDINGREGISTRATION_HH_
#define PENDINGREGISTRATION_HH_


/**
 * struct for pending registrations at mobile node
 */
struct PendingRegistration {
    uint8_t mobile_MAC[6];
    struct in_addr dst;
    struct in_addr care_of_address;
    uint32_t identification[2];
    uint16_t lifetime;
    uint16_t remaining_lifetime;
};

#endif
