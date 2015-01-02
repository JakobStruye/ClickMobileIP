#ifndef VISITORLISTENTRY_HH_
#define VISITORLISTENTRY_HH_

/**
 * Struct for an entry in the visitor list at a foreign agent
 */
struct VisitorListEntry {
    uint8_t mobile_MAC[6];
    in_addr ip_src;
    in_addr ip_dst;
    uint16_t port_src;
    in_addr home_agent;
    uint32_t identification[2];
    uint16_t lifetime;
    uint16_t remaining_lifetime;
    bool active;
};



#endif
