#ifndef MOBILITYBINDINGLISTENTRY_HH_
#define MOBILITYBINDINGLISTENTRY_HH_

struct MobilityBindingListEntry {
    in_addr home_address;
    in_addr care_of_address;
    uint32_t identification[2];
    uint16_t remaining_lifetime;
};



#endif
