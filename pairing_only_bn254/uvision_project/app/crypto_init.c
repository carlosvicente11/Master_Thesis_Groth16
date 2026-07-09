#include "pairing.h"

int pairing_init(void) {
    if (core_init() != RLC_OK) {
        return -1;
    }
    ep_param_set(BN_P254E);
    ep2_curve_set_twist(RLC_EP_DTYPE);
    return 0;
}

void pairing_cleanup(void) {
    core_clean();
}
