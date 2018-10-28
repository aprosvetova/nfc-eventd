#ifndef __NEM_PLANTAIN__
#define __NEM_PLANTAIN__

#include "nem_common.h"

void nem_plantain_init(nfcconf_context *module_context, nfcconf_block* module_block);
int nem_plantain_event_handler(nfc_device* nfc_device, nfc_target* tag, const nem_event_t event);

#endif /* __NEM_PLANTAIN__ */

