/*
 * Nfc Event Module Execute
 *
 * Copyright (C) 2009 Romuald Conty <romuald@libnfc.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif // HAVE_CONFIG_H

#include "nem_plantain.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>

#define ONERROR_IGNORE	0
#define ONERROR_RETURN	1
#define ONERROR_QUIT	2

#ifdef __APPLE__
#include <crt_externs.h>
#define environ (*_NSGetEnviron())
#else
extern char **environ;
#endif

static uint8_t keys[] = {
        0xE5, 0x6A, 0xC1, 0x27, 0xDD, 0x45,
        0x77, 0xDA, 0xBC, 0x98, 0x25, 0xE1
};
static mifare_param mp;

void
nem_plantain_init( nfcconf_context *module_context, nfcconf_block* module_block ) {
    set_debug_level ( 1 );
}

void
load_tag(nfc_device* nfc_device, nfc_target* tag) {
    debug_print_tag(tag);

    /// @TODO We don't need to reselect tag to get his UID: nfc_target contains this data.
    // Poll for a ISO14443A (MIFARE) tag
    if (!nfc_initiator_select_passive_target(nfc_device, tag->nm, tag->nti.nai.abtUid, tag->nti.nai.szUidLen, tag)) {
        DBG("%s", "ISO14443A (MIFARE) tag not found" );
        return;
    }
}

bool
authenticate(nfc_device* nfc_device, nfc_target* tag, uint8_t uiBlock) {
    memcpy(mp.mpa.abtAuthUid, tag->nti.nai.abtUid + tag->nti.nai.szUidLen - 4, 4);
    if (uiBlock == 0x10) {
        memcpy(mp.mpa.abtKey, keys, 6);
    } else {
        memcpy(mp.mpa.abtKey, keys+6, 6);
    }
    return nfc_initiator_mifare_cmd(nfc_device, MC_AUTH_A, uiBlock, &mp);
}

int
nem_plantain_event_handler(nfc_device* nfc_device, nfc_target* tag, const nem_event_t event) {
    switch (event) {
        case EVENT_TAG_INSERTED:
            load_tag(nfc_device, tag);
            if (authenticate(nfc_device, tag, 0x10)) {
                ERR("%s", "SUCKASS");
            } else {
                ERR("%s", "fail(");
            }
            if (authenticate(nfc_device, tag, 0x16)) {
                ERR("%s", "SUCKASS");
            } else {
                ERR("%s", "fail(");
            }
            print_nfc_target(tag, false);
            break;
        case EVENT_TAG_REMOVED:
            break;
        default:
            return -1;
    }
    return 0;
}

bool
nfc_initiator_mifare_cmd(nfc_device *pnd, const mifare_cmd mc, const uint8_t ui8Block, mifare_param *pmp)
{
    uint8_t  abtRx[265];
    size_t  szParamLen;
    uint8_t  abtCmd[265];
    //bool    bEasyFraming;

    abtCmd[0] = mc;               // The MIFARE Classic command
    abtCmd[1] = ui8Block;         // The block address (1K=0x00..0x39, 4K=0x00..0xff)

    switch (mc) {
        // Read and store command have no parameter
        case MC_READ:
        case MC_STORE:
            szParamLen = 0;
            break;

            // Authenticate command
        case MC_AUTH_A:
        case MC_AUTH_B:
            szParamLen = sizeof(struct mifare_param_auth);
            break;

            // Data command
        case MC_WRITE:
            szParamLen = sizeof(struct mifare_param_data);
            break;

            // Value command
        case MC_DECREMENT:
        case MC_INCREMENT:
        case MC_TRANSFER:
            szParamLen = sizeof(struct mifare_param_value);
            break;

            // Please fix your code, you never should reach this statement
        default:
            return false;
    }

    // When available, copy the parameter bytes
    if (szParamLen)
        memcpy(abtCmd + 2, (uint8_t *) pmp, szParamLen);

    // FIXME: Save and restore bEasyFraming
    // bEasyFraming = nfc_device_get_property_bool (pnd, NP_EASY_FRAMING, &bEasyFraming);
    if (nfc_device_set_property_bool(pnd, NP_EASY_FRAMING, true) < 0) {
        nfc_perror(pnd, "nfc_device_set_property_bool");
        return false;
    }
    // Fire the mifare command
    int res;
    if ((res = nfc_initiator_transceive_bytes(pnd, abtCmd, 2 + szParamLen, abtRx, sizeof(abtRx), -1))  < 0) {
        if (res == NFC_ERFTRANS) {
            // "Invalid received frame",  usual means we are
            // authenticated on a sector but the requested MIFARE cmd (read, write)
            // is not permitted by current acces bytes;
            // So there is nothing to do here.
        } else {
            nfc_perror(pnd, "nfc_initiator_transceive_bytes");
        }
        // XXX nfc_device_set_property_bool (pnd, NP_EASY_FRAMING, bEasyFraming);
        return false;
    }
    /* XXX
    if (nfc_device_set_property_bool (pnd, NP_EASY_FRAMING, bEasyFraming) < 0) {
      nfc_perror (pnd, "nfc_device_set_property_bool");
      return false;
    }
    */

    // When we have executed a read command, copy the received bytes into the param
    if (mc == MC_READ) {
        if (res == 16) {
            memcpy(pmp->mpd.abtData, abtRx, 16);
        } else {
            return false;
        }
    }
    // Command succesfully executed
    return true;
}