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
#include <curl/curl.h>

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
static char * _tag_uid = NULL;

void
nem_plantain_init( nfcconf_context *module_context, nfcconf_block* module_block ) {
    set_debug_level ( 1 );
}

bool
load_tag(nfc_device* nfc_device, nfc_target* tag, char **dest) {
    if(nfc_initiator_select_passive_target(nfc_device, tag->nm, tag->nti.nai.abtUid, tag->nti.nai.szUidLen, tag)) {
        *dest = malloc(tag->nti.nai.szUidLen*sizeof(char)*2+1);
        size_t szPos;
        char *pcUid = *dest;
        for (szPos=0; szPos < tag->nti.nai.szUidLen; szPos++) {
            sprintf(pcUid, "%02x",tag->nti.nai.abtUid[szPos]);
            pcUid += 2;
        }
        pcUid[0]='\0';
        return true;
    }
    return false;
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
    int balance = -1;
    int lastPaymentDate = -1;
    int lastPaymentValue = -1;
    int lastRideDate = -1;
    int lastRideCost = -1;
    int lastValidatorId = -1;
    int subwayCount = -1;
    int groundCount = -1;
    switch (event) {
        case EVENT_TAG_INSERTED:
            /*if (!load_tag(nfc_device, tag, &_tag_uid)) {
                ERR("%s", "Can't load tag");
                return -1;
            }*/
            if (!authenticate(nfc_device, tag, 0x10)) {
                ERR("%s", "Can't auth block 16");
                return -1;
            }
            if (nfc_initiator_mifare_cmd(nfc_device, MC_READ, 0x10, &mp)) {
                balance = *(int *)mp.mpd.abtData;
                balance = balance/100;
                if (balance < 0) {
                    balance = -1;
                }
            } else {
                ERR("%s", "Can't read block 16");
                return -1;
            }
            if (nfc_initiator_mifare_cmd(nfc_device, MC_READ, 0x12, &mp)) {
                lastPaymentDate = mp.mpd.abtData[4] << 16 | mp.mpd.abtData[3] << 8 | mp.mpd.abtData[2];
                if (lastPaymentDate <= 0) {
                    lastPaymentDate = -1;
                } else {
                    lastPaymentDate = lastPaymentDate*60+1262293200;
                }
                lastPaymentValue = mp.mpd.abtData[10] << 16 | mp.mpd.abtData[9] << 8 | mp.mpd.abtData[8];
                if (lastPaymentValue <= 0) {
                    lastPaymentValue = -1;
                } else {
                    lastPaymentValue = lastPaymentValue/100;
                }
            } else {
                ERR("%s", "Can't read block 18");
                return -1;
            }
            if (!authenticate(nfc_device, tag, 0x14)) {
                ERR("%s", "Can't auth block 20");
            }
            if (nfc_initiator_mifare_cmd(nfc_device, MC_READ, 0x14, &mp)) {
                lastRideDate = mp.mpd.abtData[2] << 16 | mp.mpd.abtData[1] << 8 | mp.mpd.abtData[0];
                if (lastRideDate <= 0) {
                    lastRideDate = -1;
                } else {
                    lastRideDate = lastRideDate*60+1262293200;
                }
                lastRideCost = mp.mpd.abtData[7] << 8 | mp.mpd.abtData[6];
                if (lastRideCost <= 0) {
                    lastRideCost = -1;
                } else {
                    lastRideCost = lastRideCost/100;
                }
                lastValidatorId = mp.mpd.abtData[5] << 8 | mp.mpd.abtData[4];
                if (lastValidatorId <= 0) {
                    lastValidatorId = -1;
                }
            } else {
                ERR("%s", "Can't read block 20");
                return -1;
            }
            if (nfc_initiator_mifare_cmd(nfc_device, MC_READ, 0x15, &mp)) {
                if (mp.mpd.abtData[0] >= 0) {
                    subwayCount = mp.mpd.abtData[0];
                }
                if (mp.mpd.abtData[1] >= 0) {
                    groundCount = mp.mpd.abtData[1];
                }
            } else {
                ERR("%s", "Can't read block 21");
                return -1;
            }
            char url[1024];
            sprintf(url,"http://192.168.1.2:9566/tag?id=%s&b=%d&lpd=%d&lpv=%d&lrd=%d&lrc=%d&lrv=%d&sub=%d&gr=%d", "a", balance, lastPaymentDate, lastPaymentValue, lastRideDate, lastRideCost, lastValidatorId, subwayCount, groundCount);
            printf("%s\n", url);
            http_get_response_t *res = http_get(url);
            http_get_free(res);
            break;
        case EVENT_TAG_REMOVED:
            break;
        default:
            return -1;
    }
    return 0;
}

static size_t http_get_cb(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    http_get_response_t *res = userp;

    res->data = realloc(res->data, res->size + realsize + 1);
    if (NULL == res->data) {
        fprintf(stderr, "not enough memory!");
        return 0;
    }

    memcpy(&(res->data[res->size]), contents, realsize);
    res->size += realsize;
    res->data[res->size] = 0;

    return realsize;
}

http_get_response_t *http_get(const char *url) {
    CURL *req = curl_easy_init();

    static http_get_response_t res;
    res.data = malloc(1);
    res.size = 0;

    curl_easy_setopt(req, CURLOPT_URL, url);
    curl_easy_setopt(req, CURLOPT_HTTPGET, 1);
    curl_easy_setopt(req, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(req, CURLOPT_WRITEFUNCTION, http_get_cb);
    curl_easy_setopt(req, CURLOPT_WRITEDATA, (void *)&res);

    int c = curl_easy_perform(req);

    curl_easy_getinfo(req, CURLINFO_RESPONSE_CODE, &res.status);
    res.ok = (200 == res.status && CURLE_ABORTED_BY_CALLBACK != c) ? 1 : 0;
    curl_easy_cleanup(req);

    return &res;
}


void http_get_free(http_get_response_t *res) {
    if (NULL == res) return;
    free(res->data);
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