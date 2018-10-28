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

static char * _tag_uid = NULL;

void
nem_plantain_init( nfcconf_context *module_context, nfcconf_block* module_block ) {
    set_debug_level ( 1 );
}

void
tag_get_uid(nfc_device* nfc_device, nfc_target* tag, char **dest) {
    debug_print_tag(tag);

    /// @TODO We don't need to reselect tag to get his UID: nfc_target contains this data.
    // Poll for a ISO14443A (MIFARE) tag
    if ( nfc_initiator_select_passive_target ( nfc_device, tag->nm, tag->nti.nai.abtUid, tag->nti.nai.szUidLen, tag ) ) {
        *dest = malloc(tag->nti.nai.szUidLen*sizeof(char)*2+1);
        size_t szPos;
        char *pcUid = *dest;
        for (szPos=0; szPos < tag->nti.nai.szUidLen; szPos++) {
            sprintf(pcUid, "%02x",tag->nti.nai.abtUid[szPos]);
            pcUid += 2;
        }
        pcUid[0]='\0';
        DBG( "ISO14443A tag found: UID=0x%s", *dest );
        nfc_initiator_deselect_target ( nfc_device );
    } else {
        *dest = NULL;
        DBG("%s", "ISO14443A (MIFARE) tag not found" );
        return;
    }
}

int
nem_plantain_event_handler(nfc_device* nfc_device, nfc_target* tag, const nem_event_t event) {
    switch (event) {
        case EVENT_TAG_INSERTED:
            if ( _tag_uid != NULL ) {
                free(_tag_uid);
            }
            tag_get_uid(nfc_device, tag, &_tag_uid);
            ERR("%s", "WOW")
            print_nfc_target(tag, false);
            break;
        case EVENT_TAG_REMOVED:
            break;
        default:
            return -1;
    }

    if ( _tag_uid == NULL ) {
        ERR( "%s", "Unable to read tag UID... This should not happend !" );
        exit ( EXIT_FAILURE );
    }
    return 0;
}

