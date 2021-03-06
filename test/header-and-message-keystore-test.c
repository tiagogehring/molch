/* Molch, an implementation of the axolotl ratchet based on libsodium
 *  Copyright (C) 2015  Max Bruckner (FSMaxB)
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>
#include <assert.h>

#include "../lib/header-and-message-keystore.h"
#include "utils.h"
#include "common.h"


int main(void) {
	sodium_init();

	//buffer for message keys
	buffer_t *header_key = buffer_create(crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_t *message_key = buffer_create(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);

	//initialise message keystore
	header_and_message_keystore keystore = header_and_message_keystore_init();
	assert(keystore.length == 0);
	assert(keystore.head == NULL);
	assert(keystore.tail == NULL);

	int status;

	//add keys to the keystore
	unsigned int i;
	for (i = 0; i < 6; i++) {
		//create new keys
		status = buffer_fill_random(header_key, header_key->buffer_length);
		if (status != 0) {
			fprintf(stderr, "ERROR: Failed to create header key. (%i)\n", status);
			header_and_message_keystore_clear(&keystore);
			buffer_clear(header_key);
			buffer_clear(message_key);
			return status;
		}
		status = buffer_fill_random(message_key, message_key->buffer_length);
		if (status != 0) {
			fprintf(stderr, "ERROR: Failed to create header key. (%i)\n", status);
			header_and_message_keystore_clear(&keystore);
			buffer_clear(header_key);
			buffer_clear(message_key);
			return status;
		}

		//print the new header key
		printf("New Header Key No. %u:\n", i);
		print_hex(header_key);
		putchar('\n');

		//print the new message key
		printf("New message key No. %u:\n", i);
		print_hex(message_key);
		putchar('\n');

		//add keys to the keystore
		status = header_and_message_keystore_add(&keystore, message_key, header_key);
		buffer_clear(message_key);
		buffer_clear(header_key);
		if (status != 0) {
			fprintf(stderr, "ERROR: Failed to add key to keystore. (%i)\n", status);
			header_and_message_keystore_clear(&keystore);
			return EXIT_FAILURE;
		}

		print_header_and_message_keystore(&keystore);

		assert(keystore.length == (i + 1));
	}

	//remove key from the head
	printf("Remove head!\n");
	header_and_message_keystore_remove(&keystore, keystore.head);
	assert(keystore.length == (i - 1));
	print_header_and_message_keystore(&keystore);

	//remove key from the tail
	printf("Remove Tail:\n");
	header_and_message_keystore_remove(&keystore, keystore.tail);
	assert(keystore.length == (i - 2));
	print_header_and_message_keystore(&keystore);

	//remove from inside
	printf("Remove from inside:\n");
	header_and_message_keystore_remove(&keystore, keystore.head->next);
	assert(keystore.length == (i - 3));
	print_header_and_message_keystore(&keystore);

	//clear the keystore
	printf("Clear the keystore:\n");
	header_and_message_keystore_clear(&keystore);
	assert(keystore.length == 0);
	assert(keystore.head == NULL);
	assert(keystore.tail == NULL);
	print_header_and_message_keystore(&keystore);
	return EXIT_SUCCESS;
}
