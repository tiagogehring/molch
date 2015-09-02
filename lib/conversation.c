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
#include <sodium.h>
#include <string.h>
#include <assert.h>

#include "conversation.h"
#include "header.h"
#include "packet.h"

/*
 * Start new conversation.
 *
 * returns NULL in case of failures.
 */
ratchet_state* conversation_create(
		const unsigned char * const our_private_identity,
		const unsigned char * const our_public_identity,
		const unsigned char * const their_public_identity,
		const unsigned char * const our_private_ephemeral,
		const unsigned char * const our_public_ephemeral,
		const unsigned char * const their_public_ephemeral) {
	//decide if alice or bob by comparing their and our public key
	bool am_i_alice;
	//TODO Move this comparison to ratchet_create?
	int comparison = memcmp(our_public_identity, their_public_identity, crypto_box_PUBLICKEYBYTES);
	if (comparison > 0) {
		am_i_alice = true;
	} else if (comparison < 0) {
		am_i_alice = false;
	} else {
		return NULL;
	}

	return ratchet_create(
			our_private_identity,
			our_public_identity,
			their_public_identity,
			our_private_ephemeral,
			our_public_ephemeral,
			their_public_ephemeral,
			am_i_alice);
}

/*
 * Send a message.
 *
 * FIXME: Better handle buffer lengths
 * The buffer for the packet (ciphertext) has to be 362 Bytes + message_length
 */
int conversation_send_message(
		unsigned char * ciphertext,
		size_t * const ciphertext_length,
		const unsigned char * const message,
		const size_t message_length,
		ratchet_state * const state) {
	//get send keys
	unsigned char message_key[crypto_secretbox_KEYBYTES];
	unsigned char header_key[crypto_aead_chacha20poly1305_KEYBYTES];
	int status = ratchet_next_send_keys(
			message_key,
			header_key,
			state);
	if (status != 0) {
		sodium_memzero(message_key, sizeof(message_key));
		sodium_memzero(header_key, sizeof(header_key));
		return status;
	}

	//create the header
	//TODO: move this to ratchet.h?
	uint32_t message_number = state->send_message_number;
	uint32_t previous_message_number = state->previous_message_number;
	unsigned char header[crypto_box_PUBLICKEYBYTES + 8];
	header_construct(
			header,
			state->our_public_ephemeral,
			message_number,
			previous_message_number);

	//create the ciphertext
	status = packet_encrypt(
			ciphertext,
			ciphertext_length,
			0, //TODO: Specify packet types somewhere.
			0, //current protocol version
			0, //highest supported protocol version
			header,
			sizeof(header),
			header_key,
			message,
			message_length,
			message_key);
	if (status != 0) {
		sodium_memzero(message_key, sizeof(message_key));
		sodium_memzero(header_key, sizeof(header_key));
		sodium_memzero(header, sizeof(header));
		return status;
	}

	sodium_memzero(message_key, sizeof(message_key));
	sodium_memzero(header_key, sizeof(header_key));
	sodium_memzero(header, sizeof(header));
	return 0;
}

/*
 * Receive a message.
 *
 * FIXME: Better handle buffer lengths
 * TODO: Handle skipped messages
 * The buffer for the message has to be ciphertext_length - 100
 */
int conversation_receive_message(
		unsigned char * const message,
		size_t * const message_length,
		const unsigned char * const ciphertext,
		const size_t ciphertext_length,
		ratchet_state * const state) {
	//possible receive header keys
    const unsigned char *current_header_key;
    const unsigned char *next_header_key;
    ratchet_get_receive_header_keys(
            &current_header_key,
            &next_header_key,
			state);

	//try to decrypt the header
	unsigned char header[255];
	size_t header_length;
	unsigned char message_nonce[crypto_secretbox_NONCEBYTES];
	ratchet_header_decryptability decryptable = NOT_TRIED;
	if (packet_decrypt_header( //test current header key
				ciphertext,
				ciphertext_length,
				header,
				&header_length,
				message_nonce,
				current_header_key) == 0) {
		decryptable = CURRENT_DECRYPTABLE;
	} else if (packet_decrypt_header( //test next header key
				ciphertext,
				ciphertext_length,
				header,
				&header_length,
				message_nonce,
				next_header_key) == 0) {
		decryptable = NEXT_DECRYPTABLE;
	} else {
		decryptable = UNDECRYPTABLE;
	}

	//check the header length
	if (header_length != crypto_box_PUBLICKEYBYTES + 8) {
		sodium_memzero(header, sizeof(header));
		header_length = 0;
		sodium_memzero(message_nonce, sizeof(message_nonce));
		return -10;
	}

	//set decryptability
	int status = ratchet_set_header_decryptability(
			decryptable,
			state);
	if (status != 0) {
		sodium_memzero(header, sizeof(header));
		header_length = 0;
		sodium_memzero(message_nonce, sizeof(message_nonce));
	}

	//extract information from the header
	unsigned char their_public_ephemeral[crypto_box_PUBLICKEYBYTES];
	uint32_t message_number;
	uint32_t previous_message_number;
	header_extract(
			header,
			their_public_ephemeral,
			&message_number,
			&previous_message_number);

	//get the message key
	unsigned char message_key[crypto_secretbox_KEYBYTES];
	status = ratchet_receive(
			message_key,
			their_public_ephemeral,
			message_number,
			previous_message_number,
			state);
	if (status != 0) {
		sodium_memzero(header, sizeof(header));
		header_length = 0;
		message_number = 0;
		previous_message_number = 0;
		sodium_memzero(message_nonce, sizeof(message_nonce));
		sodium_memzero(message_key, sizeof(message_key));
		sodium_memzero(their_public_ephemeral, sizeof(their_public_ephemeral));
		return -10;
	}
	sodium_memzero(header, sizeof(header));
	header_length = 0;
	message_number = 0;
	previous_message_number = 0;
	sodium_memzero(their_public_ephemeral, sizeof(their_public_ephemeral));

	//finally decrypt the message
	unsigned char plaintext[ciphertext_length];
	size_t plaintext_length;
	status = packet_decrypt_message(
			ciphertext,
			ciphertext_length,
			plaintext,
			&plaintext_length,
			message_nonce,
			message_key);
	sodium_memzero(message_nonce, sizeof(message_nonce));
	sodium_memzero(message_key, sizeof(message_key));
	if (status != 0) {
		sodium_memzero(plaintext, sizeof(plaintext));
		return status;
	}

	//copy the message
	*message_length = plaintext_length;
	memcpy(message, plaintext, plaintext_length);
	sodium_memzero(plaintext, sizeof(plaintext));
	return 0;
}

/*
 * End and destroy a running conversation.
 */
void conversation_destroy(ratchet_state *state) {
	ratchet_destroy(state);
}
