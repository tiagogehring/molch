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
#include <string.h>
#include <assert.h>

#include "../lib/conversation.h"
#include "utils.h"
#include "common.h"

int main(void) {
	sodium_init();

	int status;

	//creating charlie's identity keypair
	unsigned char charlie_private_identity[crypto_box_SECRETKEYBYTES];
	unsigned char charlie_public_identity[crypto_box_PUBLICKEYBYTES];
	status = generate_and_print_keypair(
			charlie_public_identity,
			charlie_private_identity,
			"charlie",
			"identity");
	if (status != 0) {
		sodium_memzero(charlie_private_identity, sizeof(charlie_private_identity));
		return status;
	}

	//creating charlie's ephemeral keypair
	unsigned char charlie_private_ephemeral[crypto_box_SECRETKEYBYTES];
	unsigned char charlie_public_ephemeral[crypto_box_PUBLICKEYBYTES];
	status = generate_and_print_keypair(
			charlie_public_ephemeral,
			charlie_private_ephemeral,
			"charlie",
			"ephemeral");
	if (status != 0) {
		sodium_memzero(charlie_private_identity, sizeof(charlie_private_identity));
		sodium_memzero(charlie_private_ephemeral, sizeof(charlie_private_ephemeral));
		return status;
	}

	//creating dora's identity keypair
	unsigned char dora_private_identity[crypto_box_SECRETKEYBYTES];
	unsigned char dora_public_identity[crypto_box_PUBLICKEYBYTES];
	status = generate_and_print_keypair(
			dora_public_identity,
			dora_private_identity,
			"dora",
			"identity");
	if (status != 0) {
		sodium_memzero(charlie_private_identity, sizeof(charlie_private_identity));
		sodium_memzero(charlie_private_ephemeral, sizeof(charlie_private_ephemeral));
		sodium_memzero(dora_private_identity, sizeof(dora_private_identity));
		return status;
	}

	//creating dora's ephemeral keypair
	unsigned char dora_private_ephemeral[crypto_box_SECRETKEYBYTES];
	unsigned char dora_public_ephemeral[crypto_box_PUBLICKEYBYTES];
	status = generate_and_print_keypair(
			dora_public_ephemeral,
			dora_private_ephemeral,
			"dora",
			"ephemeral");
	if (status != 0) {
		sodium_memzero(charlie_private_identity, sizeof(charlie_private_identity));
		sodium_memzero(charlie_private_ephemeral, sizeof(charlie_private_ephemeral));
		sodium_memzero(dora_private_identity, sizeof(dora_private_identity));
		sodium_memzero(dora_private_ephemeral, sizeof(dora_private_ephemeral));
		return status;
	}

	//create charlie's conversation
	ratchet_state *charlie_conversation = conversation_create(
			charlie_private_identity,
			charlie_public_identity,
			dora_public_identity,
			charlie_private_ephemeral,
			charlie_public_ephemeral,
			dora_public_ephemeral);
	sodium_memzero(charlie_private_identity, sizeof(charlie_private_identity));
	sodium_memzero(charlie_private_ephemeral, sizeof(charlie_private_ephemeral));
	if (charlie_conversation == NULL) {
		fprintf(stderr, "ERROR: Failed to create Charlie's conversation.\n");
		sodium_memzero(dora_private_identity, sizeof(dora_private_identity));
		sodium_memzero(dora_private_ephemeral, sizeof(dora_private_ephemeral));
		return EXIT_FAILURE;
	}

	//create Dora's conversation
	ratchet_state *dora_conversation = conversation_create(
			dora_private_identity,
			dora_public_identity,
			charlie_public_identity,
			dora_private_ephemeral,
			dora_public_ephemeral,
			charlie_public_ephemeral);
	sodium_memzero(dora_private_identity, sizeof(dora_private_identity));
	sodium_memzero(dora_private_ephemeral, sizeof(dora_private_ephemeral));
	if (dora_conversation == NULL) {
		fprintf(stderr, "ERROR: Failed to create Dora's conversation.\n");
		return EXIT_FAILURE;
	}

	//--------------------------------------------------------------------------
	//charlie writes two messages to dora
	//message 1
	unsigned char charlie_send_message1[] = "Hi Dora.";
	unsigned char charlie_send_ciphertext1[362 + sizeof(charlie_send_message1)];
	size_t charlie_send_ciphertext1_length;
	status = conversation_send_message(
			charlie_send_ciphertext1,
			&charlie_send_ciphertext1_length,
			charlie_send_message1,
			sizeof(charlie_send_message1),
			charlie_conversation);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to encrypt Charlie's first message. (%i)\n", status);
		sodium_memzero(charlie_send_message1, sizeof(charlie_send_message1));
		return status;
	}

	printf("Charlie's first message (%zi Bytes):\n%s\n", sizeof(charlie_send_message1), charlie_send_message1);
	printf("Ciphertext of Charlie's first message (%zi):\n", charlie_send_ciphertext1_length);
	print_hex(charlie_send_ciphertext1, charlie_send_ciphertext1_length, 30);
	putchar('\n');

	//message 2
	unsigned char charlie_send_message2[] = "How are you doing?";
	unsigned char charlie_send_ciphertext2[362 + sizeof(charlie_send_message2)];
	size_t charlie_send_ciphertext2_length;
	status = conversation_send_message(
			charlie_send_ciphertext2,
			&charlie_send_ciphertext2_length,
			charlie_send_message2,
			sizeof(charlie_send_message2),
			charlie_conversation);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to encrypt Charlie's second message. (%i)\n", status);
		sodium_memzero(charlie_send_message1, sizeof(charlie_send_message1));
		sodium_memzero(charlie_send_message2, sizeof(charlie_send_message2));
		return status;
	}

	printf("Charlie's second message (%zi Bytes):\n%s\n", sizeof(charlie_send_message2), charlie_send_message2);
	printf("Ciphertext of Charlie's first message (%zi):\n", charlie_send_ciphertext2_length);
	print_hex(charlie_send_ciphertext2, charlie_send_ciphertext2_length, 30);
	putchar('\n');

	//--------------------------------------------------------------------------
	//dora receives the two messages
	//message 1
	unsigned char dora_receive_message1[charlie_send_ciphertext1_length - 100];
	size_t dora_receive_message1_length;
	status = conversation_receive_message(
			dora_receive_message1,
			&dora_receive_message1_length,
			charlie_send_ciphertext1,
			charlie_send_ciphertext1_length,
			dora_conversation);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to decrypt Charlie's first message. (%i)\n", status);
		sodium_memzero(dora_receive_message1, sizeof(dora_receive_message1));
		sodium_memzero(charlie_send_message1, sizeof(charlie_send_message1));
		sodium_memzero(charlie_send_message2, sizeof(charlie_send_message2));
		return status;
	}
	printf("First decrypted message (%zi):\n%s\n", dora_receive_message1_length, dora_receive_message1);

	//compare message 1
	if (sodium_memcmp(charlie_send_message1, dora_receive_message1, sizeof(charlie_send_message1)) != 0) {
		fprintf(stderr, "ERROR: First message didn't match.\n");
		sodium_memzero(dora_receive_message1, sizeof(dora_receive_message1));
		sodium_memzero(charlie_send_message1, sizeof(charlie_send_message1));
		sodium_memzero(charlie_send_message2, sizeof(charlie_send_message2));
		return EXIT_FAILURE;
	}
	printf("First message matches.\n");
	sodium_memzero(dora_receive_message1, sizeof(dora_receive_message1));
	sodium_memzero(charlie_send_message1, sizeof(charlie_send_message1));

	//message 2
	unsigned char dora_receive_message2[charlie_send_ciphertext2_length - 100];
	size_t dora_receive_message2_length;
	status = conversation_receive_message(
			dora_receive_message2,
			&dora_receive_message2_length,
			charlie_send_ciphertext2,
			charlie_send_ciphertext2_length,
			dora_conversation);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to decrypt Charlie's second message. (%i)\n", status);
		sodium_memzero(dora_receive_message2, sizeof(dora_receive_message2));
		sodium_memzero(charlie_send_message2, sizeof(charlie_send_message2));
		return status;
	}

	//compare message 1
	if (sodium_memcmp(charlie_send_message2, dora_receive_message2, sizeof(charlie_send_message2)) != 0) {
		fprintf(stderr, "ERROR: First message didn't match.\n");
		sodium_memzero(dora_receive_message2, sizeof(dora_receive_message2));
		sodium_memzero(charlie_send_message2, sizeof(charlie_send_message2));
		return EXIT_FAILURE;
	}
	printf("First message matches.\n");
	sodium_memzero(dora_receive_message2, sizeof(dora_receive_message2));
	sodium_memzero(charlie_send_message2, sizeof(charlie_send_message2));

	return EXIT_SUCCESS;
}
