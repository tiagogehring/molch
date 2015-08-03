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

#include "../lib/ratchet.h"
#include "../lib/utils.h"

int main(void) {
	sodium_init();

	int status;

	//create Alice's identity keypair
	printf("Creating Alice's identity keypair ...\n");
	unsigned char alice_private_identity[crypto_box_SECRETKEYBYTES];
	unsigned char alice_public_identity[crypto_box_PUBLICKEYBYTES];
	status = crypto_box_keypair(alice_public_identity, alice_private_identity);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate Alice's identity keypair! (%i)\n", status);
		sodium_memzero(alice_private_identity, crypto_box_SECRETKEYBYTES);
		return status;
	}

	//create Alice's ephemeral keypair
	printf("Creating Alice's ephemeral keypair ...\n");
	unsigned char alice_private_ephemeral[crypto_box_SECRETKEYBYTES];
	unsigned char alice_public_ephemeral[crypto_box_PUBLICKEYBYTES];
	status = crypto_box_keypair(alice_public_ephemeral, alice_private_ephemeral);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate Alice's ephemeral keypair! (%i)\n", status);
		sodium_memzero(alice_private_identity, crypto_box_SECRETKEYBYTES);
		sodium_memzero(alice_private_ephemeral, crypto_box_SECRETKEYBYTES);
		return status;
	}

	//create Bob's identity keypair
	printf("Creating Bob's identity keypair ...\n");
	unsigned char bob_private_identity[crypto_box_SECRETKEYBYTES];
	unsigned char bob_public_identity[crypto_box_PUBLICKEYBYTES];
	status = crypto_box_keypair(bob_public_identity, bob_private_identity);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate Bob's identity keypair! (%i)\n", status);
		sodium_memzero(alice_private_identity, crypto_box_SECRETKEYBYTES);
		sodium_memzero(alice_private_ephemeral, crypto_box_SECRETKEYBYTES);
		sodium_memzero(bob_private_identity, crypto_box_SECRETKEYBYTES);
		return status;
	}

	//create Bob's ephemeral keypair
	printf("Creating Bob's ephemeral keypair ...\n");
	unsigned char bob_private_ephemeral[crypto_box_SECRETKEYBYTES];
	unsigned char bob_public_ephemeral[crypto_box_PUBLICKEYBYTES];
	status = crypto_box_keypair(bob_public_ephemeral, bob_private_ephemeral);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate Bob's ephemeral keypair! (%i)\n", status);
		sodium_memzero(alice_private_identity, crypto_box_SECRETKEYBYTES);
		sodium_memzero(alice_private_ephemeral, crypto_box_SECRETKEYBYTES);
		sodium_memzero(bob_private_identity, crypto_box_SECRETKEYBYTES);
		sodium_memzero(bob_private_ephemeral, crypto_box_SECRETKEYBYTES);
		return status;
	}

	//start new ratchet for alice
	printf("Creating new ratchet for Alice ...\n");
	ratchet_state *alice_state = ratchet_create(
			alice_private_identity,
			alice_public_identity,
			bob_public_identity,
			alice_private_ephemeral,
			alice_public_ephemeral,
			bob_private_ephemeral,
			true);
	if (alice_state == NULL) {
		sodium_memzero(alice_private_identity, crypto_box_SECRETKEYBYTES);
		sodium_memzero(alice_private_ephemeral, crypto_box_SECRETKEYBYTES);
		sodium_memzero(bob_private_identity, crypto_box_SECRETKEYBYTES);
		sodium_memzero(bob_private_ephemeral, crypto_box_SECRETKEYBYTES);
		return EXIT_FAILURE;
	}

	//destroy the ratchet again
	printf("Destroying Alice's ratchet ...\n");
	ratchet_destroy(alice_state);

	//TODO test everything else

	sodium_memzero(alice_private_identity, crypto_box_SECRETKEYBYTES);
	sodium_memzero(alice_private_ephemeral, crypto_box_SECRETKEYBYTES);
	sodium_memzero(bob_private_identity, crypto_box_SECRETKEYBYTES);
	sodium_memzero(bob_private_ephemeral, crypto_box_SECRETKEYBYTES);

	return EXIT_SUCCESS;
}