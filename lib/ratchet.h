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

#include <stdbool.h>

#include "message-keystore.h"

#ifndef RATCHET_H
#define RATCHET_H

//struct that represents the state of a conversation
typedef struct ratchet_state {
	unsigned char *root_key; //RK
	unsigned char *purported_root_key; //RKp
	//chain keys
	unsigned char *send_chain_key; //CKs
	unsigned char *receive_chain_key; //CKr
	unsigned char *purported_receive_chain_key; //CKp
	//identity keys
	unsigned char *our_public_identity; //DHIs
	unsigned char *their_public_identity; //DHIr
	//ephemeral keys (ratchet keys)
	unsigned char *our_private_ephemeral; //DHRs
	unsigned char *our_public_ephemeral; //DHRs
	unsigned char *their_public_ephemeral; //DHRr
	unsigned char *their_purported_public_ephemeral; //DHp
	//message numbers
	unsigned int send_message_number; //Ns
	unsigned int receive_message_number; //Nr
	unsigned int purported_message_number; //Np
	unsigned int previous_message_number; //PNs (number of messages sent in previous chain)
	unsigned int purported_previous_message_number; //PNp
	//ratchet flag
	bool ratchet_flag;
	bool am_i_alice;
	bool received_valid; //is false until the validity of a received message has been verified until the validity of a received message has been verified,
	                     //this is necessary to be able to split key derivation from message
	                     //decryption
	//list of previous message keys
	message_keystore skipped_message_keys; //skipped_MK (list containing message keys for messages that weren't received)
	message_keystore purported_message_keys; //this represents the staging area specified in the axolotl ratchet
} ratchet_state;

/*
 * Start a new ratchet chain. This derives an initial root key and returns a new ratchet state.
 *
 * All the keys will be copied so you can free the buffers afterwards. (private identity get's
 * immediately deleted after deriving the initial root key though!)
 *
 * The return value is a valid ratchet state or NULL if an error occured.
 */
ratchet_state* ratchet_create(
		const unsigned char * const our_private_identity,
		const unsigned char * const our_public_identity,
		const unsigned char * const their_public_identity,
		const unsigned char * const our_private_ephemeral,
		const unsigned char * const our_public_ephemeral,
		const unsigned char * const their_public_ephemeral,
		bool am_i_alice);

/*
 * Create message key to encrypt the next send message with.
 */
int ratchet_next_send_key(
		unsigned char * const next_message_key, //crypto_secretbox_KEYBYTES
		bool *new_ephemeral, //was a new ephemeral created? If yes the caller has to get it
		                     //from the ratchet_state struct
		ratchet_state *state);

/*
 * End the ratchet chain and free the memory.
 */
void ratchet_destroy(ratchet_state *state);
#endif
