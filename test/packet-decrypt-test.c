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

#include "../lib/packet.h"
#include "utils.h"
#include "packet-test-lib.h"

int main(void) {
	sodium_init();

	//generate keys and message
	buffer_t *header_key = buffer_create(crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_t *message_key = buffer_create(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	buffer_t *message = buffer_create_from_string("Hello world!\n");
	buffer_t *header = buffer_create(4, 4);
	header->content[0] = 0x01;
	header->content[1] = 0x02;
	header->content[2] = 0x03;
	header->content[3] = 0x04;
	buffer_t *packet = buffer_create(3 + crypto_aead_chacha20poly1305_NPUBBYTES + crypto_aead_chacha20poly1305_ABYTES + crypto_secretbox_NONCEBYTES + message->content_length + header->content_length + crypto_secretbox_MACBYTES + 255, 3 + crypto_aead_chacha20poly1305_NPUBBYTES + crypto_aead_chacha20poly1305_ABYTES + crypto_secretbox_NONCEBYTES + message->content_length + header->content_length + crypto_secretbox_MACBYTES + 255);
	const unsigned char packet_type = 1;
	printf("Packet type: %02x\n", packet_type);
	const unsigned char current_protocol_version = 2;
	printf("Current protocol version: %02x\n", current_protocol_version);
	const unsigned char highest_supported_protocol_version = 3;
	printf("Highest supported protocol version: %02x\n", highest_supported_protocol_version);
	putchar('\n');
	int status = create_and_print_message(
			packet,
			packet_type,
			current_protocol_version,
			highest_supported_protocol_version,
			message,
			message_key,
			header,
			header_key);
	if (status != 0) {
		buffer_clear(header_key);
		buffer_clear(header);
		buffer_clear(message_key);
		buffer_clear(message);
		return status;
	}

	//now decrypt the packet
	buffer_t *decrypted_header = buffer_create(255, 255);
	buffer_t *decrypted_message = buffer_create(packet->content_length, packet->content_length);
	unsigned char authenticated_packet_type;
	unsigned char authenticated_current_protocol_version;
	unsigned char authenticated_highest_supported_protocol_version;
	status = packet_decrypt(
			packet,
			&authenticated_packet_type,
			&authenticated_current_protocol_version,
			&authenticated_highest_supported_protocol_version,
			decrypted_header,
			header_key,
			decrypted_message,
			message_key);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to decrypt the packet. (%i)\n", status);
		buffer_clear(header);
		buffer_clear(decrypted_header);
		buffer_clear(header_key);
		buffer_clear(message_key);
		buffer_clear(message);
		buffer_clear(decrypted_message);
		return status;
	}

	if ((packet_type != authenticated_packet_type)
		|| (current_protocol_version != authenticated_current_protocol_version)
		|| (highest_supported_protocol_version != authenticated_highest_supported_protocol_version)) {
		fprintf(stderr, "ERROR: Failed to retrieve metadata!\n");
		buffer_clear(header);
		buffer_clear(decrypted_header);
		buffer_clear(header_key);
		buffer_clear(message_key);
		buffer_clear(message);
		buffer_clear(decrypted_message);
		return EXIT_FAILURE;
	}


	if (decrypted_header->content_length != header->content_length) {
		fprintf(stderr, "ERROR: Decrypted header isn't of the same length!\n");
		buffer_clear(header);
		buffer_clear(decrypted_header);
		buffer_clear(header_key);
		buffer_clear(message_key);
		buffer_clear(message);
		buffer_clear(decrypted_message);
		return EXIT_SUCCESS;
	}
	printf("Decrypted header has the same length.\n");

	//compare headers
	if (buffer_compare(header, decrypted_header) != 0) {
		fprintf(stderr, "ERROR: Decrypted header doesn't match!\n");
		buffer_clear(header);
		buffer_clear(decrypted_header);
		buffer_clear(header_key);
		buffer_clear(message_key);
		buffer_clear(message);
		buffer_clear(decrypted_message);
		return EXIT_FAILURE;
	}
	printf("Decrypted header matches.\n\n");

	if (decrypted_message->content_length != message->content_length) {
		fprintf(stderr, "ERROR: Decrypted message isn't of the same length!\n");
		buffer_clear(header);
		buffer_clear(decrypted_header);
		buffer_clear(header_key);
		buffer_clear(message_key);
		buffer_clear(message);
		buffer_clear(decrypted_message);
		return EXIT_FAILURE;
	}
	printf("Decrypted message has the same length.\n");

	//compare messages
	if (buffer_compare(message, decrypted_message) != 0) {
		fprintf(stderr, "ERROR: Decrypted message doesn't match!\n");
		buffer_clear(header);
		buffer_clear(decrypted_header);
		buffer_clear(header_key);
		buffer_clear(message_key);
		buffer_clear(message);
		buffer_clear(decrypted_message);
		return EXIT_FAILURE;
	}
	printf("Decrypted message matches.\n");

	buffer_clear(header);
	buffer_clear(decrypted_header);
	buffer_clear(header_key);
	buffer_clear(message_key);
	buffer_clear(message);
	buffer_clear(decrypted_message);

	return EXIT_SUCCESS;
}
