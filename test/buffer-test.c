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

#include "../lib/buffer.h"
#include "utils.h"

int main(void) {
	sodium_init();

	//test comparison function
	buffer_t *string1 = buffer_create_from_string("1234");
	buffer_t *string2 = buffer_create_from_string("1234");
	buffer_t *string3 = buffer_create_from_string("2234");
	buffer_t *string4 = buffer_create_from_string("12345");

	if ((buffer_compare(string1, string2) != 0)
			|| (buffer_compare(string1, string3) != -1)
			|| (buffer_compare(string1, string4) != -1)) {
		fprintf(stderr, "ERROR: buffer_compare doesn't work as expected\n");
		buffer_clear(string1);
		buffer_clear(string2);
		buffer_clear(string3);
		buffer_clear(string4);

		return EXIT_FAILURE;
	}

	if ((buffer_compare_partial(string1, 0, string4, 0, 4) != 0)
			|| (buffer_compare_partial(string1, 2, string3, 2, 2) != 0)) {
		fprintf(stderr, "ERROR: buffer_compare_partial doesn't work as expected\n");
		buffer_clear(string1);
		buffer_clear(string2);
		buffer_clear(string3);
		buffer_clear(string4);
		return EXIT_FAILURE;
	}
	buffer_clear(string1);
	buffer_clear(string2);
	buffer_clear(string3);
	buffer_clear(string4);
	printf("Successfully tested buffer comparison ...\n");

	//test heap allocated buffers
	buffer_t *heap_buffer = buffer_create_on_heap(10, 0);
	buffer_destroy_from_heap(heap_buffer);

	//create a new buffer
	buffer_t *buffer1 = buffer_create(14, 10);
	unsigned char buffer1_content[10];
	randombytes_buf(buffer1_content, sizeof(buffer1_content));
	memcpy(buffer1->content, buffer1_content, sizeof(buffer1_content));
	printf("Here\n");

	printf("Random buffer (%zi Bytes):\n", buffer1->content_length);
	print_hex(buffer1);
	putchar('\n');

	//make second buffer (from pointer)
	buffer_t *buffer2 = buffer_init_with_pointer(alloca(sizeof(buffer_t)), malloc(5), 5, 4);
	buffer2->content[0] = 0xde;
	buffer2->content[1] = 0xad;
	buffer2->content[2] = 0xbe;
	buffer2->content[3] = 0xef;

	printf("Second buffer (%zi Bytes):\n", buffer2->content_length);
	print_hex(buffer2);
	putchar('\n');

	//concatenate buffers
	printf("Concatenating buffers!\n");
	int status = buffer_concat(buffer1, buffer2);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to concatenate both buffers. (%i)\n", status);
		buffer_clear(buffer1);
		buffer_clear(buffer2);
		free(buffer2->content);
		return status;
	}
	assert(buffer1->content_length == 14);
	print_hex(buffer1);
	putchar('\n');

	//check if the buffers were successfully concatenated
	if ((sodium_memcmp(buffer1->content, buffer1_content, sizeof(buffer1_content)) != 0)
			|| (sodium_memcmp(buffer1->content + sizeof(buffer1_content), buffer2->content, buffer2->content_length) !=0)) {
		fprintf(stderr, "ERROR: Failed to concatenate buffers.\n");
		buffer_clear(buffer1);
		buffer_clear(buffer2);
		free(buffer2->content);
		return EXIT_FAILURE;
	}
	printf("Buffers successfully concatenated.\n");

	//concatenate buffers that are to long
	status = buffer_concat(buffer1, buffer2);
	if (status == 0) {
		fprintf(stderr, "ERROR: Concatenated buffers that go over the bounds.\n");
		buffer_clear(buffer1);
		buffer_clear(buffer2);
		free(buffer2->content);
		return EXIT_FAILURE;
	}
	printf("Detected out of bounds buffer concatenation.\n");

	//test empty buffers
	buffer_t *empty = buffer_create(0, 0);
	status = buffer_concat(buffer1, empty);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to concatenate empty buffer to buffer.\n");
		buffer_clear(buffer1);
		buffer_clear(buffer2);
		free(buffer2->content);
		return status;
	}
	buffer_t *empty2 = buffer_create(0, 0);
	status = buffer_clone(empty2, empty);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to clone empty buffer.\n");
		buffer_clear(buffer1);
		buffer_clear(buffer2);
		free(buffer2->content);
		return status;
	}
	buffer_clear(empty);
	buffer_clear(empty2);
	//TODO more tests with empty buffers
	//FIXME Yeah this needs to be done ASAP!!!!!!!!!!!!!

	//TODO check readonly
	//TODO check content lengths
	//TODO test buffer clone functions

	//copy buffer
	buffer_t *buffer3 = buffer_create(5,0);
	status = buffer_copy(buffer3, 0, buffer2, 0, buffer2->content_length);
	if ((status != 0) || (buffer_compare(buffer2, buffer3) != 0)) {
		fprintf(stderr, "ERROR: Failed to copy buffer. (%i)\n", status);
		buffer_clear(buffer1);
		buffer_clear(buffer2);
		free(buffer2->content);
		return EXIT_FAILURE;
	}
	printf("Buffer successfully copied.\n");

	status = buffer_copy(buffer3, buffer2->content_length, buffer2, 0, buffer2->content_length);
	if (status == 0) {
		fprintf(stderr, "ERROR: Copied buffer that out of bounds.\n");
		buffer_clear(buffer1);
		buffer_clear(buffer2);
		free(buffer2->content);
		return EXIT_FAILURE;
	}
	printf("Detected out of bounds buffer copying.\n");

	status = buffer_copy(buffer3, 1, buffer2, 0, buffer2->content_length);
	if ((status != 0) || (buffer3->content[0] != buffer2->content[0]) || (sodium_memcmp(buffer2->content, buffer3->content + 1, buffer2->content_length) != 0)) {
		fprintf(stderr, "ERROR: Failed to copy buffer. (%i)\n", status);
		buffer_clear(buffer1);
		buffer_clear(buffer2);
		free(buffer2);
		return EXIT_FAILURE;
	}
	printf("Successfully copied buffer.\n");

	//copy to a raw array
	unsigned char raw_array[4];
	status = buffer_copy_to_raw(
			raw_array, //destination
			0, //destination offset
			buffer1, //source
			1, //source offset
			4); //length
	if ((status != 0) || (sodium_memcmp(raw_array, buffer1->content + 1, 4) != 0)) {
		fprintf(stderr, "ERROR: Failed to copy buffer to raw array. (%i)\n", status);
		buffer_clear(buffer1);
		buffer_clear(buffer2);
		free(buffer2->content);
		return EXIT_FAILURE;
	}
	printf("Successfully copied buffer to raw array.\n");

	status = buffer_copy_to_raw(
			raw_array,
			0,
			buffer2,
			3,
			4);
	if (status == 0) {
		fprintf(stderr, "ERROR: Failed to detect out of bounds read!\n");
		buffer_clear(buffer1);
		buffer_clear(buffer2);
		free(buffer2->content);
		return EXIT_FAILURE;
	}
	printf("Successfully detected out of bounds read.\n");

	//copy from raw array
	unsigned char heeelo[14] = "Hello World!\n";
	status = buffer_copy_from_raw(
			buffer1, //destination
			0, //offset
			heeelo, //source
			0, //offset
			sizeof(heeelo)); //length
	if ((status != 0) || (sodium_memcmp(heeelo, buffer1->content, sizeof(heeelo)))) {
		fprintf(stderr, "ERROR: Failed to copy from raw array to buffer. (%i)\n", status);
		buffer_clear(buffer1);
		buffer_clear(buffer2);
		free(buffer2->content);
		return EXIT_FAILURE;
	}
	printf("Successfully copied raw array to buffer.\n");

	status = buffer_copy_from_raw(
			buffer1,
			1,
			heeelo,
			0,
			sizeof(heeelo));
	if (status == 0) {
		fprintf(stderr, "ERROR: Failed to detect out of bounds read.\n");
		buffer_clear(buffer1);
		buffer_clear(buffer2);
		free(buffer2->content);
		return EXIT_FAILURE;
	}
	printf("Out of bounds read detected.\n");

	//create a buffer from a string
	buffer_t *string = buffer_create_from_string("This is a string!");
	if (string == NULL) {
		fprintf(stderr, "ERROR: Buffer created from string is NULL!");
		buffer_clear(buffer1);
		buffer_clear(buffer2);
		free(buffer2->content);
		return EXIT_FAILURE;
	}
	if (string->content_length != sizeof("This is a string!")) {
		fprintf(stderr, "ERROR: Buffer created from string has incorrect length.\n");
		buffer_clear(buffer1);
		buffer_clear(buffer2);
		free(buffer2->content);
		return EXIT_FAILURE;
	}
	if (sodium_memcmp(string->content, "This is a string!", string->content_length) != 0) {
		fprintf(stderr, "ERROR: Failed to create buffer from string.\n");
		buffer_clear(buffer1);
		buffer_clear(buffer2);
		free(buffer2->content);
		return EXIT_FAILURE;
	}
	printf("Successfully created buffer from string.\n");

	//erase the buffer
	printf("Erasing buffer.\n");
	buffer_clear(buffer1);

	//check if the buffer was properly cleared
	size_t i;
	for (i = 0; i < buffer1->buffer_length; i++) {
		if (buffer1->content[i] != '\0') {
			fprintf(stderr, "ERROR: Byte %zi of the buffer hasn't been erased.\n", i);
			buffer_clear(buffer1);
			buffer_clear(buffer2);
			free(buffer2->content);
			return EXIT_FAILURE;
		}
	}

	if (buffer1->content_length != 0) {
		fprintf(stderr, "ERROR: The content length of the buffer hasn't been set to zero.\n");
		buffer_clear(buffer1);
		buffer_clear(buffer2);
		return EXIT_FAILURE;
	}
	printf("Buffer successfully erased.\n");

	buffer_clear(buffer2);
	free(buffer2->content);

	//fill a buffer with random numbers
	buffer_t *random = buffer_create(10, 0);
	status = buffer_fill_random(random, 5);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to fill buffer with random numbers. (%i)\n", status);
		buffer_clear(random);
		return status;
	}

	if (random->content_length != 5) {
		fprintf(stderr, "ERROR: Wrong content length.\n");
		buffer_clear(random);
		return EXIT_FAILURE;
	}
	printf("Buffer with %zi random bytes:\n", random->content_length);
	print_hex(random);

	if (buffer_fill_random(random, 20) == 0) {
		fprintf(stderr, "ERROR: Failed to detect too long write to buffer.\n");
		buffer_clear(random);
		return EXIT_FAILURE;
	}

	random->readonly = true;
	if (buffer_fill_random(random, 4) == 0) {
		fprintf(stderr, "ERROR: Failed to prevent write to readonly buffer.\n");
		buffer_clear(random);
		return EXIT_FAILURE;
	}

	//test xor
	buffer_t *text = buffer_create_from_string("Hello World!");
	buffer_t *xor = buffer_create(text->content_length, text->content_length);
	status = buffer_clone(xor, text);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to clone buffer.\n");
		return status;
	}

	buffer_t *random2 = buffer_create(text->content_length, text->content_length);
	status = buffer_fill_random(random2, random2->buffer_length);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to fill buffer with random data. (%i)\n", status);
		return status;
	}

	//xor random data to xor-buffer
	status = buffer_xor(xor, random2);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to xor buffers. (%i)\n", status);
		return status;
	}

	//make sure that xor doesn't contain either 'text' or 'random2'
	if ((buffer_compare(xor, text) == 0) || (buffer_compare(xor, random2) == 0)) {
		fprintf(stderr, "ERROR: xor buffer contains 'text' or 'random2'\n");
		return EXIT_FAILURE;
	}

	//xor the buffer with text again to get out the random data
	status = buffer_xor(xor, text);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to xor buffers. (%i)\n", status);
		return status;
	}

	//xor should now contain the same as random2
	if (buffer_compare(xor, random2) != 0) {
		fprintf(stderr, "ERROR: Failed to xor buffers properly.\n");
		return EXIT_FAILURE;
	}
	printf("Successfully tested xor.\n");

	//test creating a buffer with an existing array
	unsigned char array[] = "Hello World!\n";
	buffer_t *buffer_with_array = buffer_create_with_existing_array(array, sizeof(array));
	if ((buffer_with_array->content != array)
			|| (buffer_with_array->content_length != sizeof(array))
			|| (buffer_with_array->buffer_length != sizeof(array))) {
		fprintf(stderr, "ERROR: Failed to create buffer with existing array.\n");
		return EXIT_FAILURE;
	}

	//test character access
	buffer_t *character_buffer = buffer_create(4,3);
	buffer_t *test_buffer = buffer_create_from_string("Hi");
	status = buffer_set_char_at(character_buffer, 0, 'H');
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to set character at given position. (%i)\n", status);
		return status;
	}
	status = buffer_set_char_at(character_buffer, 1, 'i');
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to set character at given position. (%i)\n", status);
		return status;
	}
	status = buffer_set_char_at(character_buffer, 2, '\0');
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to set character at given position. (%i)\n", status);
		return status;
	}
	status = buffer_set_char_at(character_buffer, 3, '!');
	if (status == 0) {
		fprintf(stderr, "ERROR: Failed to detect out of bound write to buffer.\n");
		return EXIT_FAILURE;
	}
	//compare the bufers
	if (buffer_compare(character_buffer, test_buffer) != 0) {
		fprintf(stderr, "ERROR: Setting characters manually failed!\n");
		return EXIT_FAILURE;
	}

	//test memset functions
	buffer_t *set_buffer = buffer_create(10, 10);
	buffer_memset(set_buffer, 0x01);
	if (set_buffer->content[3] != 0x01) {
		fprintf(stderr, "ERROR: Failed to memset buffer.\n");
		return EXIT_FAILURE;
	}
	status = buffer_memset_partial(set_buffer, 0x02, 5);
	if ((status != 0) || (set_buffer->content[3] != 0x02) || (set_buffer->content[4] != 0x02) || (set_buffer->content[5] != 0x01) || (set_buffer->content_length != 5)) {
		fprintf(stderr, "ERROR: Failed to partially memset buffer.\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
