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

#include <alloca.h>
#include <stdbool.h>

#ifndef LIB_BUFFER_H
#define LIB_BUFFER_H

typedef struct buffer_t {
	const size_t buffer_length;
	size_t content_length;
	bool readonly; //if set, this buffer shouldn't be written to.
	unsigned char * const content;
} buffer_t;

/*
 * Initialize a buffer with a given length.
 *
 * This is normally not called directly but via
 * the buffer_create macro.
 */
buffer_t* buffer_init(
		buffer_t * const buffer,
		const size_t buffer_length,
		const size_t content_length) __attribute__((warn_unused_result));

/*
 * initialize a buffer with a pointer to the character array.
 */
buffer_t* buffer_init_with_pointer(
		buffer_t * const buffer,
		unsigned char * const content,
		const size_t buffer_length,
		const size_t content_length);

/*
 * Macro to create a new buffer of a given length.
 */
#define buffer_create(buffer_length, content_length) buffer_init(alloca(sizeof(buffer_t) + buffer_length), buffer_length, content_length)

/*
 * Macro to create a new buffer on the heap.
 */
//FIXME: What if malloc returns NULL?
#define buffer_create_on_heap(buffer_length, content_length) buffer_init(malloc(sizeof(buffer_t) + buffer_length), buffer_length, content_length)

/*
 * Copy a raw array to a buffer and return the
 * buffer.
 *
 * This should not be used directly, it is intended for the use
 * with the macro buffer_create_from_string.
 *
 * Returns NULL on error.
 */
buffer_t* buffer_create_from_string_helper(
		buffer_t * const buffer,
		const unsigned char * const content,
		const size_t content_length) __attribute__((warn_unused_result));

/*
 * Create a new buffer from a string literal.
 */
#define buffer_create_from_string(string) buffer_create_from_string_helper(buffer_create(sizeof(string), sizeof(string)), (unsigned char*) string, sizeof(string))

/*
 * Clear a buffer.
 *
 * Overwrites the buffer with zeroes and
 * resets the content size.
 */
void buffer_clear(buffer_t *buffer);

/*
 * Macro to free and clear a heap allocated buffer.
 */
#define buffer_destroy_from_heap(buffer) buffer_clear(buffer); free(buffer)

/*
 * Macro to create a buffer with already existing data without cloning it.
 */
#define buffer_create_with_existing_array(array, length) buffer_init_with_pointer(alloca(sizeof(buffer_t)), array, length, length)

/*
 * Concatenate a buffer to the first.
 *
 * Return 0 on success.
 */
int buffer_concat(
		buffer_t * const destination,
		const buffer_t * const source) __attribute__((warn_unused_result));

/*
 * Copy parts of a buffer to another buffer.
 *
 * Returns 0 on success.
 */
int buffer_copy(
		buffer_t * const destination,
		const size_t destination_offset,
		const buffer_t * const source,
		const size_t source_offset,
		const size_t copy_length) __attribute__((warn_unused_result));

/*
 * Copy the content of a buffer to the beginning of another
 * buffer and set the destinations content length to the
 * same length as the source.
 *
 * Returns 0 on success.
 */
int buffer_clone(
		buffer_t * const destination,
		const buffer_t * const source) __attribute__((warn_unused_result));

/*
 * Copy from a raw array to a buffer.
 *
 * Returns 0 on success.
 */
int buffer_copy_from_raw(
		buffer_t * const destination,
		const size_t destination_offset,
		const unsigned char * const source,
		const size_t source_offset,
		const size_t copy_length) __attribute__((warn_unused_result));

/*
 * Copy the content of a raw array to the
 * beginning of a buffer, setting the buffers
 * content length to the length that was copied.
 *
 * Returns 0 on success.
 */
int buffer_clone_from_raw(
		buffer_t * const destination,
		const unsigned char * const source,
		const size_t length) __attribute__((warn_unused_result));

/*
 * Copy the content of a raw array to the
 * beginning of a buffer, setting the buffers
 * content length to the length that was copied.
 *
 * Returns 0 on success.
 */
int buffer_clone_from_raw(
		buffer_t * const destination,
		const unsigned char * const source,
		const size_t length) __attribute__((warn_unused_result));

/*
 * Copy from a buffer to a raw array.
 *
 * Returns 0 on success.
 */
int buffer_copy_to_raw(
		unsigned char * const destination,
		const size_t destination_offset,
		const buffer_t * const source,
		const size_t source_offset,
		const size_t copy_length) __attribute__((warn_unused_result));

/*
 * Copy the entire content of a buffer
 * to a raw array.
 *
 * Returns 0 on success.
 */
int buffer_clone_to_raw(
		unsigned char * const destination,
		const size_t destination_length,
		const buffer_t *source) __attribute__((warn_unused_result));

/*
 * Compare two buffers.
 *
 * Returns 0 if both buffers match.
 */
int buffer_compare(
		const buffer_t * const buffer1,
		const buffer_t * const buffer2) __attribute__((warn_unused_result));

/*
 * Compare parts of two buffers.
 *
 * Returns 0 if both buffers match.
 */
int buffer_compare_partial(
		const buffer_t * const buffer1,
		const size_t position1,
		const buffer_t * const buffer2,
		const size_t position2,
		const size_t length) __attribute__((warn_unused_result));

/*
 * Fill a buffer with random numbers.
 */
int buffer_fill_random(
		buffer_t * const buffer,
		const size_t length) __attribute__((warn_unused_result));

/*
 * Xor a buffer onto another of the same length.
 */
int buffer_xor(
		buffer_t * const destination,
		const buffer_t * const source) __attribute__((warn_unused_result));

/*
 * Set a single character in a buffer.
 */
int buffer_set_char_at(
		const buffer_t * const buffer,
		const size_t pos,
		const unsigned char character) __attribute__((warn_unused_result));

/*
 * Set parts of a buffer to a given character.
 * ( sets the content length to the given length! )
 */
int buffer_memset_partial(
		buffer_t * const buffer,
		const unsigned char character,
		const size_t length) __attribute__((warn_unused_result));

/*
 * Set the entire buffer to a given character.
 * (content_length is used as the length, not buffer_length)
 */
void buffer_memset(
		buffer_t * const buffer,
		const unsigned char character);
#endif
