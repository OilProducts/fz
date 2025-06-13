// target2.c - conditional stack smash with single-byte prefix.
#include <stdio.h>
#include <string.h>
#include <stdlib.h> // For exit()

int main(void) {
    char buf[8];
    // Buffer to hold the magic byte + 64 bytes for the overflow attempt
    char input_buffer[65];

    // Read up to 65 bytes. We expect at least 1 for the magic byte.
    size_t bytes_read = fread(input_buffer, 1, sizeof(input_buffer) -1, stdin);
    input_buffer[bytes_read] = '\0'; // Null-terminate the actual input

    if (bytes_read < 1) {
        // Not enough input for magic byte
        puts("Too short");
        return 1;
    }

    // Check for the magic byte 'X'
    if (input_buffer[0] == 'X') {
        // If magic byte is present, then attempt to copy up to 64 bytes
        // from the rest of the input into buf, causing overflow.
        // Ensure we don't read past what was actually read into input_buffer if it's less than 1+64.
        size_t len_to_copy = bytes_read > 1 ? bytes_read - 1 : 0;
        if (len_to_copy > 0) {
             memcpy(buf, input_buffer + 1, len_to_copy > 64 ? 64 : len_to_copy);
        }
        puts("Magic received!");
    } else {
        puts("No magic.");
    }
    return 0;
}
