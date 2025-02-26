#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>

/*
* Takes in an input string and generates a 32-bit checksum hash value of type uint32_t
* This function is internally called by the function getCheckSumValue(); so not to be called directly by
developer
* Input type: String
* Output type: uint32_t
*/
uint32_t generate32bitChecksum(const char* valueToConvert) {
    uint32_t checksum = 0;
    while (*valueToConvert) {
        checksum += *valueToConvert++;
        checksum += (checksum << 10);
        checksum ^= (checksum >> 6);
    }
    checksum += (checksum << 3);
    checksum ^= (checksum >> 11);
    checksum += (checksum << 15);
    return checksum;
}
/*
* This function can be called by the developer to generate a 32-bit checksum directly from the pointer to your
frame structure
* The function is independent of the contents/data types used in your frame structure
* It works based on the bits in your structure
* IMPORTANT NOTE & Hint: For accurate results, you must use __attribute__((packed)) while creating your
Frame structure
* to avoid additional padding bytes which occur in C language structures
* Input: Pointer to the frame structure, the size of the frame structure, number of bytes to skip from the start
and end (for crc calculation)
* Providing example input for reference: uint32_t checksum = getCheckSumValue(&yourFrame,
sizeof(yourFrame), bytesToSkipFromStart, bytesToSkipFromEnd)
* Hint: bytesToSkipFromEnd is provided (for instance) since the CRC computation should not include the FCS
field of the payload
* Output: uint 32 bit final Check Sum value
*/
uint32_t getCheckSumValue(const void *ptr, size_t size, ssize_t bytesToSkipFromStart, size_t bytesToSkipFromEnd) {
    const unsigned char *byte = (const unsigned char *)ptr;
    // binaryString[] is a logical representation of 1 byte. Each character in it represents 1 bit.
    // Do not confuse with the size of character in C language (which is 1 byte). This is just a representation.
    char binaryString[9]; // One additional character for the null terminator
    binaryString[8] = '\0'; // Null terminator definition
    char *buffer = malloc(1); // Allocates space for an empty string (1 byte for the null terminator)
    buffer[0] = '\0'; // Initializes an empty string
    for (size_t i = 1; i <= size; i++) {
        for (int j = 7; j >= 0; j--) {
            int bit = (byte[i - 1] >> j) & 1;
            binaryString[7 - j] = bit + '0'; // Converts bit to character '0' or '1'
        }
        buffer = realloc (buffer, strlen(buffer) + strlen(binaryString) + 1); // Resizes buffer to fit the concatenated result
        strcat(buffer, binaryString);
    }
    buffer[strlen(buffer)-(bytesToSkipFromEnd*8)] = '\0';
    memmove(buffer, buffer + (bytesToSkipFromStart*8), strlen(buffer) - (bytesToSkipFromStart*8) + 1); //+1 for null terminator
    // printf("\nGenerated string: %s\n", buffer);
    // printf("\nSize of generated string in bytes: %zu\n", strlen(buffer)/8);
    uint32_t checkSumValue = generate32bitChecksum(buffer);
    free(buffer); // Freeing memory allocated by malloc.
    return checkSumValue;
}

int AssociationRequest(){
    return 0;
}

int main(){
    int protocolVersion = 0;
    int moreFragment = 0;
    bool retry = false;
    bool powerManagement = false;
    int moreData = 0;
    int WEP = 0;
    int order = 0;
    char sequenceControl[] = "0000";
    char address4[] = "000000000000"; //bridge address
    char type[] = "00";
    char subtype[]= "0000";
    int ToDS = 0;
    int FromDS = 0;
    int durationID = 0;
    char address1[] = "1245CCDDEE88"; //receiver address
    char address2[] = "AABBCCDDEEDD"; //transmitter address
    char address3[] = "AABBCCDDEEDD"; //BSSID
    int bytesToSkipFromStart = 0;
    int bytesToSkipFromEnd = 4;
    char payload[] = "Hello World!";
    int FCS = 0;
    char frame[100];


    uint32_t checksum = getCheckSumValue(&frame, sizeof(frame), bytesToSkipFromStart, bytesToSkipFromEnd);
    printf("Checksum: %u\n", checksum);

    

    return 0;
}