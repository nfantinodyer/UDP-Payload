#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>

#define MAX_PAYLOAD 2312

void error(char *msg){
    perror(msg);
    exit(0);
}

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

int main(){
    int sock, length, fromlen, n;
    struct sockaddr_in server;
    struct sockaddr_in from;
    char buf[3000];
    static int associated = 0; //flag to track if a client is already associated

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0){
        error("Opening socket");
    }
    length = sizeof(server);
    bzero(&server, length);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(4547);
    if (bind(sock, (struct sockaddr *)&server, length) < 0){
        error("binding");
    }
    fromlen = sizeof(struct sockaddr_in);

    while(1){
        n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
        if (n < 0){
            error("recvfrom");
        }

        if (n < 40) { 
            printf("Packet too short to be a valid 802.11 frame. Ignoring.\n");
            continue;
        }
        
        //start of frame ID
        if ((unsigned char)buf[0] != 0xFF || (unsigned char)buf[1] != 0xFF) {
            printf("Invalid start-of-frame identifier\n");
            continue;
        }
        
        //end of frame ID
        if ((unsigned char)buf[n-2] != 0xFF || (unsigned char)buf[n-1] != 0xFF) {
            printf("Invalid end-of-frame identifier\n");
            continue;
        }
        
        //since fcs and end of frame are 6 bytes I skip the last 6 bytes.
        uint32_t computedFCS = getCheckSumValue(buf, n, 0, 6);
        
        int fcsPosition = n - 6;
        uint32_t receivedFCS = ((unsigned char)buf[fcsPosition] << 24) |
                               ((unsigned char)buf[fcsPosition+1] << 16) |
                               ((unsigned char)buf[fcsPosition+2] << 8) |
                               ((unsigned char)buf[fcsPosition+3]);
        
        //compare computed FCS with the received FCS.
        if (computedFCS != receivedFCS) {
            //if the frame is a Data frame (frame control first byte = 0x20), extract fragment info.
            if ((unsigned char)buf[2] == 0x20) {
                //assume sequence control is at bytes 30 and 31 in a 32-byte header.
                uint16_t seqControl = (((unsigned char)buf[30]) << 8) | ((unsigned char)buf[31]);
                uint8_t fragNum = seqControl & 0x0F; //lower 4 bits
                printf("AP: FCS Error fragment or data frame %u. Computed FCS = %u, but Received FCS = %u. No ACK sent.\n",
                       fragNum+1, computedFCS, receivedFCS);
                //clear the buffer
                memset(buf, 0, sizeof(buf));
                seqControl = 0;
                fragNum = 0;
            } else {
                printf("AP: FCS Error detected. Computed FCS = %u, but Received FCS = %u. Sending error message.\n", computedFCS, receivedFCS);
                memset(buf, 0, sizeof(buf));
            }
            char errorMsg[] = "FCS (Frame Check Sequence) Error";
            printf("AP: FCS (Frame Check Sequence) Error\n");
            continue;
        } else {
            if ((unsigned char)buf[2] == 0x00 && (unsigned char)buf[3] == 0x01) {
                printf("AP: Received Association Request (size %d bytes). FCS verified: %u\n", n, computedFCS);
            
                associated = 1;  //mark client as associated

                //association response frame
                char respFrame[3000];
                int offset = 0;

                //start of frame ID
                respFrame[offset++] = 0xFF;
                respFrame[offset++] = 0xFF;

                //for association response, type = 00, subtype = 0001
                respFrame[offset++] = 0x00;
                respFrame[offset++] = 0x02;

                //duration ID using random ones
                respFrame[offset++] = 0x12;
                respFrame[offset++] = 0x34;

                //address 1: client is the reciever 0x12, 0x45, 0xCC, 0xDD, 0xEE, 0x88
                unsigned char clientMAC[6] = {0x12, 0x45, 0xCC, 0xDD, 0xEE, 0x88};
                memcpy(respFrame + offset, clientMAC, 6);
                offset += 6;

                //address 2: AP’s 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xDD
                unsigned char apMAC[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xDD};
                memcpy(respFrame + offset, apMAC, 6);
                offset += 6;

                //ap address again
                memcpy(respFrame + offset, apMAC, 6);
                offset += 6;

                //bridge (0s)
                unsigned char bridge[6] = {0, 0, 0, 0, 0, 0};
                memcpy(respFrame + offset, bridge, 6);
                offset += 6;

                //seq control
                respFrame[offset++] = 0x00;
                respFrame[offset++] = 0x00;

                //paylaod
                char *payload = "Association Response";
                int payloadLen = strlen(payload);
                memcpy(respFrame + offset, payload, payloadLen);
                offset += payloadLen;

                //FCS reserving
                int fcsPosition = offset;
                respFrame[offset++] = 0x00;
                respFrame[offset++] = 0x00;
                respFrame[offset++] = 0x00;
                respFrame[offset++] = 0x00;

                //end of frame ID
                respFrame[offset++] = 0xFF;
                respFrame[offset++] = 0xFF;

                int respSize = offset;

                uint32_t respChecksum = getCheckSumValue(respFrame, respSize, 0, 6);

                //put computed FCS into the reserved space
                respFrame[fcsPosition + 0] = (respChecksum >> 24) & 0xFF;
                respFrame[fcsPosition + 1] = (respChecksum >> 16) & 0xFF;
                respFrame[fcsPosition + 2] = (respChecksum >> 8)  & 0xFF;
                respFrame[fcsPosition + 3] = respChecksum & 0xFF;

                //send association response
                int sendBytes = sendto(sock, respFrame, respSize, 0, (struct sockaddr *)&from, fromlen);
                if (sendBytes < 0) {
                    error("sendto");
                }
                printf("AP: Built Association Response with FCS = %u. Sending response (size %d bytes).\n", respChecksum, respSize);
                continue;
                
            }
            else if ((unsigned char)buf[2] == 0x04 && (unsigned char)buf[3] == 0x01) {
                printf("AP: Received Probe Request from client. Processing...\n");

                //build Probe Response frame
                char probeRespFrame[3000];
                int pOffset = 0;

                //start of frame ID
                probeRespFrame[pOffset++] = 0xFF;
                probeRespFrame[pOffset++] = 0xFF;

                //for probe response, type = 00, subtype = 0101
                //first byte: 0x05; second byte: AP->client: ToDS=0, FromDS=1 -> 0x02.
                probeRespFrame[pOffset++] = 0x05;
                probeRespFrame[pOffset++] = 0x02;

                //duration ID: use 0x56, 0x78
                probeRespFrame[pOffset++] = 0x56;
                probeRespFrame[pOffset++] = 0x78;

                //address 1 client is the receiver: 0x12,0x45,0xCC,0xDD,0xEE,0x88
                unsigned char clientMAC[6] = {0x12, 0x45, 0xCC, 0xDD, 0xEE, 0x88};
                memcpy(probeRespFrame + pOffset, clientMAC, 6);
                pOffset += 6;

                //address 2 AP: 0xAA,0xBB,0xCC,0xDD,0xEE,0xDD
                unsigned char apMAC[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xDD};
                memcpy(probeRespFrame + pOffset, apMAC, 6);
                pOffset += 6;

                //address 3 AP again
                memcpy(probeRespFrame + pOffset, apMAC, 6);
                pOffset += 6;

                //address 4 Bridge (all zeros)
                unsigned char bridge[6] = {0,0,0,0,0,0};
                memcpy(probeRespFrame + pOffset, bridge, 6);
                pOffset += 6;

                //sequence control (0x0000)
                probeRespFrame[pOffset++] = 0x00;
                probeRespFrame[pOffset++] = 0x00;

                //payload
                unsigned char fullPayload[MAX_PAYLOAD];
                memset(fullPayload, 0xFF, MAX_PAYLOAD);

                char *probeRespPayload = "Probe Response";
                int probeRespPayloadLen = strlen(probeRespPayload);
                memcpy(fullPayload, probeRespPayload, probeRespPayloadLen);

                memcpy(probeRespFrame + pOffset, fullPayload, MAX_PAYLOAD);
                pOffset += MAX_PAYLOAD;

                //reserve 4 bytes for FCS
                int probeFcsPos = pOffset;
                probeRespFrame[pOffset++] = 0x00;
                probeRespFrame[pOffset++] = 0x00;
                probeRespFrame[pOffset++] = 0x00;
                probeRespFrame[pOffset++] = 0x00;

                //end of frame ID
                probeRespFrame[pOffset++] = 0xFF;
                probeRespFrame[pOffset++] = 0xFF;

                int probeRespSize = pOffset;
                uint32_t probeRespChecksum = getCheckSumValue(probeRespFrame, probeRespSize, 0, 6);

                //insert computed FCS into reserved space
                probeRespFrame[probeFcsPos + 0] = (probeRespChecksum >> 24) & 0xFF;
                probeRespFrame[probeFcsPos + 1] = (probeRespChecksum >> 16) & 0xFF;
                probeRespFrame[probeFcsPos + 2] = (probeRespChecksum >> 8) & 0xFF;
                probeRespFrame[probeFcsPos + 3] = probeRespChecksum & 0xFF;

                //send probe response
                int probeSendBytes = sendto(sock, probeRespFrame, probeRespSize, 0, (struct sockaddr *)&from, fromlen);
                if(probeSendBytes < 0) {
                    error("sendto");
                }

                printf("AP: Built Probe Response with FCS = %u. Sent Probe Response (size %d bytes).\n", probeRespChecksum, probeRespSize);
                continue;
            }
            else if ((unsigned char)buf[2] == 0x1B && (unsigned char)buf[3] == 0x01) {
                printf("AP: Received RTS frame from client. Preparing CTS response...\n");
                
                // Build CTS Response frame
                char ctsFrame[3000];
                int ctsOffset = 0;
                
                //start of frame ID
                ctsFrame[ctsOffset++] = 0xFF;
                ctsFrame[ctsOffset++] = 0xFF;
                
                //for CTS response, set type = 01, subtype = 1100
                //0x1C (binary 00011100)
                //For AP->client, ToDS=0, FromDS=1 -> 0x02
                ctsFrame[ctsOffset++] = 0x1C;
                ctsFrame[ctsOffset++] = 0x02;
                
                //Duration ID = 3 (0x0003)
                ctsFrame[ctsOffset++] = 0x00;
                ctsFrame[ctsOffset++] = 0x03;
                
                //address 1 receiver (client): 1245CCDDEE88
                unsigned char clientMAC_CTS[6] = {0x12, 0x45, 0xCC, 0xDD, 0xEE, 0x88};
                memcpy(ctsFrame + ctsOffset, clientMAC_CTS, 6);
                ctsOffset += 6;
                
                //address 2 source (AP): AABBCCDDEEDD
                unsigned char apMAC_CTS[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xDD};
                memcpy(ctsFrame + ctsOffset, apMAC_CTS, 6);
                ctsOffset += 6;
                
                //address 3 AP address (AABBCCDDEEDD)
                memcpy(ctsFrame + ctsOffset, apMAC_CTS, 6);
                ctsOffset += 6;
                
                //address 4 Bridge (all zeros)
                unsigned char bridge_CTS[6] = {0,0,0,0,0,0};
                memcpy(ctsFrame + ctsOffset, bridge_CTS, 6);
                ctsOffset += 6;
                
                //sequence control (0x0000)
                ctsFrame[ctsOffset++] = 0x00;
                ctsFrame[ctsOffset++] = 0x00;
                
                //payload
                unsigned char fullPayload[MAX_PAYLOAD];
                memset(fullPayload, 0xFF, MAX_PAYLOAD);

                char *ctsPayload = "CTS";
                int ctsPayloadLen = strlen(ctsPayload);
                memcpy(fullPayload, ctsPayload, ctsPayloadLen);

                memcpy(ctsFrame + ctsOffset, fullPayload, MAX_PAYLOAD);
                ctsOffset += MAX_PAYLOAD;
                
                //reserve 4 bytes for FCS
                int ctsFcsPos = ctsOffset;
                ctsFrame[ctsOffset++] = 0x00;
                ctsFrame[ctsOffset++] = 0x00;
                ctsFrame[ctsOffset++] = 0x00;
                ctsFrame[ctsOffset++] = 0x00;
                
                //end of frame ID
                ctsFrame[ctsOffset++] = 0xFF;
                ctsFrame[ctsOffset++] = 0xFF;
                
                int ctsFrameSize = ctsOffset;
                uint32_t ctsChecksum = getCheckSumValue(ctsFrame, ctsFrameSize, 0, 6);
                ctsFrame[ctsFcsPos + 0] = (ctsChecksum >> 24) & 0xFF;
                ctsFrame[ctsFcsPos + 1] = (ctsChecksum >> 16) & 0xFF;
                ctsFrame[ctsFcsPos + 2] = (ctsChecksum >> 8) & 0xFF;
                ctsFrame[ctsFcsPos + 3] = ctsChecksum & 0xFF;
                
                //send CTS response
                int ctsSendBytes = sendto(sock, ctsFrame, ctsFrameSize, 0, (struct sockaddr *)&from, fromlen);
                if(ctsSendBytes < 0) {
                    error("sendto");
                }
                
                printf("AP: Built CTS Response with FCS = %u. Sent CTS Response (size %d bytes).\n", ctsChecksum, ctsFrameSize);
                continue;
            }
            else if ((unsigned char)buf[2] == 0x20) {
                //parse the Frame Control field (2 bytes at positions 2 and 3)
                uint8_t fcByte1 = (unsigned char)buf[2];
                uint8_t fcByte2 = (unsigned char)buf[3];
            
                // parse the data frame, extract seqControl, etc.
                uint16_t seqControl = (((unsigned char)buf[30]) << 8) | ((unsigned char)buf[31]);
                uint8_t fragNum = seqControl & 0x0F;  
                bool moreFragments = ((fcByte2 & 0x02) != 0);

                printf("AP: Received Data Frame. Frame Control: 0x%02X 0x%02X; "
                    "Sequence Control: 0x%04X (Fragment %u); More Frags: %s\n",
                    fcByte1, fcByte2, seqControl, (fragNum + 1),
                    moreFragments ? "true" : "false");

            
                char ackFrame[3000];
                int aOffset = 0;
            
                //start of frame ID
                ackFrame[aOffset++] = 0xFF;
                ackFrame[aOffset++] = 0xFF;
            
                //Frame Control for ACK: Type=1, Subtype=1101 -> 0xD4,
                //AP->Client -> second byte=0x02 (FromDS=1, ToDS=0)
                ackFrame[aOffset++] = 0xD4; // (binary 00011101)
                ackFrame[aOffset++] = 0x02;
            
                //duration ID = 1
                ackFrame[aOffset++] = 0x00;
                ackFrame[aOffset++] = 0x01;
                    
                //addresses
                unsigned char clientMAC_ACK[6] = {0x12, 0x45, 0xCC, 0xDD, 0xEE, 0x88};
                memcpy(ackFrame + aOffset, clientMAC_ACK, 6);
                aOffset += 6;
            
                unsigned char apMAC_ACK[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xDD};
                memcpy(ackFrame + aOffset, apMAC_ACK, 6);
                aOffset += 6;
            
                //AP address again
                memcpy(ackFrame + aOffset, apMAC_ACK, 6);
                aOffset += 6;
            
                // Bridge address (all zeros)
                unsigned char bridge_ACK[6] = {0, 0, 0, 0, 0, 0};
                memcpy(ackFrame + aOffset, bridge_ACK, 6);
                aOffset += 6;
            
                //sequence control (0x0000)
                ackFrame[aOffset++] = 0x00;
                ackFrame[aOffset++] = 0x00;
            
                unsigned char fullPayload[MAX_PAYLOAD];
                memset(fullPayload, 0xFF, MAX_PAYLOAD);
            
                char ackPayload[100];
                snprintf(ackPayload, sizeof(ackPayload),
                         "ACK for Seq=0x%04X (Frag %u)", seqControl, (fragNum + 1));
            
                size_t ackPayloadLen = strlen(ackPayload);
                memcpy(fullPayload, ackPayload, ackPayloadLen);
                memcpy(ackFrame + aOffset, fullPayload, MAX_PAYLOAD);
                aOffset += MAX_PAYLOAD;
            
                //reserve 4 bytes for FCS
                int ackFcsPos = aOffset;
                ackFrame[aOffset++] = 0x00;
                ackFrame[aOffset++] = 0x00;
                ackFrame[aOffset++] = 0x00;
                ackFrame[aOffset++] = 0x00;
            
                //end of frame ID
                ackFrame[aOffset++] = 0xFF;
                ackFrame[aOffset++] = 0xFF;
            
                int ackFrameSize = aOffset;
                uint32_t ackChecksum = getCheckSumValue(ackFrame, ackFrameSize, 0, 6);
            
                //insert FCS
                ackFrame[ackFcsPos + 0] = (ackChecksum >> 24) & 0xFF;
                ackFrame[ackFcsPos + 1] = (ackChecksum >> 16) & 0xFF;
                ackFrame[ackFcsPos + 2] = (ackChecksum >> 8) & 0xFF;
                ackFrame[ackFcsPos + 3] = ackChecksum & 0xFF;
            
                //send ACK
                int ackSendBytes = sendto(sock, ackFrame, ackFrameSize, 0,
                                          (struct sockaddr *)&from, fromlen);
                if (ackSendBytes < 0) {
                    error("sendto");
                }
            
                printf("AP: Built ACK for Data Frame (Frag %u, seq=0x%04X) with FCS=%u. Sent ACK (size %d bytes).\n",
                       fragNum + 1, seqControl, ackChecksum, ackFrameSize);

                //clear the buffer
                memset(buf, 0, sizeof(buf));
                
                //clear the ackFrame
                memset(ackFrame, 0, sizeof(ackFrame));

                //clear the fullPayload
                memset(fullPayload, 0, sizeof(fullPayload));

                //clear the ackPayload
                memset(ackPayload, 0, sizeof(ackPayload));

                continue;
            }
        }
    }
    
    return 0;
}