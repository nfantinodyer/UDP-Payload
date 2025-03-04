#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>


#define SERVER_PORT 4547
#define SERVER_IP "127.0.0.1"

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
    /*
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
    */

    char frame[100];
    int offset=0;

    //start frame identifier
    frame[offset++] = 0xFF;
    frame[offset++] = 0xFF; //needs two since its 1 byte per, and char can only hold 1

    //association request type=0, subtype=0 -> first byte = 0x00.
    //second byte: ToDS=1, FromDS =0 -> 0x01. (from ap would be 0x02)
    frame[offset++] = 0x00;
    frame[offset++] = 0x01;

    //durationID
    frame[offset++] = 0x00;
    frame[offset++] = 0x00;

    //address 1: Receiver (6 bytes AABBCCDDEEDD)
    unsigned char addr1[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xDD};
    memcpy(frame + offset, addr1, 6);
    offset += 6;

    //address 2: Source 6 bytes 1245CCDDEE88
    unsigned char addr2[6] = {0x12, 0x45, 0xCC, 0xDD, 0xEE, 0x88};
    memcpy(frame + offset, addr2, 6);
    offset += 6;

    //address 3: AP 6 bytes AABBCCDDEEDD
    unsigned char addr3[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xDD};
    memcpy(frame + offset, addr3, 6);
    offset += 6;

    //address 4: Bridge address 6 bytes all zeros
    unsigned char addr4[6] = {0,0,0,0,0,0};
    memcpy(frame + offset, addr4, 6);
    offset += 6;

    //seq control
    frame[offset++] = 0x00;
    frame[offset++] = 0x00;

    //payload
    char *payload = "Association Request";
    int payloadLen = strlen(payload);
    memcpy(frame + offset, payload, payloadLen);
    offset += payloadLen;

    //fcs position
    int fcsPosition = offset;
    frame[offset++] = 0x00;
    frame[offset++] = 0x00;
    frame[offset++] = 0x00;
    frame[offset++] = 0x00;

    //end of frame ID
    frame[offset++] = 0xFF;
    frame[offset++] = 0xFF;

    int totalFrameSize = offset;
    uint32_t checksum = getCheckSumValue(frame, totalFrameSize, 0, 6);

    //put parts of the checksum value into the fcs part
    //has to be split since only so much can fit into a char
    frame[fcsPosition + 0] = (checksum >> 24) & 0xFF;
    frame[fcsPosition + 1] = (checksum >> 16) & 0xFF;
    frame[fcsPosition + 2] = (checksum >> 8) & 0xFF;
    frame[fcsPosition + 3] = checksum & 0xFF;

    printf("Client: Association Request FCS computed as %u.\n", checksum);

    //create a UDP socket and send the frame like in the video
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &servaddr.sin_addr);
    
    int n = sendto(sockfd, frame, totalFrameSize, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
    if (n < 0) {
        perror("sendto failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    } else {
        printf("Client: Association Request sent (%d bytes).\n", totalFrameSize);
    }
    

    //recieve asoo responsce
    char resp[1024];
    struct sockaddr_in fromAddr;
    socklen_t addrLen = sizeof(fromAddr);
    n = recvfrom(sockfd, resp, sizeof(resp), 0, (struct sockaddr *)&fromAddr, &addrLen);
    if (n < 0) {
        perror("recvfrom failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    printf("Client: Received Association Response (%d bytes) from AP.\n", n);
    
    //validate start of frame and end of frame ID
    if ((unsigned char)resp[0] != 0xFF || (unsigned char)resp[1] != 0xFF) {
        printf("Invalid start-of-frame identifier in response.\n");
    }
    if ((unsigned char)resp[n-2] != 0xFF || (unsigned char)resp[n-1] != 0xFF) {
        printf("Invalid end-of-frame identifier in response.\n");
    }
    
    //recalculate the FCS for the response, skipping the last 6 bytes.
    uint32_t respComputedFCS = getCheckSumValue(resp, n, 0, 6);
    int respFcsPos = n - 6;
    uint32_t respReceivedFCS = ((unsigned char)resp[respFcsPos] << 24) |
                               ((unsigned char)resp[respFcsPos+1] << 16) |
                               ((unsigned char)resp[respFcsPos+2] << 8) |
                               ((unsigned char)resp[respFcsPos+3]);
    
    if (respComputedFCS != respReceivedFCS) {
        printf("FCS mismatch in Association Response: computed %u, received %u\n", respComputedFCS, respReceivedFCS);
        close(sockfd);
        exit(EXIT_FAILURE);
    } else {
        printf("Client: Association Response FCS verified successfully: %u.\n", respComputedFCS);
    }

    //send probe request
    char probeFrame[100];
    int pOffset = 0;

    //start frame identifier
    probeFrame[pOffset++] = 0xFF;
    probeFrame[pOffset++] = 0xFF;

    //probe request: type = 00, subtype = 0100
    //first byte: 0x04, second byte: ToDS=1, FromDS=0 -> 0x01.
    probeFrame[pOffset++] = 0x04;
    probeFrame[pOffset++] = 0x01;

    //duration ID (zeros)
    probeFrame[pOffset++] = 0x00;
    probeFrame[pOffset++] = 0x00;

    //address 1 receiver (AP): AABBCCDDEEDD
    unsigned char apMAC[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xDD};
    memcpy(probeFrame + pOffset, apMAC, 6);
    pOffset += 6;

    //address 2 source (client): 1245CCDDEE88
    unsigned char clientMAC[6] = {0x12, 0x45, 0xCC, 0xDD, 0xEE, 0x88};
    memcpy(probeFrame + pOffset, clientMAC, 6);
    pOffset += 6;

    //address 3 AP address: AABBCCDDEEDD
    memcpy(probeFrame + pOffset, apMAC, 6);
    pOffset += 6;

    //address 4 Bridge (all zeros)
    unsigned char bridge[6] = {0,0,0,0,0,0};
    memcpy(probeFrame + pOffset, bridge, 6);
    pOffset += 6;

    //sequence control (0x0000)
    probeFrame[pOffset++] = 0x00;
    probeFrame[pOffset++] = 0x00;

    //payload
    char *probePayload = "Probe Request";
    int probePayloadLen = strlen(probePayload);
    memcpy(probeFrame + pOffset, probePayload, probePayloadLen);
    pOffset += probePayloadLen;

    //reserve 4 bytes for FCS
    int probeFcsPos = pOffset;
    probeFrame[pOffset++] = 0x00;
    probeFrame[pOffset++] = 0x00;
    probeFrame[pOffset++] = 0x00;
    probeFrame[pOffset++] = 0x00;

    //end of frame identifier
    probeFrame[pOffset++] = 0xFF;
    probeFrame[pOffset++] = 0xFF;

    int probeFrameSize = pOffset;
    uint32_t probeChecksum = getCheckSumValue(probeFrame, probeFrameSize, 0, 6);

    //insert computed FCS into reserved space
    probeFrame[probeFcsPos + 0] = (probeChecksum >> 24) & 0xFF;
    probeFrame[probeFcsPos + 1] = (probeChecksum >> 16) & 0xFF;
    probeFrame[probeFcsPos + 2] = (probeChecksum >> 8) & 0xFF;
    probeFrame[probeFcsPos + 3] = probeChecksum & 0xFF;

    printf("Client: Probe Request FCS computed as %u.\n", probeChecksum);

    //send probe request
    n = sendto(sockfd, probeFrame, probeFrameSize, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
    if(n < 0){
        perror("sendto failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    } else {
        printf("Client: Probe Request sent (%d bytes) to AP.\n", probeFrameSize);
    }

    //receive probe response
    char probeResp[1024];
    n = recvfrom(sockfd, probeResp, sizeof(probeResp), 0, (struct sockaddr *)&servaddr, &addrLen);
    if(n < 0){
        perror("recvfrom failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    printf("Client: Received Probe Response (%d bytes) from AP.\n", n);
    
    //validate start-of-frame and end-of-frame identifiers
    if ((unsigned char)probeResp[0] != 0xFF || (unsigned char)probeResp[1] != 0xFF) {
        printf("Invalid start-of-frame identifier in Probe Response.\n");
    }
    if ((unsigned char)probeResp[n-2] != 0xFF || (unsigned char)probeResp[n-1] != 0xFF) {
        printf("Invalid end-of-frame identifier in Probe Response.\n");
    }
    
    //recalculate FCS for the probe response (skip last 6 bytes)
    uint32_t probeRespComputedFCS = getCheckSumValue(probeResp, n, 0, 6);
    int probeRespFcsPos = n - 6;
    uint32_t probeRespReceivedFCS = ((unsigned char)probeResp[probeRespFcsPos] << 24) |
                                    ((unsigned char)probeResp[probeRespFcsPos+1] << 16) |
                                    ((unsigned char)probeResp[probeRespFcsPos+2] << 8) |
                                    ((unsigned char)probeResp[probeRespFcsPos+3]);
    
    if(probeRespComputedFCS != probeRespReceivedFCS){
        printf("FCS mismatch in Probe Response: computed %u, received %u\n", probeRespComputedFCS, probeRespReceivedFCS);
        close(sockfd);
        exit(EXIT_FAILURE);
    } else {
        printf("Client: Probe Response FCS verified successfully: %u.\n", probeRespComputedFCS);
    }

    //rts frame
    char rtsFrame[100];
    int rtsOffset = 0;
    
    //start frame ID
    rtsFrame[rtsOffset++] = 0xFF;
    rtsFrame[rtsOffset++] = 0xFF;
    
    //RTS frame set type = 01 and subtype = 1011
    //0x1B (binary 00011011) 
    //For client->AP, ToDS=1, FromDS=0 -> 0x01
    rtsFrame[rtsOffset++] = 0x1B;
    rtsFrame[rtsOffset++] = 0x01;
    
    //Duration ID = 4 (0x0004)
    rtsFrame[rtsOffset++] = 0x00;
    rtsFrame[rtsOffset++] = 0x04;
    
    //address 1 receiver (AP): AABBCCDDEEDD
    unsigned char apMAC_RTS[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xDD};
    memcpy(rtsFrame + rtsOffset, apMAC_RTS, 6);
    rtsOffset += 6;
    
    //address 2 source (client): 1245CCDDEE88
    unsigned char clientMAC_RTS[6] = {0x12, 0x45, 0xCC, 0xDD, 0xEE, 0x88};
    memcpy(rtsFrame + rtsOffset, clientMAC_RTS, 6);
    rtsOffset += 6;
    
    //address 3 AP address (AABBCCDDEEDD)
    memcpy(rtsFrame + rtsOffset, apMAC_RTS, 6);
    rtsOffset += 6;
    
    //address 4 Bridge (all zeros)
    unsigned char bridge_RTS[6] = {0,0,0,0,0,0};
    memcpy(rtsFrame + rtsOffset, bridge_RTS, 6);
    rtsOffset += 6;
    
    //sequence control (0x0000)
    rtsFrame[rtsOffset++] = 0x00;
    rtsFrame[rtsOffset++] = 0x00;
    
    //payload
    char *rtsPayload = "RTS";
    int rtsPayloadLen = strlen(rtsPayload);
    memcpy(rtsFrame + rtsOffset, rtsPayload, rtsPayloadLen);
    rtsOffset += rtsPayloadLen;
    
    //reserve 4 bytes for FCS
    int rtsFcsPos = rtsOffset;
    rtsFrame[rtsOffset++] = 0x00;
    rtsFrame[rtsOffset++] = 0x00;
    rtsFrame[rtsOffset++] = 0x00;
    rtsFrame[rtsOffset++] = 0x00;
    
    //end of frame identifier
    rtsFrame[rtsOffset++] = 0xFF;
    rtsFrame[rtsOffset++] = 0xFF;
    
    int rtsFrameSize = rtsOffset;
    uint32_t rtsChecksum = getCheckSumValue(rtsFrame, rtsFrameSize, 0, 6);
    rtsFrame[rtsFcsPos + 0] = (rtsChecksum >> 24) & 0xFF;
    rtsFrame[rtsFcsPos + 1] = (rtsChecksum >> 16) & 0xFF;
    rtsFrame[rtsFcsPos + 2] = (rtsChecksum >> 8) & 0xFF;
    rtsFrame[rtsFcsPos + 3] = rtsChecksum & 0xFF;
    
    printf("Client: RTS frame FCS computed as %u.\n", rtsChecksum);
    
    //send RTS frame
    n = sendto(sockfd, rtsFrame, rtsFrameSize, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
    if(n < 0){
        perror("sendto failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    } else {
        printf("Client: RTS frame sent (%d bytes) to AP.\n", rtsFrameSize);
    }
    
    //receive CTS response
    char ctsResp[1024];
    n = recvfrom(sockfd, ctsResp, sizeof(ctsResp), 0, (struct sockaddr *)&servaddr, &addrLen);
    if(n < 0){
        perror("recvfrom failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    printf("Client: Received CTS Response (%d bytes) from AP.\n", n);
    
    //validate start of frame and end for CTS response
    if ((unsigned char)ctsResp[0] != 0xFF || (unsigned char)ctsResp[1] != 0xFF) {
        printf("Invalid start-of-frame identifier in CTS Response.\n");
    }
    if ((unsigned char)ctsResp[n-2] != 0xFF || (unsigned char)ctsResp[n-1] != 0xFF) {
        printf("Invalid end-of-frame identifier in CTS Response.\n");
    }
    
    //recalculate FCS for CTS response (skip last 6 bytes)
    uint32_t ctsRespComputedFCS = getCheckSumValue(ctsResp, n, 0, 6);
    int ctsRespFcsPos = n - 6;
    uint32_t ctsRespReceivedFCS = ((unsigned char)ctsResp[ctsRespFcsPos] << 24) |
                                    ((unsigned char)ctsResp[ctsRespFcsPos+1] << 16) |
                                    ((unsigned char)ctsResp[ctsRespFcsPos+2] << 8) |
                                    ((unsigned char)ctsResp[ctsRespFcsPos+3]);
    if(ctsRespComputedFCS != ctsRespReceivedFCS){
        printf("FCS mismatch in CTS Response: computed %u, received %u\n", ctsRespComputedFCS, ctsRespReceivedFCS);
        close(sockfd);
        exit(EXIT_FAILURE);
    } else {
        printf("Client: CTS Response FCS verified successfully: %u.\n", ctsRespComputedFCS);
    }

    //send data frame
    char dataFrame[100];
    int dOffset = 0;

    //start frame ID
    dataFrame[dOffset++] = 0xFF;
    dataFrame[dOffset++] = 0xFF;

    //data frame: Set Type = 10, Subtype = 0000.
    //for type=10 (binary 10 for the type field with protocol version=0, subtype=0000) -> 0x20
    //for client to AP, set ToDS=1, FromDS=0 => second byte = 0x01.
    dataFrame[dOffset++] = 0x20;
    dataFrame[dOffset++] = 0x01;

    //duration ID = 2 (0x0002)
    dataFrame[dOffset++] = 0x00;
    dataFrame[dOffset++] = 0x02;

    //address 1 receiver (AP): AABBCCDDEEDD
    unsigned char apMAC_Data[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xDD};
    memcpy(dataFrame + dOffset, apMAC_Data, 6);
    dOffset += 6;

    //address 2 source (client): 1245CCDDEE88
    unsigned char clientMAC_Data[6] = {0x12, 0x45, 0xCC, 0xDD, 0xEE, 0x88};
    memcpy(dataFrame + dOffset, clientMAC_Data, 6);
    dOffset += 6;

    //address 3 AP (AABBCCDDEEDD)
    memcpy(dataFrame + dOffset, apMAC_Data, 6);
    dOffset += 6;

    //address 4 Bridge address (all zeros)
    unsigned char bridge_Data[6] = {0,0,0,0,0,0};
    memcpy(dataFrame + dOffset, bridge_Data, 6);
    dOffset += 6;

    //sequence Control: 0x0000
    dataFrame[dOffset++] = 0x00;
    dataFrame[dOffset++] = 0x00;

    //payload
    char *dataPayload = "DATA";
    int dataPayloadLen = strlen(dataPayload);
    memcpy(dataFrame + dOffset, dataPayload, dataPayloadLen);
    dOffset += dataPayloadLen;
    
    //reserve 4 bytes for FCS
    int dataFcsPos = dOffset;
    dataFrame[dOffset++] = 0x00;
    dataFrame[dOffset++] = 0x00;
    dataFrame[dOffset++] = 0x00;
    dataFrame[dOffset++] = 0x00;

    //end of frame ID
    dataFrame[dOffset++] = 0xFF;
    dataFrame[dOffset++] = 0xFF;

    int dataFrameSize = dOffset;
    uint32_t dataChecksum = getCheckSumValue(dataFrame, dataFrameSize, 0, 6);
    dataFrame[dataFcsPos + 0] = (dataChecksum >> 24) & 0xFF;
    dataFrame[dataFcsPos + 1] = (dataChecksum >> 16) & 0xFF;
    dataFrame[dataFcsPos + 2] = (dataChecksum >> 8) & 0xFF;
    dataFrame[dataFcsPos + 3] = dataChecksum & 0xFF;

    printf("Client: Data Frame FCS computed as %u.\n", dataChecksum);

    //send the data frame
    n = sendto(sockfd, dataFrame, dataFrameSize, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
    if(n < 0){
        perror("sendto failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    } else {
        printf("Client: Data Frame sent (%d bytes) to AP.\n", dataFrameSize);
    }

    //receive ACK
    char ackResp[1024];
    n = recvfrom(sockfd, ackResp, sizeof(ackResp), 0, (struct sockaddr *)&servaddr, &addrLen);
    if(n < 0){
        perror("recvfrom failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    printf("Client: Received ACK from AP (%d bytes).\n", n);

    //validate ACK response start/end identifiers
    if ((unsigned char)ackResp[0] != 0xFF || (unsigned char)ackResp[1] != 0xFF) {
        printf("Invalid start-of-frame identifier in ACK Response.\n");
    }
    if ((unsigned char)ackResp[n-2] != 0xFF || (unsigned char)ackResp[n-1] != 0xFF) {
        printf("Invalid end-of-frame identifier in ACK Response.\n");
    }

    //recalculate FCS for ACK response (skip last 6 bytes)
    uint32_t ackRespComputedFCS = getCheckSumValue(ackResp, n, 0, 6);
    int ackRespFcsPos = n - 6;
    uint32_t ackRespReceivedFCS = ((unsigned char)ackResp[ackRespFcsPos] << 24) |
                                    ((unsigned char)ackResp[ackRespFcsPos+1] << 16) |
                                    ((unsigned char)ackResp[ackRespFcsPos+2] << 8) |
                                    ((unsigned char)ackResp[ackRespFcsPos+3]);
    if(ackRespComputedFCS != ackRespReceivedFCS){
        printf("FCS mismatch in ACK Response: computed %u, received %u\n", ackRespComputedFCS, ackRespReceivedFCS);
        close(sockfd);
        exit(EXIT_FAILURE);
    } else {
        printf("Client: ACK FCS verified successfully: %u.\n", ackRespComputedFCS);
    }

    //error data frame
    char errDataFrame[100];
    int errOffset = 0;

    //sstart frame ID
    errDataFrame[errOffset++] = 0xFF;
    errDataFrame[errOffset++] = 0xFF;

    //data frame: Set Type = 10, Subtype = 0000.
    //for type = 10 (with protocol version=0, subtype=0000) -> first byte = 0x20.
    //for client to AP, ToDS = 1, FromDS = 0 -> second byte = 0x01.
    errDataFrame[errOffset++] = 0x20;
    errDataFrame[errOffset++] = 0x01;

    //duration ID = 2 (0x0002)
    errDataFrame[errOffset++] = 0x00;
    errDataFrame[errOffset++] = 0x02;

    //address 1 receiver (AP): AABBCCDDEEDD
    unsigned char apMAC_EData[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xDD};
    memcpy(errDataFrame + errOffset, apMAC_EData, 6);
    errOffset += 6;

    //address 2 source (client): 1245CCDDEE88
    unsigned char clientMAC_EData[6] = {0x12, 0x45, 0xCC, 0xDD, 0xEE, 0x88};
    memcpy(errDataFrame + errOffset, clientMAC_EData, 6);
    errOffset += 6;

    //address 3 AP address (AABBCCDDEEDD)
    memcpy(errDataFrame + errOffset, apMAC_Data, 6);
    errOffset += 6;

    //address 4 Bridge address (all zeros)
    unsigned char bridge_EData[6] = {0,0,0,0,0,0};
    memcpy(errDataFrame + errOffset, bridge_EData, 6);
    errOffset += 6;

    //sequence control: 0x0000
    errDataFrame[errOffset++] = 0x00;
    errDataFrame[errOffset++] = 0x00;

    //payload
    char *errDataPayload = "DATA_ERROR";
    int errDataPayloadLen = strlen(errDataPayload);
    memcpy(errDataFrame + errOffset, errDataPayload, errDataPayloadLen);
    errOffset += errDataPayloadLen;

    // Reserve 4 bytes for FCS
    int errFcsPos = errOffset;
    errDataFrame[errOffset++] = 0x00;
    errDataFrame[errOffset++] = 0x00;
    errDataFrame[errOffset++] = 0x00;
    errDataFrame[errOffset++] = 0x00;

    //end of frame ID
    errDataFrame[errOffset++] = 0xFF;
    errDataFrame[errOffset++] = 0xFF;

    int errDataFrameSize = errOffset;
    uint32_t errDataChecksum = getCheckSumValue(errDataFrame, errDataFrameSize, 0, 6);

    //change the FCS
    errDataChecksum += 1;

    //insert false FCS
    errDataFrame[errFcsPos + 0] = (errDataChecksum >> 24) & 0xFF;
    errDataFrame[errFcsPos + 1] = (errDataChecksum >> 16) & 0xFF;
    errDataFrame[errFcsPos + 2] = (errDataChecksum >> 8) & 0xFF;
    errDataFrame[errFcsPos + 3] = errDataChecksum & 0xFF;

    printf("Client: Built Error Data Frame. Correct FCS should be %u, but using error FCS: %u.\n",
        getCheckSumValue(errDataFrame, errDataFrameSize, 0, 6), errDataChecksum);

    //send the error data frame
    n = sendto(sockfd, errDataFrame, errDataFrameSize, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
    if(n < 0){
        perror("sendto failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    } else {
        printf("Client: Error Data Frame sent (%d bytes) to AP.\n", errDataFrameSize);
    }

    //receive the error message from the AP
    char errResp[1024];
    n = recvfrom(sockfd, errResp, sizeof(errResp), 0, (struct sockaddr *)&servaddr, &addrLen);
    if(n < 0){
        perror("recvfrom failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    printf("Client: Received error response from AP: %s\n", errResp);

    //multiple frames
    char multiRTS[100];
    int mOffset = 0;

    //start frame ID
    multiRTS[mOffset++] = 0xFF;
    multiRTS[mOffset++] = 0xFF;

    //RTS: Type = 01, Subtype = 1011 0x1B for first byte second byte = 0x01 (client->AP)
    multiRTS[mOffset++] = 0x1B;
    multiRTS[mOffset++] = 0x01;

    //duration ID = 12 (0x000C)
    multiRTS[mOffset++] = 0x00;
    multiRTS[mOffset++] = 0x0C;

    //addresses 1
    unsigned char apMAC_M[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xDD};
    memcpy(multiRTS + mOffset, apMAC_M, 6); 
    mOffset += 6;

    //address 2
    unsigned char clientMAC_M[6] = {0x12,0x45,0xCC,0xDD,0xEE,0x88};
    memcpy(multiRTS + mOffset, clientMAC_M, 6); 
    mOffset += 6;

    //address 3
    memcpy(multiRTS + mOffset, apMAC_M, 6); 
    mOffset += 6;

    //address 4
    unsigned char bridge_M[6] = {0,0,0,0,0,0};
    memcpy(multiRTS + mOffset, bridge_M, 6); 
    mOffset += 6;

    //sequence control (0x0000)
    multiRTS[mOffset++] = 0x00; 
    multiRTS[mOffset++] = 0x00;

    //payload
    char *rtsPayloadM = "RTS_MULTI";
    int rtsPayloadMLen = strlen(rtsPayloadM);
    memcpy(multiRTS + mOffset, rtsPayloadM, rtsPayloadMLen); 
    mOffset += rtsPayloadMLen;

    // Reserve 4 bytes for FCS
    int multiRTSFcsPos = mOffset;
    multiRTS[mOffset++] = 0x00; 
    multiRTS[mOffset++] = 0x00; 
    multiRTS[mOffset++] = 0x00; 
    multiRTS[mOffset++] = 0x00;

    //end of frame ID
    multiRTS[mOffset++] = 0xFF; 
    multiRTS[mOffset++] = 0xFF;

    //send the multi RTS frame
    int multiRTSSize = mOffset;
    uint32_t multiRTSChecksum = getCheckSumValue(multiRTS, multiRTSSize, 0, 6);

    //insert the FCS
    multiRTS[multiRTSFcsPos+0] = (multiRTSChecksum >> 24) & 0xFF;
    multiRTS[multiRTSFcsPos+1] = (multiRTSChecksum >> 16) & 0xFF;
    multiRTS[multiRTSFcsPos+2] = (multiRTSChecksum >> 8) & 0xFF;
    multiRTS[multiRTSFcsPos+3] = multiRTSChecksum & 0xFF;

    n = sendto(sockfd, multiRTS, multiRTSSize, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
    if(n < 0){ 
        perror("sendto RTS failed"); exit(EXIT_FAILURE); 
    } else { 
        printf("Client: Multi-Frame RTS sent with Duration ID 12, FCS computed as %u (frame size: %d bytes).\n", multiRTSChecksum, multiRTSSize);
    }

    //step 2: send 5 fragmented (correct) data frames with decreasing Duration IDs.
    for (int i = 0; i < 5; i++) {
        char fragFrame[100];
        int fOffset = 0;

        //start of Frame ID
        fragFrame[fOffset++] = 0xFF; 
        fragFrame[fOffset++] = 0xFF;

        //data frame: Type = 10, Subtype = 0000 -> first byte = 0x20, second = 0x01.
        fragFrame[fOffset++] = 0x20; 
        fragFrame[fOffset++] = 0x01;

        //duration ID: start at 12 and decrement per fragment.
        uint16_t duration = 12 - i; 
        fragFrame[fOffset++] = (duration >> 8) & 0xFF;
        fragFrame[fOffset++] = duration & 0xFF;

        //addresses same as previous data frame.
        memcpy(fragFrame + fOffset, apMAC_Data, 6); 
        fOffset += 6;
        memcpy(fragFrame + fOffset, clientMAC_Data, 6); 
        fOffset += 6;
        memcpy(fragFrame + fOffset, apMAC_Data, 6); 
        fOffset += 6;
        memcpy(fragFrame + fOffset, bridge_Data, 6); 
        fOffset += 6;

        //sequence control (0x0000)
        fragFrame[fOffset++] = 0x00; 
        fragFrame[fOffset++] = 0x00;
        
        //payload
        char payloadFrag[50];
        sprintf(payloadFrag, "DATA_MULTI_CORRECT_%d", i+1);
        int payloadFragLen = strlen(payloadFrag);
        memcpy(fragFrame + fOffset, payloadFrag, payloadFragLen);
        fOffset += payloadFragLen;

        //reserve 4 bytes for FCS
        int fragFcsPos = fOffset;
        fragFrame[fOffset++] = 0x00; 
        fragFrame[fOffset++] = 0x00; 
        fragFrame[fOffset++] = 0x00; 
        fragFrame[fOffset++] = 0x00;
        fragFrame[fOffset++] = 0xFF; 
        fragFrame[fOffset++] = 0xFF;

        int fragFrameSize = fOffset;
        uint32_t fragChecksum = getCheckSumValue(fragFrame, fragFrameSize, 0, 6);
        fragFrame[fragFcsPos+0] = (fragChecksum >> 24) & 0xFF;
        fragFrame[fragFcsPos+1] = (fragChecksum >> 16) & 0xFF;
        fragFrame[fragFcsPos+2] = (fragChecksum >> 8) & 0xFF;
        fragFrame[fragFcsPos+3] = fragChecksum & 0xFF;
        printf("Client: Fragment %d prepared with Duration ID %d, FCS = %u.\n", i+1, duration, fragChecksum);

        //rretransmission with timer and retry counter
        int retry = 0;
        int ackReceived = 0;
        while(retry < 3 && !ackReceived) {
            n = sendto(sockfd, fragFrame, fragFrameSize, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
            if(n < 0){ 
                perror("sendto frag failed"); 
                exit(EXIT_FAILURE); 
            }

            printf("Client: Sending Fragment %d (attempt %d).\n", i+1, retry+1);
            n = recvfrom(sockfd, resp, sizeof(resp), 0, (struct sockaddr *)&servaddr, &addrLen);
            if(n > 0) {
                uint32_t ackComputed = getCheckSumValue(resp, n, 0, 6);
                int ackFcsPos = n - 6;
                uint32_t ackReceivedChecksum = ((unsigned char)resp[ackFcsPos] << 24) |
                                               ((unsigned char)resp[ackFcsPos+1] << 16) |
                                               ((unsigned char)resp[ackFcsPos+2] << 8) |
                                               ((unsigned char)resp[ackFcsPos+3]);
                if(ackComputed == ackReceivedChecksum) {
                    printf("Client: ACK received for Fragment %d.\n", i+1);
                    ackReceived = 1;
                } else {
                    printf("Client: Fragment %d ACK FCS mismatch on attempt %d.\n", i+1, retry+1);
                }
            } else {
                printf("Client: No ACK received for Fragment %d on attempt %d.\n", i+1, retry+1);
            }
            retry++;
        }
        if(!ackReceived) {
            printf("Client: Final status - No ACK received from AP for Fragment %d after 3 attempts.\n", i+1);
        }
    }

    //step 3: send another 5 fragmented frames, with one correct and four error.
    for (int i = 0; i < 5; i++) {
        char fragFrame[100];
        int fOffset = 0;

        //start frame ID
        fragFrame[fOffset++] = 0xFF; 
        fragFrame[fOffset++] = 0xFF;

        //data frame: Type = 10, Subtype = 0000 -> first byte = 0x20, second = 0x01.
        fragFrame[fOffset++] = 0x20; 
        fragFrame[fOffset++] = 0x01;

        //duration ID: start at 8 and decrement per fragment.
        uint16_t duration = 8 - i;
        fragFrame[fOffset++] = (duration >> 8) & 0xFF;
        fragFrame[fOffset++] = duration & 0xFF;

        //addresses
        memcpy(fragFrame + fOffset, apMAC_Data, 6); 
        fOffset += 6;
        memcpy(fragFrame + fOffset, clientMAC_Data, 6); 
        fOffset += 6;
        memcpy(fragFrame + fOffset, apMAC_Data, 6); 
        fOffset += 6;
        memcpy(fragFrame + fOffset, bridge_Data, 6); 
        fOffset += 6;

        //sequence control (0x0000)
        fragFrame[fOffset++] = 0x00; 
        fragFrame[fOffset++] = 0x00;

        //payload
        char payloadFrag[50];
        if(i == 2){
            sprintf(payloadFrag, "DATA_MULTI_CORRECT_%d", i+1);
        } else {
            sprintf(payloadFrag, "DATA_MULTI_ERROR_%d", i+1);
        }

        int payloadFragLen = strlen(payloadFrag);
        memcpy(fragFrame + fOffset, payloadFrag, payloadFragLen);
        fOffset += payloadFragLen;

        //reserve 4 bytes for FCS
        int fragFcsPos = fOffset;
        fragFrame[fOffset++] = 0x00; 
        fragFrame[fOffset++] = 0x00; 
        fragFrame[fOffset++] = 0x00; 
        fragFrame[fOffset++] = 0x00;
        fragFrame[fOffset++] = 0xFF; 
        fragFrame[fOffset++] = 0xFF;
        int fragFrameSize = fOffset;

        uint32_t fragChecksum = getCheckSumValue(fragFrame, fragFrameSize, 0, 6);
        //corrupt FCS for error frames
        if(i != 2){
            fragChecksum += 1;
        }

        fragFrame[fragFcsPos+0] = (fragChecksum >> 24) & 0xFF;
        fragFrame[fragFcsPos+1] = (fragChecksum >> 16) & 0xFF;
        fragFrame[fragFcsPos+2] = (fragChecksum >> 8) & 0xFF;
        fragFrame[fragFcsPos+3] = fragChecksum & 0xFF;

        printf("Client: Multi Data Fragment %d prepared with Duration ID %d, FCS = %u.\n", i+1, duration, fragChecksum);
        
        int retry = 0;
        int ackReceived = 0;
        
        while(retry < 3 && !ackReceived) {
            n = sendto(sockfd, fragFrame, fragFrameSize, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
            if(n < 0) { 
                perror("sendto frag failed"); 
                exit(EXIT_FAILURE); 
            }

            printf("Client: Sending Multi Data Fragment %d (attempt %d).\n", i+1, retry+1);
            n = recvfrom(sockfd, resp, sizeof(resp), 0, (struct sockaddr *)&servaddr, &addrLen);
            if(n > 0) {
                uint32_t ackComputed = getCheckSumValue(resp, n, 0, 6);
                int ackFcsPos = n - 6;
                uint32_t ackReceivedChecksum = ((unsigned char)resp[ackFcsPos] << 24) |
                                               ((unsigned char)resp[ackFcsPos+1] << 16) |
                                               ((unsigned char)resp[ackFcsPos+2] << 8) |
                                               ((unsigned char)resp[ackFcsPos+3]);
                if(ackComputed == ackReceivedChecksum) {
                    printf("Client: ACK received for Multi Data Fragment %d.\n", i+1);
                    ackReceived = 1;
                } else {
                    printf("Client: Multi Data Fragment %d ACK FCS mismatch on attempt %d.\n", i+1, retry+1);
                }
            } else {
                printf("Client: Final status - No ACK received for Multi Data Fragment %d after 3 attempts.\n", i+1);
            }
            retry++;
        }
        if(!ackReceived) {
            printf("No ACK received from AP for Multi Data Fragment %d.\n", i+1);
        }
    }

    close(sockfd);
    return 0;
}