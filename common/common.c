//
// Created by messi on 12/6/16.
//

#include "types.h"
#include "common.h"
#include "base_commands.h"

#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <pthread.h>

#ifdef _BSD
#include <netinet/in.h>
#endif

int local_error;

VOID client_connection(Remote *remote);

Remote *gen_Remote() {
    Remote *remote = (Remote *) malloc(sizeof(Remote));
    remote->connect = remote_connect;
    remote->transmit = packet_transmit;
    remote->receive = packet_receive;
    remote->lock = lock_create();
    return remote;
}

BOOL local_bind(DWORD port) {
    DWORD err;
    SOCKET local;
    pthread_t tmp;

    printf("[COMMON] START server.\n");

    if ((local = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("ERROR on create socket\n");
        return FALSE;
    }

    struct sockaddr_in local_addr, cli_addr;
    bzero(&local_addr, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(port);
    local_addr.sin_addr.s_addr = INADDR_ANY;
    if ((err = bind(local, (struct sockaddr *) &local_addr, sizeof(local_addr))) < 0) {
        printf("[COMMON] Error on bind, code=%d\n", err);
        printf("ERROR on bind\n");
        return FALSE;
    }

    listen(local, 1);
    int clilen = sizeof(cli_addr);

    printf("[COMMON] Wating for client connections.\n");
    do {
        SOCKET newsockfd = accept(local, (struct sockaddr *) &cli_addr, &clilen);
        if (newsockfd < 0) {
            printf("ERROR on accept\n");
            return FALSE;
        }

        printf("[COMMON] Established a connection with a new client\n");

        Remote *remote = gen_Remote();
        LPSTR client_ip_address = (LPSTR) malloc(INET_ADDRSTRLEN);
        remote->address = inet_ntop(AF_INET,
                                    &cli_addr.sin_addr,
                                    client_ip_address,
                                    sizeof(cli_addr.sin_addr));
        remote->port = ntohs(cli_addr.sin_port);
        remote->sock = newsockfd;

        printf("[COMMON] Creating the thread that will handle this new client.\n");
        pthread_create(&tmp, NULL, client_connection, remote);
//    client_connection(remote);

        // Clean before reuse
        memset(&tmp, 0, sizeof(pthread_t));
        memset(&cli_addr, 0, sizeof(struct sockaddr_in));
        newsockfd = -1;
    } while (TRUE);

    return TRUE;
}

VOID client_connection(Remote *remote) {
    Packet *packet = NULL;
    DWORD res = ERROR_SUCCESS;

    printf("[COMMON] client_connection handler in new thread\n", remote->address, remote->port, res);
    do {
        res = ERROR_SUCCESS;
        if ((res = packet_receive(remote, &packet)) < 0) {
            printf("[COMMON] Packet receive from client[%s:%d] with error:%d\n", remote->address, remote->port, res);
            return;
        }

        if (!command_handle(remote, packet)) {
            printf("[COMMON] Command handle of client connection [%s:%d] failed.\n", remote->address, remote->port);
            return;
        }
    } while (TRUE);
}

BOOL remote_connect(Remote *remote) {
    if ((remote->sock = socket(AF_INET, SOCK_STREAM, 0) < 0)) {
        // TODO: handle error
    }

    struct sockaddr_in remote_addr;
    bzero(&remote_addr, sizeof(remote_addr));
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(remote->port);
    if (inet_pton(AF_INET, remote->address, &remote_addr.sin_addr) < 0) {
        // TODO: handle error
        printf("ERROR on inet_pton\n");
        return FALSE;
    }

    if ((remote->sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("ERROR on create socket\n");
        return FALSE;
    }

    if (connect(remote->sock, (struct sockaddr *) &remote_addr, sizeof(remote_addr)) < 0) {
        printf("ERROR on connecting to target\n");
        return FALSE;
    }

    return remote;
}

/*!
 * @brief Transmit a packet via SSL _and_ destroy it.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the \c Packet that is to be sent.
 * @param completion Pointer to the completion routines to process.
 * @return An indication of the result of processing the transmission request.
 * @remark This uses an SSL-encrypted TCP channel, and does not imply the use of HTTPS.
 */
static DWORD packet_transmit(Remote *remote, Packet *packet, PacketRequestCompletion *completion) {
    Tlv requestId;
    DWORD res;
    DWORD idx;
    Packet *response = packet_create_response(packet);

    lock_acquire(remote->lock);

    // If the packet does not already have a request identifier, create one for it
    if (packet_get_tlv_string(packet, TLV_TYPE_REQUEST_ID, &requestId) != ERROR_SUCCESS) {
        DWORD index;
        CHAR rid[32];

        rid[sizeof(rid) - 1] = 0;

        for (index = 0; index < sizeof(rid) - 1; index++) {
            rid[index] = (rand() % 0x5e) + 0x21;
        }

        packet_add_tlv_string(packet, TLV_TYPE_REQUEST_ID, rid);
    }

    do {
        idx = 0;
        while (idx < sizeof(packet->header)) {
            // Transmit the packet's header (length, type)
            printf("[PACKET-DEBUG] transmit header to sockFD:%d, bytes:%d\n", remote->sock, sizeof(packet->header) - idx);
            res = write(remote->sock,
                        (LPCSTR) (&packet->header) + idx,
                        sizeof(packet->header) - idx);

            if (res <= 0) {
                printf("[PACKET] transmit header failed with return %d at index %d\n", res, idx);
                break;
            }
            idx += res;
        }

        if (res < 0) {
            break;
        }

        idx = 0;
        while (idx < packet->payloadLength) {
            // Transmit the packet's payload (length, type)
            printf("[PACKET-DEBUG] transmit payload %d bytes.\n", packet->payloadLength - idx);
            res = write(remote->sock,
                        packet->payload + idx,
                        packet->payloadLength - idx);

            if (res < 0) {
                break;
            }

            idx += res;
        }

        if (res < 0) {
            printf("[PACKET] transmit header failed with return %d at index %d\n", res, idx);
            break;
        }

        // If a completion routine was supplied and the packet has a request
        // identifier, insert the completion routine into the list
        if ((completion) &&
            (packet_get_tlv_string(packet, TLV_TYPE_REQUEST_ID,
                                   &requestId) == ERROR_SUCCESS)) {
            //packet_add_completion_handler((LPCSTR) requestId.buffer, completion);
            LPCSTR lpMethod = packet_get_tlv_value_string(packet, TLV_TYPE_METHOD);
//            completion->routine(remote, response, NULL, lpMethod, ERROR_SUCCESS);
            completion->routine(remote, response);
        }

        SetLastError(ERROR_SUCCESS);
    } while (0);

    res = GetLastError();

    // Destroy the packet
    packet_destroy(packet);

    lock_release(remote->lock);

    return res;
}

/*!
 * @brief Receive a new packet on the given remote endpoint.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to a pointer that will receive the \c Packet data.
 * @return An indication of the result of processing the transmission request.
 */
static DWORD packet_receive(Remote *remote, Packet **packet) {
    DWORD headerBytes = 0, payloadBytesLeft = 0, res;
    Packet *localPacket = NULL;
    PacketHeader header;
    LONG bytesRead;
    BOOL inHeader = TRUE;
    PUCHAR payload = NULL;
    ULONG payloadLength;

    lock_acquire(remote->lock);

    do {
        // Read the packet length
        while (inHeader) {
            printf("[PACKET-DEBUG] going to read from socketFD:%d, readbytes:%d.\n", remote->sock, sizeof(PacketHeader) - headerBytes);
            if ((bytesRead = read(remote->sock,
                                  ((PUCHAR) &header + headerBytes),
                                  sizeof(PacketHeader) - headerBytes)) <= 0) {
//                                  1)) <= 0) {
                if (!bytesRead) {
                    SetLastError(ERROR_NOT_FOUND);
                    printf("[PACKET] receive header failed with error code %d.\n", local_error);
                }

                if (bytesRead < 0) {
                    printf("[PACKET] receive header failed with error code %d.\n", local_error);
                    SetLastError(ERROR_NOT_FOUND);
                }

                break;
            }
            printf("[PACKET-DEBUG] Received readbytes:%d.\n", bytesRead);

            headerBytes += bytesRead;

            if (headerBytes != sizeof(PacketHeader)) {
                continue;
            }

            inHeader = FALSE;
        }

        if (headerBytes != sizeof(PacketHeader)) {
            break;
        }

        // Initialize the header
        header.length = ntohl(header.length);

        // use TlvHeader size here, because the length doesn't include the xor byte
        payloadLength = header.length - sizeof(TlvHeader);
        payloadBytesLeft = payloadLength;

        // Allocate the payload
        if (!(payload = (PUCHAR) malloc(payloadLength))) {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            break;
        }

        // Read the payload
        while (payloadBytesLeft > 0) {
            if ((bytesRead = read(remote->sock,
                                  payload + payloadLength - payloadBytesLeft,
                                  payloadBytesLeft)) <= 0) {

                if (GetLastError() == WSAEWOULDBLOCK) {
                    continue;
                }

                if (!bytesRead) {
                    SetLastError(ERROR_NOT_FOUND);
                }

                if (bytesRead < 0) {
                    printf("[PACKET] receive payload of length %d failed with error code %d.\n", payloadLength,
                           bytesRead);
                    SetLastError(ERROR_NOT_FOUND);
                }

                break;
            }

            payloadBytesLeft -= bytesRead;
        }

        // Didn't finish?
        if (payloadBytesLeft) {
            break;
        }

        // Allocate a packet structure
        if (!(localPacket = (Packet *) malloc(sizeof(Packet)))) {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            break;
        }

        memset(localPacket, 0, sizeof(Packet));

        localPacket->header.length = header.length;
        localPacket->header.type = header.type;
        localPacket->payload = payload;
        localPacket->payloadLength = payloadLength;

        *packet = localPacket;

        SetLastError(ERROR_SUCCESS);

    } while (0);

    res = GetLastError();

    // Cleanup on failure
    if (res != ERROR_SUCCESS) {
        if (payload) {
            free(payload);
        }
        if (localPacket) {
            free(localPacket);
        }
    }

    lock_release(remote->lock);

    return -res;
}
