//
// Created by messi on 12/6/16.
//

#include "core.h"

#include <string.h>
#include <netinet/in.h>
#include <stdlib.h>

/*!
 * @brief Reference to the list of packet completion routines.
 * @details This pointer is a singularly-linked list which contains references
 *          to PacketCompletionRouteEntry items, each of which is processed
 *          when packet_call_completion_handlers is invoked.
 */
PacketCompletionRoutineEntry *packetCompletionRoutineList = NULL;

/*!
 * @brief Enumerate TLV entries until hitting a given index or type.
 * @details This function will iterate through the given payload until one of the following conditions is true:
 *             - The end of the payload is encountered
 *             - The specified index is reached
 *             - A TLV of the specified type is reached
 *
 *          If the first condition is met, the function returns with a failure.
 * @param packet Pointer to the packet to get the TLV from.
 * @param payload Pointer to the payload to parse.
 * @param index Index of the TLV entry to find (optional).
 * @param type Type of TLV to get (optional).
 * @param tlv Pointer to the TLV that will receive the data.
 * @return Indication of success or failure.
 * @retval ERROR_SUCCESS The operation completed successfully.
 * @retval ERROR_NOT_FOUND Unable to find the TLV.
 */
DWORD packet_find_tlv_buf(Packet *packet, PUCHAR payload, DWORD payloadLength, DWORD index, TlvType type, Tlv *tlv) {
    DWORD currentIndex = 0;
    DWORD offset = 0, length = 0;
    BOOL found = FALSE;
    PUCHAR current;

    memset(tlv, 0, sizeof(Tlv));

    do {
        // Enumerate the TLV's
        for (current = payload, length = 0; !found && current; offset += length, current += length) {
            TlvHeader *header = (TlvHeader *) current;
            TlvType current_type = TLV_TYPE_ANY; // effectively '0'

            if ((current + sizeof(TlvHeader) > payload + payloadLength) || (current < payload)) {
                break;
            }

            // TLV's length
            length = ntohl(header->length);

            // Matching type?
            current_type = (TlvType) ntohl(header->type);

            // if the type has been compressed, temporarily remove the compression flag as compression is to be transparent.
            if ((current_type & TLV_META_TYPE_COMPRESSED) == TLV_META_TYPE_COMPRESSED) {
                current_type = (TlvType) (current_type ^ TLV_META_TYPE_COMPRESSED);
            }

            // check if the types match?
            if ((current_type != type) && (type != TLV_TYPE_ANY)) {
                continue;
            }

            // Matching index?
            if (currentIndex != index) {
                currentIndex++;
                continue;
            }

            if ((current + length > payload + payloadLength) || (current < payload)) {
                break;
            }

            tlv->header.type = ntohl(header->type);
            tlv->header.length = ntohl(header->length) - sizeof(TlvHeader);
            tlv->buffer = payload + offset + sizeof(TlvHeader);

            found = TRUE;
        }

    } while (0);

    return (found) ? ERROR_SUCCESS : ERROR_NOT_FOUND;
}

/*!
 * @brief Enumerate a TLV (with the option of constraining its type).
 * @param packet Pointer to the packet to get the TLV from.
 * @param type Type of TLV to get (optional).
 * @param tlv Pointer to the TLV that will receive the data.
 * @return Indication of success or failure.
 * @retval ERROR_SUCCESS The operation completed successfully.
 * @retval ERROR_NOT_FOUND Unable to find the TLV.
 */
DWORD packet_enum_tlv(Packet *packet, DWORD index, TlvType type, Tlv *tlv) {
    return packet_find_tlv_buf(packet, packet->payload, packet->payloadLength, index, type, tlv);
}

/*!
 * @brief Get a TLV of a given type from the packet.
 * @param packet Pointer to the packet to get the TLV from.
 * @param type Type of TLV to get.
 * @param tlv Pointer to the TLV that will receive the data.
 * @return Indication of success or failure.
 * @retval ERROR_SUCCESS The operation completed successfully.
 * @retval ERROR_NOT_FOUND Unable to find the TLV.
 */
DWORD packet_get_tlv(Packet *packet, TlvType type, Tlv *tlv) {
    return packet_enum_tlv(packet, 0, type, tlv);
}

/*!
 * @brief Get a string TLV from the packet.
 * @param packet Pointer to the packet to get the TLV from.
 * @param type Type of TLV to get.
 * @param tlv Pointer to the TLV that will receive the data.
 * @return Indication of success or failure.
 * @retval ERROR_SUCCESS The operation completed successfully.
 * @retval ERROR_NOT_FOUND Unable to find the TLV or the string
 *                         value is not NULL-terminated.
 */
DWORD packet_get_tlv_string(Packet *packet, TlvType type, Tlv *tlv) {
    DWORD res;

    if ((res = packet_get_tlv(packet, type, tlv)) == ERROR_SUCCESS) {
        res = packet_is_tlv_null_terminated(tlv);
    }

    return res;
}

/*!
 * @brief Add a string value TLV to a packet, including the \c NULL terminator.
 * @param packet Pointer to the packet to add the value to.
 * @param type TLV type for the value.
 * @param str Pointer to the string value to add to the packet.
 * @return Indication of success or failure.
 * @retval ERROR_SUCCESS The operation completed successfully.
 * @retval ERROR_NOT_ENOUGH_MEMORY Insufficient memory available.
 */
DWORD packet_add_tlv_string(Packet *packet, TlvType type, LPCSTR str) {
    return packet_add_tlv_raw(packet, type, (PUCHAR) str, (DWORD) strlen(str) + 1);
}

/*!
 * @brief Destroy the packet context and the payload buffer.
 * @param packet Pointer to the \c Packet to destroy.
 */
VOID packet_destroy(Packet *packet) {
    if (packet == NULL) {
        return;
    }

    if (packet->payload) {
        memset(packet->payload, 0, packet->payloadLength);
        free(packet->payload);
    }

    memset(packet, 0, sizeof(Packet));

    free(packet);
}

/*!
 * @brief Check if a TLV is NULL-terminated.
 * @details The function checks the data within the range of bytes specified by
 *         the \c length property of the TLV \c header.
 * @param tlv Pointer to the TLV to check.
 * @return Indication of whether the TLV is terminated with a \c NULL byte or not.
 * @retval ERROR_SUCCESS A \c NULL byte is present.
 * @retval ERROR_NOT_FOUND No \c NULL byte is present.
 * @sa TlvHeader
 */
DWORD packet_is_tlv_null_terminated(Tlv *tlv) {
    if ((tlv->header.length) && (tlv->buffer[tlv->header.length - 1] != 0)) {
        return ERROR_NOT_FOUND;
    }

    return ERROR_SUCCESS;
}

/*!
 * @brief Add an arbitrary raw value TLV to a packet.
 * @details The value given in the \c buf parameter will _not_ be compressed.
 * @param packet Pointer to the packet to add the value to.
 * @param type TLV type for the value.
 * @param buf Pointer to the data that is to be added.
 * @param length Number of bytes in \c buf to add.
 * @return Indication of success or failure.
 * @retval ERROR_SUCCESS The operation completed successfully.
 * @retval ERROR_NOT_ENOUGH_MEMORY Insufficient memory available.
 */
DWORD packet_add_tlv_raw(Packet *packet, TlvType type, LPVOID buf, DWORD length) {
    DWORD headerLength = sizeof(TlvHeader);
    DWORD realLength = length + headerLength;
    DWORD newPayloadLength = packet->payloadLength + realLength;
    PUCHAR newPayload = NULL;

    // Allocate/Reallocate the packet's payload
    if (packet->payload) {
        newPayload = (PUCHAR) realloc(packet->payload, newPayloadLength);
    } else {
        newPayload = (PUCHAR) malloc(newPayloadLength);
    }

    if (!newPayload) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    // Populate the new TLV
    ((LPDWORD) (newPayload + packet->payloadLength))[0] = htonl(realLength);
    ((LPDWORD) (newPayload + packet->payloadLength))[1] = htonl((DWORD) type);

    memcpy(newPayload + packet->payloadLength + headerLength, buf, length);

    // Update the header length and payload length
    packet->header.length = htonl(ntohl(packet->header.length) + realLength);
    packet->payload = newPayload;
    packet->payloadLength = newPayloadLength;

    return ERROR_SUCCESS;
}

/*!
 * @brief Add a completion routine for a given request identifier.
 * @return Indication of success or failure.
 * @retval ERROR_NOT_ENOUGH_MEMORY Unable to allocate memory for the \c PacketCompletionRouteEntry instance.
 * @retval ERROR_SUCCESS Addition was successful.
 */
DWORD packet_add_completion_handler(LPCSTR requestId, PacketRequestCompletion *completion) {
    PacketCompletionRoutineEntry *entry;
    DWORD res = ERROR_SUCCESS;

    do {
        // Allocate the entry
        if (!(entry = (PacketCompletionRoutineEntry *) malloc(sizeof(PacketCompletionRoutineEntry)))) {
            res = ERROR_NOT_ENOUGH_MEMORY;
            break;
        }

        // Copy the completion routine information
        memcpy(&entry->handler, completion, sizeof(PacketRequestCompletion));

        // Copy the request identifier
        if (!(entry->requestId = _strdup(requestId))) {
            res = ERROR_NOT_ENOUGH_MEMORY;

            free(entry);

            break;
        }

        // Add the entry to the list
        entry->next = packetCompletionRoutineList;
        packetCompletionRoutineList = entry;

    } while (0);

    return res;
}

/*!
 * @brief Call the register completion handler(s) for the given request identifier.
 * @details Only those handlers that match the given request are executed.
 * @param remote Pointer to the \c Remote instance for this call.
 * @param response Pointer to the response \c Packet.
 * @param requestId ID of the request to execute the completion handlers of.
 * @return Indication of success or failure.
 * @retval ERROR_NOT_FOUND Unable to find any matching completion handlers for the request.
 * @retval ERROR_SUCCESS Execution was successful.
 */
DWORD packet_call_completion_handlers(Remote *remote, Packet *response, LPCSTR requestId) {
    PacketCompletionRoutineEntry *current;
    DWORD result = packet_get_tlv_value_uint(response, TLV_TYPE_RESULT);
    DWORD matches = 0;
    Tlv methodTlv;
    LPCSTR method = NULL;

    // Get the method associated with this packet
    if (packet_get_tlv_string(response, TLV_TYPE_METHOD, &methodTlv) == ERROR_SUCCESS) {
        method = (LPCSTR) methodTlv.buffer;
    }

    // Enumerate the completion routine list
    for (current = packetCompletionRoutineList; current; current = current->next) {
        // Does the request id of the completion entry match the packet's request
        // id?
        if (strcmp(requestId, current->requestId)) {
            continue;
        }

        // Call the completion routine
        // TODO: current->handler.routine(remote, response, current->handler.context, method, result);

        // Increment the number of matched handlers
        matches++;
    }

    if (matches) {
        packet_remove_completion_handler(requestId);
    }

    return (matches > 0) ? ERROR_SUCCESS : ERROR_NOT_FOUND;
}

/*!
 * @brief Get the string value of a TLV.
 * @param packet Pointer to the packet to get the TLV from.
 * @param type Type of TLV to get (optional).
 * @return Pointer to the string value, if found.
 * @retval NULL The string value was not found in the TLV.
 * @retval Non-NULL Pointer to the string value.
 */
PCHAR packet_get_tlv_value_string( Packet *packet, TlvType type ) {
    Tlv stringTlv;
    PCHAR string = NULL;

    if (packet_get_tlv_string(packet, type, &stringTlv) == ERROR_SUCCESS)
    {
        string = (PCHAR)stringTlv.buffer;
    }

    return string;
}

/*!
 * @brief Get the unsigned int value of a TLV.
 * @param packet Pointer to the packet to get the TLV from.
 * @param type Type of TLV to get (optional).
 * @return The value found in the TLV.
 * @todo On failure, 0 is returned. We need to make sure this is the right
 *       thing to do because 0 might also be a valid value.
 */
UINT packet_get_tlv_value_uint(Packet *packet, TlvType type) {
    Tlv uintTlv;

    if ((packet_get_tlv(packet, type, &uintTlv) != ERROR_SUCCESS) || (uintTlv.header.length < sizeof(DWORD))) {
        return 0;
    }

    return ntohl(*(LPDWORD) uintTlv.buffer);
}

/*!
 * @brief Remove a set of completion routine handlers for a given request identifier.
 * @param requestId ID of the request.
 * @return \c ERROR_SUCCESS is always returned.
 */
DWORD packet_remove_completion_handler(LPCSTR requestId) {
    PacketCompletionRoutineEntry *current, *next, *prev;

    // Enumerate the list, removing entries that match
    for (current = packetCompletionRoutineList, next = NULL, prev = NULL;
         current;
         prev = current, current = next) {
        next = current->next;

        if (strcmp(requestId, current->requestId)) {
            continue;
        }

        // Remove the entry from the list
        if (prev) {
            prev->next = next;
        } else {
            packetCompletionRoutineList = next;
        }

        // Deallocate it
        free((PCHAR) current->requestId);
        free(current);
    }

    return ERROR_SUCCESS;
}

/*!
 * @brief Get the boolean value of a TLV.
 * @param packet Pointer to the packet to get the TLV from.
 * @param type Type of TLV to get (optional).
 * @return The value found in the TLV.
 * @todo On failure, FALSE is returned. We need to make sure this is the right
 *       thing to do because FALSE might also be a valid value.
 */
BOOL packet_get_tlv_value_bool(Packet *packet, TlvType type)
{
    Tlv boolTlv;
    BOOL val = FALSE;

    if (packet_get_tlv(packet, type, &boolTlv) == ERROR_SUCCESS)
    {
        val = (BOOL)(*(PCHAR)boolTlv.buffer);
    }

    return val;
}

DWORD packet_get_result(Packet *packet) {
    return packet_get_tlv_value_bool(packet, TLV_TYPE_RESULT);
}