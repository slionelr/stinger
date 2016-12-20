#include "base_commands.h"

DWORD remote_request_core_console_write(Remote *remote, Packet *packet) {
    return ERROR_SUCCESS;
}

DWORD remote_response_core_console_write(Remote *remote, Packet *packet) {
    return ERROR_SUCCESS;
}

DWORD remote_request_echo(Remote *remote, Packet *packet, PacketRequestCompletion *completionRoutine)
{
    DWORD res = ERROR_SUCCESS;
    Packet *response = packet_create_response(packet);

    do
    {
        LPCSTR stam = packet_get_tlv_value_string(packet, TLV_TYPE_DATA);

        packet_add_tlv_string(response, TLV_TYPE_DATA, stam);

        PACKET_TRANSMIT(remote, response, completionRoutine);
//        packet_transmit_response(res, remote, response);

    } while (0);

    return res;
}

DWORD remote_response_echo(Remote *remote, Packet *packet) {
    DWORD res = ERROR_SUCCESS;
    packet_add_tlv_string(packet, TLV_TYPE_CIPHER_NAME, "LALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALALA");
    PACKET_TRANSMIT(remote, packet, NULL);
    return res;
}

/// THIS IS AN EXAMPLE FOR A COMMAND
/*
 * core_channel_open (response)
 * -----------------
 *
 * Handles the response to a request to open a channel.
 *
 * This function takes the supplied channel identifier and creates a
 * channel list entry with it.
 *
 * req: TLV_TYPE_CHANNEL_ID -- The allocated channel identifier
 */
//DWORD remote_response_core_channel_open(Remote *remote, Packet *packet)
//{
//    DWORD res = ERROR_SUCCESS, channelId;
//    Channel *newChannel;
//
//    do
//    {
//        channelId = packet_get_tlv_value_uint(packet, TLV_TYPE_CHANNEL_ID);
//
//        // DId the request fail?
//        if (!channelId)
//        {
//            res = ERROR_NOT_ENOUGH_MEMORY;
//            break;
//        }
//
//        // Create a local instance of the channel with the supplied identifier
//        if (!(newChannel = channel_create(channelId, 0)))
//        {
//            res = ERROR_NOT_ENOUGH_MEMORY;
//            break;
//        }
//
//    } while (0);
//
//    return res;
//}
