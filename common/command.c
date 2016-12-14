#include "command.h"
#include "base_commands.h"

#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>

BOOL command_is_inline(Command *command, Packet *packet);
DWORD command_validate_arguments(Command *command, Packet *packet);

/*!
 * @brief Base RPC dispatch table.
 */
Command baseCommands[] =
        {
                // Console commands
                { "core_console_write",
                  { remote_request_core_console_write, NULL, { TLV_META_TYPE_STRING }, 1 | ARGUMENT_FLAG_REPEAT },
                  { remote_response_core_console_write, NULL, EMPTY_TLV },
                },
#ifdef _DEBUG
                // Echo
                //COMMAND_INLINE_REQ("core_echo", remote_request_echo),
                COMMAND_REQ_REP("core_echo", remote_request_echo, remote_response_echo),
#endif
//
//                // Native Channel commands
//                // this overloads the "core_channel_open" in the base command list
//                COMMAND_REQ_REP("core_channel_open", remote_request_core_channel_open, remote_response_core_channel_open),
//                COMMAND_REQ("core_channel_write", remote_request_core_channel_write),
//                COMMAND_REQ_REP("core_channel_close", remote_request_core_channel_close, remote_response_core_channel_close),
//
//                // Buffered/Pool channel commands
//                COMMAND_REQ("core_channel_read", remote_request_core_channel_read),
//                // Pool channel commands
//                COMMAND_REQ("core_channel_seek", remote_request_core_channel_seek),
//                COMMAND_REQ("core_channel_eof", remote_request_core_channel_eof),
//                COMMAND_REQ("core_channel_tell", remote_request_core_channel_tell),
//                // Soon to be deprecated
//                COMMAND_REQ("core_channel_interact", remote_request_core_channel_interact),
//                // Crypto
//                COMMAND_REQ("core_crypto_negotiate", remote_request_core_crypto_negotiate),
//                // timeouts
//                COMMAND_REQ("core_transport_set_timeouts", remote_request_core_transport_set_timeouts),
//#ifdef _WIN32
//        COMMAND_REQ("core_transport_getcerthash", remote_request_core_transport_getcerthash),
//	COMMAND_REQ("core_transport_setcerthash", remote_request_core_transport_setcerthash),
//#endif
//                COMMAND_REQ("core_transport_list", remote_request_core_transport_list),
//                COMMAND_INLINE_REQ("core_transport_sleep", remote_request_core_transport_sleep),
//                COMMAND_INLINE_REQ("core_transport_change", remote_request_core_transport_change),
//                COMMAND_INLINE_REQ("core_transport_next", remote_request_core_transport_next),
//                COMMAND_INLINE_REQ("core_transport_prev", remote_request_core_transport_prev),
//                COMMAND_REQ("core_transport_add", remote_request_core_transport_add),
//                COMMAND_REQ("core_transport_remove", remote_request_core_transport_remove),
//                // Migration
//                COMMAND_INLINE_REQ("core_migrate", remote_request_core_migrate),
//                // Shutdown
//                COMMAND_INLINE_REQ("core_shutdown", remote_request_core_shutdown),
                // Terminator
                COMMAND_TERMINATOR
        };

/*!
 * @brief Dynamically registered command extensions.
 * @details A linked list of commands registered on the fly by reflectively-loaded extensions.
 */
Command* extensionCommands = NULL;

/*!
 * @brief Determine if a given command/packet combination should be invoked inline.
 * @param command Pointer to the \c Command being invoked.
 * @param packet Pointer to the \c Packet being received/sent.
 * @returns Boolean indication of whether the command should be executed inline.
 * @retval TRUE The command should be executed inline on the current thread.
 * @retval FALSE The command should be executed on a new thread.
 */
BOOL command_is_inline( Command *command, Packet *packet )
{
    switch (packet_get_type( packet ))
    {
        case PACKET_TLV_TYPE_REQUEST:
        case PACKET_TLV_TYPE_PLAIN_REQUEST:
            if (command->request.inline_handler)
                return TRUE;
        case PACKET_TLV_TYPE_RESPONSE:
        case PACKET_TLV_TYPE_PLAIN_RESPONSE:
            if (command->response.inline_handler)
                return TRUE;
    }

    return FALSE;
}

/*!
 * @brief Process a command directly on the current thread.
 * @param baseCommand Pointer to the \c Command in the base command list to be executed.
 * @param extensionCommand Pointer to the \c Command in the extension command list to be executed.
 * @param remote Pointer to the \c Remote endpoint for this command.
 * @param packet Pointer to the \c Packet containing the command detail.
 * @returns Boolean value indicating if the server should continue processing.
 * @retval TRUE The server can and should continue processing.
 * @retval FALSE The server should stop processing and shut down.
 * @sa command_handle
 * @sa command_process_thread
 * @remarks The \c baseCommand is always executed first, but if there is an \c extensionCommand
 *          then the result of the \c baseCommand processing is ignored and the result of
 *          \c extensionCommand is returned instead.
 */
BOOL command_process_inline(Command *baseCommand, Command *extensionCommand, Remote *remote, Packet *packet)
{
    DWORD result;
    BOOL serverContinue = TRUE;
    Tlv requestIdTlv;
    PCHAR requestId;
    PacketTlvType packetTlvType;
    Command *commands[2] = { baseCommand, extensionCommand };
    Command *command = NULL;
    DWORD dwIndex;
    LPCSTR lpMethod = NULL;
    PacketRequestCompletion completionRoutine;

    __try
    {
        do
        {
            for (dwIndex = 0; dwIndex < 2; ++dwIndex)
            {
                command = commands[dwIndex];

                if (command == NULL)
                {
                    continue;
                }

                lpMethod = command->method;
                printf("[COMMAND] Executing command %s\n", lpMethod);

                // Validate the arguments, if requested.  Always make sure argument
                // lengths are sane.
                if (command_validate_arguments(command, packet) != ERROR_SUCCESS)
                {
                    printf("[COMMAND] Command arguments failed to validate\n");
                    continue;
                }

                packetTlvType = packet_get_type(packet);
                switch (packetTlvType)
                {
                    case PACKET_TLV_TYPE_REQUEST:
                    case PACKET_TLV_TYPE_PLAIN_REQUEST:
                        if (command->request.inline_handler) {
                            printf("[DISPATCH] executing inline request handler %s\n", lpMethod);
                            serverContinue = command->request.inline_handler(remote, packet, &result) && serverContinue;
                            printf("[DISPATCH] executed %s, continue %s\n", lpMethod, serverContinue ? "yes" : "no");
                        }
                        else
                        {
                            completionRoutine.routine = command->response.handler;
                            printf("[DISPATCH] executing request handler %s\n", lpMethod);
                            result = command->request.handler(remote, packet, &completionRoutine);
                        }
                        break;
                    case PACKET_TLV_TYPE_RESPONSE:
                    case PACKET_TLV_TYPE_PLAIN_RESPONSE:
                        if (command->response.inline_handler)
                        {
                            printf("[DISPATCH] executing inline response handler %s\n", lpMethod);
                            serverContinue = command->response.inline_handler(remote, packet, &result) && serverContinue;
                        }
                        else
                        {
                            printf("[DISPATCH] executing response handler %s\n", lpMethod);
                            result = command->response.handler(remote, packet, NULL);
                        }
                        break;
                }
            }

            printf("[COMMAND] Calling completion handlers...\n");

            // Get the request identifier if the packet has one.
            if (packet_get_tlv_string(packet, TLV_TYPE_REQUEST_ID, &requestIdTlv) == ERROR_SUCCESS)
            {
                requestId = (PCHAR)requestIdTlv.buffer;
            }

            // Finally, call completion routines for the provided identifier
            if (((packetTlvType == PACKET_TLV_TYPE_RESPONSE) || (packetTlvType == PACKET_TLV_TYPE_PLAIN_RESPONSE)) && requestId)
            {
                packet_call_completion_handlers(remote, packet, requestId);
            }

            printf("[COMMAND] Completion handlers finished for %s. Returning: %s\n", lpMethod, (serverContinue ? "TRUE" : "FALSE"));
        } while (0);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        printf("[COMMAND] Exception hit in command %s\n", lpMethod);
    }

    if (!packet->local)
    {
        packet_destroy(packet);
    }

    return serverContinue;
}

/*!
 * @brief Attempt to locate a command in the base command list.
 * @param method String that identifies the command.
 * @returns Pointer to the command entry in the base command list.
 * @retval NULL Indicates that no command was found for the given method.
 * @retval NON-NULL Pointer to the command that can be executed.
 */
Command* command_locate_base(const char* method)
{
    DWORD index;

    printf("[COMMAND EXEC] Attempting to locate base command %s\n", method);
    for (index = 0; baseCommands[index].method; ++index)
    {
        if (strcmp(baseCommands[index].method, method) == 0)
        {
            return &baseCommands[index];
        }
    }

    printf("[COMMAND EXEC] Couldn't find base command %s\n", method);
    return NULL;
}

/*!
 * @brief Attempt to locate a command in the extensions command list.
 * @param method String that identifies the command.
 * @returns Pointer to the command entry in the extensions command list.
 * @retval NULL Indicates that no command was found for the given method.
 * @retval NON-NULL Pointer to the command that can be executed.
 */
Command* command_locate_extension(const char* method)
{
    Command* command;

    printf("[COMMAND EXEC] Attempting to locate extension command %s (%p)\n", method, extensionCommands);
    for (command = extensionCommands; command; command = command->next)
    {
        if (strcmp(command->method, method) == 0)
        {
            return command;
        }
    }

    printf("[COMMAND EXEC] Couldn't find extension command %s\n", method);
    return NULL;
}

/*!
 * @brief Handle an incoming command.
 * @param remote Pointer to the \c Remote instance associated with this command.
 * @param packet Pointer to the \c Packet containing the command data.
 * @retval TRUE The server can and should continue processing.
 * @retval FALSE The server should stop processing and shut down.
 * @remark This function was incorporate to help support two things in meterpreter:
 *         -# A way of allowing a command to be processed directly on the main server
 *            thread and not on another thread (which in some cases can cause problems).
 *         -# A cleaner way of shutting down the server so that container processes
 *            can shutdown cleanly themselves, where appropriate.
 *
 *         This function will look at the command definition and determine if it should
 *         be executed inline or on a new command thread.
 * @sa command_process_inline
 * @sa command_process_thread
 */
BOOL command_handle(Remote *remote, Packet *packet)
{
    BOOL result = TRUE;
    Command* baseCommand = NULL;
    Command* extensionCommand = NULL;
    Command** commands = NULL;
    Packet* response = NULL;
    PCHAR lpMethod = NULL;
    Tlv methodTlv;

    do
    {
        if (packet_get_tlv_string(packet, TLV_TYPE_METHOD, &methodTlv) != ERROR_SUCCESS)
        {
            printf("[COMMAND] Unable to extract method from packet.\n");
            break;
        }

        lpMethod = (PCHAR)methodTlv.buffer;

        baseCommand = command_locate_base(lpMethod);
        extensionCommand = command_locate_extension(lpMethod);

        if (baseCommand == NULL && extensionCommand == NULL) {
            printf("[DISPATCH] Command not found: %s\n", lpMethod);
            // We have no matching command for this packet, so it won't get handled. We
            // need to send an empty response and clean up here before exiting out.
            response = packet_create_response(packet);
            if (packet->local)
            {
                packet_add_tlv_uint(response, TLV_TYPE_RESULT, ERROR_NOT_SUPPORTED);
            }
            else
            {
                packet_transmit_response(ERROR_NOT_SUPPORTED, remote, response);
                packet_destroy(packet);
            }
            break;
        }

        // if either command is registered as inline, run them inline
        if ((baseCommand && command_is_inline(baseCommand, packet))
            || (extensionCommand && command_is_inline(extensionCommand, packet))
            || packet->local)
        {
            printf("[DISPATCH] Executing inline: %s\n", lpMethod);
            result = command_process_inline(baseCommand, extensionCommand, remote, packet);
        } else {
            printf("[DISPATCH] Executing in thread: %s\n", lpMethod);

            commands = (Command **) malloc(sizeof(Command *) * 2);
            *commands = baseCommand;
            *(commands + 1) = extensionCommand;

            // TODO:
//            cpt = thread_create(command_process_thread, remote, packet, commands);
//            if (cpt) {
//                printf("[DISPATCH] created command_process_thread 0x%08X, handle=0x%08X", cpt, cpt->handle);
//                thread_run(cpt);
//            }
            command_process_inline(*commands, *(commands + 1), remote, packet);
        }

    } while (0);

    return result;
}

/*!
 * @brief Register a full list of commands with meterpreter.
 * @param commands The array of commands that are to be registered for the module/extension.
 */
void command_register_all(Command commands[])
{
    DWORD index;

    for (index = 0; commands[index].method; index++)
    {
        command_register(&commands[index]);
    }

#ifdef DEBUGTRACE
    Command* command;

	printf("[COMMAND LIST] Listing current extension commands");
	for (command = extensionCommands; command; command = command->next)
	{
		printf("[COMMAND LIST] Found: %s", command->method);
	}
#endif
}

/*!
 * @brief Dynamically register a custom command handler
 * @param command Pointer to the command that should be registered.
 * @return `ERROR_SUCCESS` when command registers successfully, otherwise returns the error.
 */
DWORD command_register(Command *command)
{
    Command *newCommand;

    printf("Registering a new command (%s)...\n", command->method);
    if (!(newCommand = (Command *)malloc(sizeof(Command))))
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    printf("Allocated memory...\n");
    memcpy(newCommand, command, sizeof(Command));

    printf("Setting new command...\n");
    if (extensionCommands)
    {
        extensionCommands->prev = newCommand;
    }

    printf("Fixing next/prev... %p\n", newCommand);
    newCommand->next = extensionCommands;
    newCommand->prev = NULL;
    extensionCommands = newCommand;

    printf("Done...\n");
    return ERROR_SUCCESS;
}

/*!
 * @brief Create a packet of a given type (request/response) and method.
 * @param type The TLV type that this packet represents.
 * @param method TLV method type (can be \c NULL).
 * @return Pointer to the newly created \c Packet.
 */
Packet *packet_create(PacketTlvType type, LPCSTR method)
{
    Packet *packet = NULL;
    BOOL success = FALSE;

    do
    {
        if (!(packet = (Packet *)malloc(sizeof(Packet))))
        {
            break;
        }

        memset(packet, 0, sizeof(Packet));

        // Initialize the header length and message type
        packet->header.length = htonl(sizeof(TlvHeader));
        packet->header.type = htonl((DWORD)type);

        // Initialize the payload to be blank
        packet->payload = NULL;
        packet->payloadLength = 0;

        // Add the method TLV if provided
        if (method && packet_add_tlv_string(packet, TLV_TYPE_METHOD, method) != ERROR_SUCCESS)
        {
            break;
        }

        success = TRUE;

    } while (0);

    // Clean up the packet on failure
    if (!success && packet)
    {
        packet_destroy(packet);

        packet = NULL;
    }

    return packet;
}

/*!
 * @brief Get the TLV type of the packet.
 * @param packet Pointer to the packet to get the type from.
 * @return \c PacketTlvType for the given \c Packet.
 */
PacketTlvType packet_get_type( Packet *packet )
{
    return (PacketTlvType)ntohl( packet->header.type );
}
/*!
 * @brief Validate command arguments
 * @return Indication of whether the commands are valid or not.
 * @retval ERROR_SUCCESS All arguments are valid.
 * @retval ERROR_INVALID_PARAMETER An invalid parameter exists.
 */
DWORD command_validate_arguments(Command *command, Packet *packet)
{
    PacketDispatcher *dispatcher = NULL;
    PacketTlvType type = packet_get_type(packet);
    DWORD res = ERROR_SUCCESS,
            packetIndex, commandIndex;
    Tlv current;

    // Select the dispatcher table
    if ((type == PACKET_TLV_TYPE_RESPONSE) ||
        (type == PACKET_TLV_TYPE_PLAIN_RESPONSE))
        dispatcher = &command->response;
    else
        dispatcher = &command->request;

    // Enumerate the arguments, validating the meta types of each
    for (commandIndex = 0, packetIndex = 0;
         ((packet_enum_tlv(packet, packetIndex, TLV_TYPE_ANY, &current) == ERROR_SUCCESS)
          && (res == ERROR_SUCCESS));
         commandIndex++, packetIndex++)
    {
        TlvMetaType tlvMetaType;

        // Check to see if we've reached the end of the command arguments
        if ((dispatcher->numArgumentTypes) &&
            (commandIndex == (dispatcher->numArgumentTypes & ARGUMENT_FLAG_MASK)))
        {
            // If the repeat flag is set, reset the index
            if (commandIndex & ARGUMENT_FLAG_REPEAT)
                commandIndex = 0;
            else
                break;
        }

        // Make sure the argument is at least one of the meta types
        tlvMetaType = packet_get_tlv_meta(packet, &current);

        // Validate argument meta types
        switch (tlvMetaType)
        {
            case TLV_META_TYPE_STRING:
                if (packet_is_tlv_null_terminated(&current) != ERROR_SUCCESS)
                {
                    printf("[COMMAND] string is not null terminated\n");
                    res = ERROR_INVALID_PARAMETER;
                }
                break;
            default:
                break;
        }

        if ((res != ERROR_SUCCESS) &&
            (commandIndex < dispatcher->numArgumentTypes))
            break;
    }

    return res;
}

/*!
 * @brief Create a response packet from a request.
 * @details Create a response packet from a request, referencing the requestors
 * message identifier.
 * @param request The request \c Packet to build a response for.
 * @return Pointer to a new \c Packet.
 */
Packet *packet_create_response(Packet *request)
{
    Packet *response = NULL;
    Tlv method, requestId;
    BOOL success = FALSE;
    PacketTlvType responseType;

    if (packet_get_type(request) == PACKET_TLV_TYPE_PLAIN_REQUEST)
    {
        responseType = PACKET_TLV_TYPE_PLAIN_RESPONSE;
    }
    else
    {
        responseType = PACKET_TLV_TYPE_RESPONSE;
    }

    do
    {
        // Get the request TLV's method
        if (packet_get_tlv_string(request, TLV_TYPE_METHOD, &method) != ERROR_SUCCESS)
        {
            break;
        }

        // Try to allocate a response packet
        if (!(response = packet_create(responseType, (PCHAR)method.buffer)))
        {
            break;
        }

        // Get the request TLV's request identifier
        if (packet_get_tlv_string(request, TLV_TYPE_REQUEST_ID, &requestId) != ERROR_SUCCESS)
        {
            break;
        }

        // Add the request identifier to the packet
        packet_add_tlv_string(response, TLV_TYPE_REQUEST_ID, (PCHAR)requestId.buffer);

        // If the packet that is being handled is considered local, then we
        // associate the response with the request so that it can be handled
        // locally (and vice versa)
        if (request->local)
        {
            request->partner = response;
            response->partner = request;
        }

        success = TRUE;

    } while (0);

    // Cleanup on failure
    if (!success)
    {
        if (response)
        {
            packet_destroy(response);
        }

        response = NULL;
    }

    return response;
}

/*!
 * @brief Add a unsigned integer value TLV to a packet.
 * @param packet Pointer to the packet to add the value to.
 * @param type TLV type for the value.
 * @param val The value to add to the packet.
 * @return Indication of success or failure.
 * @retval ERROR_SUCCESS The operation completed successfully.
 * @retval ERROR_NOT_ENOUGH_MEMORY Insufficient memory available.
 */
DWORD packet_add_tlv_uint(Packet *packet, TlvType type, UINT val)
{
    val = htonl(val);

    return packet_add_tlv_raw(packet, type, (PUCHAR)&val, sizeof(val));
}

/*!
 * @brief Transmit a `TLV_TYPE_RESULT` response if `response` is present.
 * @param result The result to be sent.
 * @param remote Reference to the remote connection to send the response to.
 * @param response the Response to add the `result` to.
 */
DWORD packet_transmit_response(DWORD result, Remote* remote, Packet* response)
{
    if (response)
    {
        packet_add_tlv_uint(response, TLV_TYPE_RESULT, result);
        return remote->transmit(remote, response, NULL);
    }
    return ERROR_NOT_ENOUGH_MEMORY;
}

/*!
 * @brief Get the TLV meta-type of the packet.
 * @param packet Pointer to the packet to get the meta-type from.
 * @return \c TlvMetaType for the given \c Packet.
 */
TlvMetaType packet_get_tlv_meta( Packet *packet, Tlv *tlv )
{
    return TLV_META_TYPE_MASK( tlv->header.type );
}
