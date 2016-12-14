
#ifndef BASE_COMMANDS_H
#define BASE_COMMANDS_H

#include "types.h"
#include "core.h"

DWORD remote_request_core_console_write(Remote *remote, Packet *packet);
DWORD remote_response_core_console_write(Remote *remote, Packet *packet);
DWORD remote_request_echo(Remote *remote, Packet *packet, PacketRequestCompletion *completionRoutine);
DWORD remote_response_echo(Remote *remote, Packet *packet);

#endif
