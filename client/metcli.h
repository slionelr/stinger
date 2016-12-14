//
// Created by messi on 12/8/16.
//

#ifndef CLIENT_METCLI_H_H
#define CLIENT_METCLI_H_H

#include "../common/common.h"

#define INBOUND_PREFIX "<<<"

/*
 * Input processing
 */
typedef struct _ConsoleCommand
{
    LPCSTR                 name;
    DWORD                  (*handler)(Remote *remote, UINT argc, CHAR **argv);
    LPCSTR                 help;
    BOOL                   separator;

    // Not stored
    struct _ConsoleCommand *prev;
    struct _ConsoleCommand *next;
} ConsoleCommand;

VOID client_init_lock();
VOID client_acquire_lock();
VOID client_release_lock();

VOID console_read_buffer(Remote *remote);
DWORD console_generic_response_output(Remote *remote, Packet *packet, LPCSTR subsys, LPCSTR cmd);

#endif //CLIENT_METCLI_H_H
