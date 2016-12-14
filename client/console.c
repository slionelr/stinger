//
// Created by messi on 12/8/16.
//

#include "metcli.h"
#include "../common/args.h"
#include "../common/command.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// Core console commands
extern DWORD cmd_echo(Remote *remote, UINT argc, CHAR **argv);

extern DWORD cmd_echo_complete(Remote *remote);

extern DWORD cmd_help(Remote *remote, UINT argc, CHAR **argv);

extern DWORD cmd_exit(Remote *remote, UINT argc, CHAR **argv);

/*
 * Local client core command line dispatch table
 */
ConsoleCommand consoleCommands[] =
        {
// Core extensions
                {"Core", NULL, "Core feature set commands", 1},
#ifdef _DEBUG
                {"echo", cmd_echo, "Echo test", 0},
#endif
                {"help", cmd_help, "Displays a list of commands.", 0},
                {"exit", cmd_exit, "Exits the client.", 0},

// Feature extensions
                {
                        "Features", NULL, "Feature extension commands", 1},
//            { "loadlib",  cmd_loadlib,  "Load a library on the remote machine.",               0 },
//            { "use",      cmd_use,      "Use a feature module.",                               0 },

// Terminator
                {NULL, NULL, NULL, 0},
        };

ConsoleCommand *extendedCommandsHead = NULL;
ConsoleCommand *extendedCommandsTail = NULL;

/*
 * Reads in data from the input device, potentially calling the
 * command processing function if a complete command has been read.
 */
VOID console_read_buffer(Remote *remote) {
    size_t buf_len = 4095;
    LPSTR buf = (LPSTR) malloc(buf_len + 1);
    LONG bytesRead;

    // Ensure null termination
    buf[sizeof(buf) - 1] = NULL;

    do {
        // Print command prompt
        console_write_prompt(remote);

        // Read the command
        if ((bytesRead = getline(&buf, &buf_len, stdin)) <= 0) {
            break;
        }

        buf[bytesRead - 1] = NULL;

        client_acquire_lock();
        console_process_command(remote, buf, bytesRead);
        client_release_lock();

    } while (0);
}


/*
 * Parse the local command into an argument vector
 *
 * TODO:
 *
 *   - Add character unescaping (\x01)
 */
VOID console_process_command(Remote *remote, LPBYTE userInput, size_t len) {
    CHAR **argv = NULL, *current;
    ConsoleCommand *command = NULL;
    UINT argc, index;

    do {
        // Calculate the number of arguments
        for (current = userInput, argc = 1;
             current = strchr(current, ' ');
             current++, argc++);

        current = userInput;
        index = 0;

        if (!(argv = (CHAR **) malloc(sizeof(PCHAR) * argc)))
            break;

        // Populate the argument vector
        while (1) {
            CHAR *space = NULL, *edquote = NULL;

            // If the first character of the current argument is a quote,
            // find the next quote.
            if (current[0] == '"') {
                if ((edquote = strchr(current + 1, '"')))
                    *edquote = 0;
            } else if ((space = strchr(current, ' ')))
                *space = 0;

            // If we're using quoting for this argument, skip one past current.
            argv[index++] = _strdup(current + ((edquote) ? 1 : 0));
            current = ((edquote) ? edquote : space) + 1;

            if (space)
                *space = ' ';
            else if (edquote)
                *edquote = '"';
            else
                break;
        }

        // Find the command
        for (index = 0;
             consoleCommands[index].name;
             index++) {
            if (!strcmp(consoleCommands[index].name, argv[0])) {
                command = &consoleCommands[index];
                break;
            }
        }

        // If the command was not found in the default command list, try looking
        // in the extended list
        if (!command) {
            for (command = extendedCommandsHead;
                 command;
                 command = command->next) {
                if (!strcmp(command->name, argv[0]))
                    break;
            }
        }

        // The command was not found.
        if ((!command) || (!command->name))
            break;

        command->handler(remote, argc, argv);

    } while (0);

    // Cleanup argv
    if (argv) {
        for (index = 0;
             index < argc;
             index++)
            free(argv[index]);

        free(argv);
    }
}

/*
 * Write a format string buffer to the console
 */
VOID console_write_output(LPCSTR fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
}


/*****************
 * Command: help *
 *****************/

VOID cmd_help_output_command(ConsoleCommand *command) {
    if (command->separator)
        console_write_output(
                "\n%13s   %s\n"
                        " ------------   ---------------\n",
                command->name, command->help);
    else
        console_write_output("%13s   %s\n", command->name,
                             command->help);
}

#ifdef _DEBUG

DWORD cmd_echo(Remote *remote, UINT argc, CHAR **argv) {
//    ChannelCompletionRoutine complete;
    ArgumentContext arg;
    BOOL printBanner = FALSE;
    DWORD res = ERROR_SUCCESS;
    LPSTR message = NULL;
    Packet *request = NULL;
    PacketRequestCompletion complete;

    do {
        // No arguments?
        if (argc == 1) {
            printBanner = TRUE;
            break;
        }

        // Parse the supplied arguments
        while (args_parse(argc, argv, "m:", &arg) == ERROR_SUCCESS) {
            switch (arg.toggle) {
                case 'm':
                    message = arg.argument;
                    break;
                default:
                    break;
            }
        }

        // Allocate the request packet
        if (!(request = packet_create(PACKET_TLV_TYPE_REQUEST, "core_echo"))) {
            console_write_output("Error: Packet allocation failure.\n");
            break;
        }

        packet_add_tlv_string(request, TLV_TYPE_DATA, message);

        // Initialize the completion routine
        memset(&complete, 0, sizeof(complete));

        complete.routine = cmd_echo_complete;
        res = PACKET_TRANSMIT(remote, request, &complete);

    } while (0);

    if (printBanner) {
        console_write_output(
                "Usage: echo -m <message>\n\n"
                        "  -m <message>   The message to send.\n"
        );
    }

    return res;
}

/*
 * Echo completion routine
 */
DWORD cmd_echo_complete(Remote *remote) {
    Packet *packet = NULL;
    DWORD res = ERROR_SUCCESS;
    DWORD result = ERROR_SUCCESS;

    do {
        result = PACKET_RECEIVE(remote, &packet);
        if (result != ERROR_SUCCESS) {
            printf("[DISPATCH] packet_receive returned %d, exiting dispatcher...\n", result);
            break;
        }

        LPCSTR rrr = packet_get_tlv_value_string(packet, TLV_TYPE_DATA);

        result = PACKET_RECEIVE(remote, &packet);
        if (result != ERROR_SUCCESS) {
            printf("[DISPATCH] packet_receive returned %d, exiting dispatcher...\n", result);
            break;
        }

        LPCSTR rrr2 = packet_get_tlv_value_string(packet, TLV_TYPE_CIPHER_NAME);
        console_write_output("Received resut from ECHO.ECHO.ECHO: %s\n", rrr2);

    } while (0);

    return result;
}

#endif

/*
 * Print the help banner
 */
DWORD cmd_help(Remote *remote, UINT argc, CHAR **argv) {
    ConsoleCommand *current;
    DWORD index;

    for (index = 0;
         consoleCommands[index].name;
         index++)
        cmd_help_output_command(&consoleCommands[index]);

    for (current = extendedCommandsHead;
         current;
         current = current->next)
        cmd_help_output_command(current);

    return ERROR_SUCCESS;
}

/*****************
 * Command: exit *
 *****************/

/*
 * Exit the client
 */
DWORD cmd_exit(Remote *remote, UINT argc, CHAR **argv) {
    exit(0);

    return ERROR_SUCCESS;
}

/*
 * Write the console prompt to the screen
 */
VOID console_write_prompt(Remote *remote) {
    fprintf(stdout, "[%s:%d]# ", remote->address, remote->port);
    fflush(stdout);
}

/*
 * Generic output of success/fail
 */
DWORD console_generic_response_output(Remote *remote, Packet *packet,
                                      LPCSTR subsys, LPCSTR cmd) {
    DWORD res = packet_get_result(packet);

    if (res == ERROR_SUCCESS)
        console_write_output(
                "\n"
                        INBOUND_PREFIX " %s: %s succeeded.\n", subsys, cmd);
    else
        console_write_output(
                "\n"
                        INBOUND_PREFIX " %s: %s failed, result %lu.\n",
                subsys, cmd, packet_get_result(packet));

    console_write_prompt(remote);

    return res;
}
