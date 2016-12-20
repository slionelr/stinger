#include "metcli.h"
#include "../common/common.h"

LOCK *clientLock = NULL;

Remote *connect_to_target(LPSTR address, DWORD port) {
    Remote *remote = gen_Remote();
    remote->address = address;
    remote->port = port;
    remote->connect(remote);

    return remote;
}

int main(int argc, char *argv[]) {
    Remote *target = connect_to_target("192.168.56.101", 31337);
//    Remote *target = connect_to_target("192.168.56.1", 31337);
    if (!target) {
        return -1;
    }

    do {
        console_read_buffer(target);

    } while (TRUE);

    return 0;
}

/*
 * Initializes the global client lock
 */
VOID client_init_lock() {
    clientLock = lock_create();
}

/*
 * Acquires the global client lock
 */
VOID client_acquire_lock() {
    lock_acquire(clientLock);
}

/*
 * Releases the global client lock
 */
VOID client_release_lock() {
    lock_release(clientLock);
}