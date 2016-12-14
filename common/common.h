
#include "types.h"
#include "core.h"

Remote* gen_Remote();
BOOL local_bind(DWORD port);
BOOL remote_connect(Remote *remote);
static DWORD packet_transmit(Remote *remote, Packet *packet, PacketRequestCompletion *completion);
static DWORD packet_receive(Remote *remote, Packet **packet);
