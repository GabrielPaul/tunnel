#include <fcntl.h>
#include "common.h"
int set_noblockSock(int fd)
{
    const int flags = fcntl(fd, F_GETFL, 0);
    if(flags < 0)
    {
        return flags;
    }
    if(flags & O_NONBLOCK)
    {
        return 0;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}