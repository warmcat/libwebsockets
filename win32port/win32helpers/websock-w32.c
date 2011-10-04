#define FD_SETSIZE 256

#include <WinSock2.h>
#include <stdlib.h>
#include <errno.h>
#include "websock-w32.h"


PFNWSAPOLL poll = NULL;


INT WSAAPI emulated_poll(LPWSAPOLLFD fdarray, ULONG nfds, INT timeout)
{
    fd_set readfds, writefds;
    struct timeval tv, *ptv;
    SOCKET max_socket;
    ULONG n;
    int num_bits, num_sockets_ready;

    if (NULL == fdarray)
    {
        errno = EFAULT;
        return -1;
    }

    FD_ZERO(&readfds);
    FD_ZERO(&writefds);

    max_socket = 0;
    n = 0;
    while (n < nfds)
    {
        WSAPOLLFD * const poll_fd = (fdarray + n);
        SOCKET sock = poll_fd->fd;
        poll_fd->revents = 0;
        if (0 <= sock)
        {
            const SHORT events = poll_fd->events;
            if (events)
            {
                if (max_socket < sock)
                {
                    max_socket = sock;
                }

                if (events & POLLIN)
                {
                    FD_SET(sock, &readfds);
                }

                if (events & POLLOUT)
                {
                    FD_SET(sock, &writefds);
                }
            }
        }
        n++;
    }

    if (0 > timeout)
    {
        ptv = NULL;
    }
    else
    {
        ptv = &tv;
        if (0 == timeout)
        {
            tv.tv_sec = 0;
            tv.tv_usec = 0;
        }
        else if (1000 <= timeout)
        {
            tv.tv_sec = (timeout / 1000);
            tv.tv_usec = ((timeout % 1000) * 1000);
        }
        else
        {
            tv.tv_sec = 0;
            tv.tv_usec = (timeout * 1000);
        }
    }

    num_bits = select((int)max_socket + 1, &readfds, &writefds, NULL, ptv);
    if (0 >= num_bits)
    {
        return num_bits;
    }

    num_sockets_ready = 0;
    n = 0;
    do
    {
        WSAPOLLFD * const poll_fd = (fdarray + n);
        SOCKET sock = poll_fd->fd;
        if (0 <= sock)
        {
            const SHORT events = poll_fd->events;
            if (events)
            {
                if (FD_ISSET(sock, &readfds))
                {
                    const int saved_error = WSAGetLastError();
                    char test_data[4] = {0};
                    int ret;

                    /* support for POLLHUP */
                    ret = recv(poll_fd->fd, test_data, sizeof(test_data), MSG_PEEK);
                    if (SOCKET_ERROR == ret)
                    {
                        const int err = WSAGetLastError();
                        if (err == WSAESHUTDOWN || err == WSAECONNRESET ||
                            err == WSAECONNABORTED || err == WSAENETRESET)
                        {
                            poll_fd->revents |= POLLHUP;
                        }
                    }
                    else
                    {
                        if (events & POLLIN)
                        {
                            poll_fd->revents |= POLLIN;
                        }
                    }

                    WSASetLastError(saved_error);

                    --num_bits;
                }

                if (FD_ISSET(sock, &writefds))
                {
                    if (events & POLLOUT)
                    {
                        poll_fd->revents |= POLLOUT;
                    }

                    --num_bits;
                }

                if (poll_fd->revents)
                {
                    num_sockets_ready++;
                }
            }
        }
        else
        {
            poll_fd->revents = POLLNVAL;
        }
        n++;
    }
    while (0 < num_bits && n < nfds);

    return num_sockets_ready;
}
