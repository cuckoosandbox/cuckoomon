/*
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2010-2014 Cuckoo Sandbox Developers

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include "hooking.h"
#include "ntapi.h"
#include "log.h"

static const char *category = "socket";
static IS_SUCCESS_INTM1();

static void get_ip_port(const struct sockaddr *addr,
    const char **ip, int *port)
{
    // TODO IPv6 support.
    if(addr != NULL) {
        const struct sockaddr_in *addr4 = (const struct sockaddr_in *) addr;
        *ip = inet_ntoa(addr4->sin_addr);
        *port = htons(addr4->sin_port);
    }
}

HOOKDEF(int, WINAPI, WSAStartup,
    _In_   WORD wVersionRequested,
    _Out_  LPWSADATA lpWSAData
) {
    IS_SUCCESS_ZERO();

    int ret = Old_WSAStartup(wVersionRequested, lpWSAData);
    LOQ("p", "VersionRequested", wVersionRequested);
    return ret;
}

HOOKDEF(struct hostent *, WSAAPI, gethostbyname,
    __in  const char *name
) {
    IS_SUCCESS_HANDLE();

    struct hostent *ret = Old_gethostbyname(name);
    LOQ("s", "Name", name);
    return ret;
}

HOOKDEF(SOCKET, WSAAPI, socket,
    __in  int af,
    __in  int type,
    __in  int protocol
) {
    SOCKET ret = Old_socket(af, type, protocol);
    LOQ("iiii", "af", af, "type", type, "protocol", protocol, "socket", ret);
    return ret;
}

HOOKDEF(int, WSAAPI, connect,
    __in  SOCKET s,
    __in  const struct sockaddr *name,
    __in  int namelen
) {
    int ret = Old_connect(s, name, namelen);
    const char *ip = NULL; int port = 0;
    get_ip_port(name, &ip, &port);
    LOQ("isi", "socket", s, "ip", ip, "port", port);
    return ret;
}

HOOKDEF(int, WSAAPI, send,
    __in  SOCKET s,
    __in  const char *buf,
    __in  int len,
    __in  int flags
) {
    int ret = Old_send(s, buf, len, flags);
    LOQ("ib", "socket", s, "buffer", ret < 1 ? 0 : ret, buf);
    return ret;
}

HOOKDEF(int, WSAAPI, sendto,
    __in  SOCKET s,
    __in  const char *buf,
    __in  int len,
    __in  int flags,
    __in  const struct sockaddr *to,
    __in  int tolen
) {
    int ret = Old_sendto(s, buf, len, flags, to, tolen);
    const char *ip = NULL; int port = 0;
    if(ret > 0) {
        get_ip_port(to, &ip, &port);
    }
    LOQ("ibsi", "socket", s, "buffer", ret < 1 ? 0 : ret, buf,
        "ip", ip, "port", port);
    return ret;
}

HOOKDEF(int, WSAAPI, recv,
    __in   SOCKET s,
    __out  char *buf,
    __in   int len,
    __in   int flags
) {
    int ret = Old_recv(s, buf, len, flags);
    LOQ("ib", "socket", s, "buffer", ret < 1 ? 0 : len, buf);
    return ret;
}

HOOKDEF(int, WSAAPI, recvfrom,
    __in         SOCKET s,
    __out        char *buf,
    __in         int len,
    __in         int flags,
    __out        struct sockaddr *from,
    __inout_opt  int *fromlen
) {
    int ret = Old_recvfrom(s, buf, len, flags, from, fromlen);
    const char *ip = NULL; int port = 0;
    if(ret > 0) {
        get_ip_port(from, &ip, &port);
    }
    LOQ("ibsi", "socket", s, "buffer", ret < 1 ? 0 : ret, buf,
        "ip", ip, "port", port);
    return ret;
}

HOOKDEF(SOCKET, WSAAPI, accept,
    __in     SOCKET s,
    __out    struct sockaddr *addr,
    __inout  int *addrlen
) {
    SOCKET ret = Old_accept(s, addr, addrlen);
    const char *ip_s = NULL, *ip_c = NULL; int port_s = 0, port_c = 0;
    struct sockaddr addr_c; int addr_c_len = sizeof(addr_c);

    get_ip_port(addr, &ip_s, &port_s);
    if(getpeername(ret, &addr_c, &addr_c_len) == 0) {
        get_ip_port(&addr_c, &ip_c, &port_c);
    }

    LOQ("iisisi", "socket", s, "ClientSocket", ret,
        "ip_accept", ip_s, "port_accept", port_s,
        "ip_client", ip_c, "port_client", port_c);
    return ret;
}

HOOKDEF(int, WSAAPI, bind,
    __in  SOCKET s,
    __in  const struct sockaddr *name,
    __in  int namelen
) {
    int ret = Old_bind(s, name, namelen);
    const char *ip = NULL; int port = 0;
    get_ip_port(name, &ip, &port);

    LOQ("isi", "socket", s, "ip", ip, "port", port);
    return ret;
}

HOOKDEF(int, WSAAPI, listen,
    __in  SOCKET s,
    __in  int backlog
) {
    int ret = Old_listen(s, backlog);
    LOQ("i", "socket", s);
    return ret;
}

HOOKDEF(int, WSAAPI, select,
    __in     SOCKET s,
    __inout  fd_set *readfds,
    __inout  fd_set *writefds,
    __inout  fd_set *exceptfds,
    __in     const struct timeval *timeout
) {
    int ret = Old_select(s, readfds, writefds, exceptfds, timeout);
    LOQ("i", "socket", s);
    return ret;
}

HOOKDEF(int, WSAAPI, setsockopt,
    __in  SOCKET s,
    __in  int level,
    __in  int optname,
    __in  const char *optval,
    __in  int optlen
) {
    int ret = Old_setsockopt(s, level, optname, optval, optlen);
    LOQ("illb", "socket", s, "level", level, "optname", optname,
        "optval", optlen, optval);
    return ret;
}

HOOKDEF(int, WSAAPI, ioctlsocket,
    __in     SOCKET s,
    __in     long cmd,
    __inout  u_long *argp
) {
    int ret = Old_ioctlsocket(s, cmd, argp);
    LOQ("il", "socket", s, "command", cmd);
    return ret;
}

HOOKDEF(int, WSAAPI, closesocket,
    __in  SOCKET s
) {
    int ret = Old_closesocket(s);
    LOQ("i", "socket", s);
    return ret;
}

HOOKDEF(int, WSAAPI, shutdown,
    __in  SOCKET s,
    __in  int how
) {
    int ret = Old_shutdown(s, how);
    LOQ("il", "socket", s, "how", how);
    return ret;
}

HOOKDEF(int, WSAAPI, WSARecv,
    __in     SOCKET s,
    __inout  LPWSABUF lpBuffers,
    __in     DWORD dwBufferCount,
    __out    LPDWORD lpNumberOfBytesRecvd,
    __inout  LPDWORD lpFlags,
    __in     LPWSAOVERLAPPED lpOverlapped,
    __in     LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) {
    BOOL ret = Old_WSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd,
        lpFlags, lpOverlapped, lpCompletionRoutine);
    // TODO dump buffers
    LOQ("i", "socket", s);
    return ret;
}

HOOKDEF(int, WSAAPI, WSARecvFrom,
    __in     SOCKET s,
    __inout  LPWSABUF lpBuffers,
    __in     DWORD dwBufferCount,
    __out    LPDWORD lpNumberOfBytesRecvd,
    __inout  LPDWORD lpFlags,
    __out    struct sockaddr *lpFrom,
    __inout  LPINT lpFromlen,
    __in     LPWSAOVERLAPPED lpOverlapped,
    __in     LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) {
    BOOL ret = Old_WSARecvFrom(s, lpBuffers, dwBufferCount,
        lpNumberOfBytesRecvd, lpFlags, lpFrom, lpFromlen, lpOverlapped,
        lpCompletionRoutine);
    const char *ip = NULL; int port = 0;
    get_ip_port(lpFrom, &ip, &port);
    // TODO dump buffer, implement support for completion routine
    LOQ("isi", "socket", s, "ip", ip, "port", port);
    return ret;
}

HOOKDEF(int, WSAAPI, WSASend,
    __in   SOCKET s,
    __in   LPWSABUF lpBuffers,
    __in   DWORD dwBufferCount,
    __out  LPDWORD lpNumberOfBytesSent,
    __in   DWORD dwFlags,
    __in   LPWSAOVERLAPPED lpOverlapped,
    __in   LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) {
    BOOL ret = Old_WSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent,
        dwFlags, lpOverlapped, lpCompletionRoutine);
    // TODO dump buffers
    LOQ("i", "Socket", s);
    return ret;
}

HOOKDEF(int, WSAAPI, WSASendTo,
    __in   SOCKET s,
    __in   LPWSABUF lpBuffers,
    __in   DWORD dwBufferCount,
    __out  LPDWORD lpNumberOfBytesSent,
    __in   DWORD dwFlags,
    __in   const struct sockaddr *lpTo,
    __in   int iToLen,
    __in   LPWSAOVERLAPPED lpOverlapped,
    __in   LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) {
    const char *ip = NULL; int port = 0;
    get_ip_port(lpTo, &ip, &port);

    BOOL ret = Old_WSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent,
        dwFlags, lpTo, iToLen, lpOverlapped, lpCompletionRoutine);
    // TODO dump buffers
    LOQ("isi", "socket", s, "ip", ip, "port", port);
    return ret;
}

HOOKDEF(SOCKET, WSAAPI, WSASocketA,
    __in  int af,
    __in  int type,
    __in  int protocol,
    __in  LPWSAPROTOCOL_INFO lpProtocolInfo,
    __in  GROUP g,
    __in  DWORD dwFlags
) {
    SOCKET ret = Old_WSASocketA(af, type, protocol, lpProtocolInfo,
        g, dwFlags);
    LOQ("iiii", "af", af, "type", type, "protocol", protocol, "socket", ret);
    return ret;
}

HOOKDEF(SOCKET, WSAAPI, WSASocketW,
    __in  int af,
    __in  int type,
    __in  int protocol,
    __in  LPWSAPROTOCOL_INFO lpProtocolInfo,
    __in  GROUP g,
    __in  DWORD dwFlags
) {
    SOCKET ret = Old_WSASocketW(af, type, protocol, lpProtocolInfo,
        g, dwFlags);
    LOQ("iiii", "af", af, "type", type, "protocol", protocol, "socket", ret);
    return ret;
}

HOOKDEF(BOOL, PASCAL, ConnectEx,
    _In_      SOCKET s,
    _In_      const struct sockaddr *name,
    _In_      int namelen,
    _In_opt_  PVOID lpSendBuffer,
    _In_      DWORD dwSendDataLength,
    _Out_     LPDWORD lpdwBytesSent,
    _In_      LPOVERLAPPED lpOverlapped
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old_ConnectEx(s, name, namelen, lpSendBuffer, dwSendDataLength,
        lpdwBytesSent, lpOverlapped);
    const char *ip = NULL; int port = 0;
    get_ip_port(name, &ip, &port);
    LOQ("iBsi", "socket", s, "SendBuffer", lpdwBytesSent, lpSendBuffer,
        "ip", ip, "port", port);
    return ret;
}

HOOKDEF(BOOL, PASCAL, TransmitFile,
    SOCKET hSocket,
    HANDLE hFile,
    DWORD nNumberOfBytesToWrite,
    DWORD nNumberOfBytesPerSend,
    LPOVERLAPPED lpOverlapped,
    LPTRANSMIT_FILE_BUFFERS lpTransmitBuffers,
    DWORD dwFlags
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old_TransmitFile(hSocket, hFile, nNumberOfBytesToWrite,
        nNumberOfBytesPerSend, lpOverlapped, lpTransmitBuffers, dwFlags);
    LOQ("ipll", "socket", hSocket, "FileHandle", hFile,
        "NumberOfBytesToWrite", nNumberOfBytesToWrite,
        "NumberOfBytesPerSend", nNumberOfBytesPerSend);
    return ret;
}
