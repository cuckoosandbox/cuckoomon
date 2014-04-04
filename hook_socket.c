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
#include <windows.h>
#include <winsock2.h>
#include <mswsock.h>
#include "hooking.h"
#include "ntapi.h"
#include "log.h"

static IS_SUCCESS_INTM1();

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
    LOQ("lll", "af", af, "type", type, "protocol", protocol);
    return ret;
}

HOOKDEF(int, WSAAPI, connect,
    __in  SOCKET s,
    __in  const struct sockaddr *name,
    __in  int namelen
) {
    int ret = Old_connect(s, name, namelen);
    LOQ("p", "socket", s);
    return ret;
}

HOOKDEF(int, WSAAPI, send,
    __in  SOCKET s,
    __in  const char *buf,
    __in  int len,
    __in  int flags
) {
    int ret = Old_send(s, buf, len, flags);
    LOQ("pb", "socket", s, "buffer", ret < 1 ? 0 : ret, buf);
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
    LOQ("pb", "socket", s, "buffer", ret < 1 ? 0 : ret, buf);
    return ret;
}

HOOKDEF(int, WSAAPI, recv,
    __in   SOCKET s,
    __out  char *buf,
    __in   int len,
    __in   int flags
) {
    int ret = Old_recv(s, buf, len, flags);
    LOQ("pb", "socket", s, "buffer", ret < 1 ? 0 : len, buf);
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
    LOQ("pb", "socket", s, "buffer", ret < 1 ? 0 : ret, buf);
    return ret;
}

HOOKDEF(SOCKET, WSAAPI, accept,
    __in     SOCKET s,
    __out    struct sockaddr *addr,
    __inout  int *addrlen
) {
    SOCKET ret = Old_accept(s, addr, addrlen);
    LOQ("pp", "socket", s, "ClientSocket", ret);
    return ret;
}

HOOKDEF(int, WSAAPI, bind,
    __in  SOCKET s,
    __in  const struct sockaddr *name,
    __in  int namelen
) {
    int ret = Old_bind(s, name, namelen);
    if(ret == 0) {
        LOQ("psl", "socket", s,
            "ip", inet_ntoa(((struct sockaddr_in *) name)->sin_addr),
            "port", htons(((struct sockaddr_in *) name)->sin_port));
    }
    else {
        LOQ2("p", "socket", s);
    }
    return ret;
}

HOOKDEF(int, WSAAPI, listen,
    __in  SOCKET s,
    __in  int backlog
) {
    int ret = Old_listen(s, backlog);
    LOQ("p", "socket", s);
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
    LOQ("p", "socket", s);
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
    LOQ("pllb", "socket", s, "level", level, "optname", optname,
        "optval", optlen, optval);
    return ret;
}

HOOKDEF(int, WSAAPI, ioctlsocket,
    __in     SOCKET s,
    __in     long cmd,
    __inout  u_long *argp
) {
    int ret = Old_ioctlsocket(s, cmd, argp);
    LOQ("pl", "socket", s, "command", cmd);
    return ret;
}

HOOKDEF(int, WSAAPI, closesocket,
    __in  SOCKET s
) {
    int ret = Old_closesocket(s);
    LOQ("p", "socket", s);
    return ret;
}

HOOKDEF(int, WSAAPI, shutdown,
    __in  SOCKET s,
    __in  int how
) {
    int ret = Old_shutdown(s, how);
    LOQ("pl", "socket", s, "how", how);
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
    LOQ("p", "socket", s);
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
    // TODO dump buffer
    LOQ("p", "socket", s);
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
    LOQ("p", "Socket", s);
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
    BOOL ret = Old_WSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent,
        dwFlags, lpTo, iToLen, lpOverlapped, lpCompletionRoutine);
    // TODO dump buffers
    LOQ("p", "Socket", s);
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
    LOQ("lll", "af", af, "type", type, "protocol", protocol);
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
    LOQ("lll", "af", af, "type", type, "protocol", protocol);
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
    LOQ("pB", "socket", s, "SendBuffer", lpdwBytesSent, lpSendBuffer);
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
    LOQ("ppll", "socket", hSocket, "FileHandle", hFile,
        "NumberOfBytesToWrite", nNumberOfBytesToWrite,
        "NumberOfBytesPerSend", nNumberOfBytesPerSend);
    return ret;
}
