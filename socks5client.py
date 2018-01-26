#! /usr/bin/env python3
#TODO: add GSSAPI support

import socket
from collections import namedtuple
import struct
import re
import http.client
import urllib.request

# used as the default value for username/password subnegotiation
USERNAME = '';
PASSWORD = '';

Socks5Nego = namedtuple('Socks5Nego', ['ver', 'nmethods' , 'methods']);
Socks5NegoRep = namedtuple('Socks5NegoRep', ['ver', 'method']);
Socks5Req = namedtuple('Socks5Req', ['ver', 'cmd', 'rsv', 'atyp', 'dstaddr', 'dstport']);
Socks5ReqRep = namedtuple('Socks5ReqRep', ['ver', 'rep', 'rsv', 'atyp', 'bndaddr', 'bndport']);
Socks5Udp = namedtuple('Socks5Udp', ['rsv', 'frag', 'atyp', 'dstaddr', 'dstport', 'data']);

# dictionaries used for explanation
mSocks5Methods = {
        b'\x00': "NO AUTHENTICATION REQUIRED",
        b'\x01': "GSSAPI",
        b'\x02': "USERNAME/PASSWORD",
        b'\x03': "to X'7F' IANA ASSIGNED",
        b'\x80': "to X'FE' RESERVED FOR PRIVATE METHODS",
        b'\xFF': "NO ACCEPTABLE METHODS",
}
mSocks5Cmd = {
        b'\x01': 'CONNECT',
        b'\x02': 'BIND',
        b'\x03': 'UDP ASSOCIATE',
}
mSocks5Atyp = {
        b'\x01': "IP V4 address",
        b'\x03': "DOMAINNAME",
        b'\x04': "IP V6 address",
}
mSocks5Rep = {
        b'\x00': "succeeded",
        b'\x01': "general SOCKS server failure",
        b'\x02': "connection not allowed by ruleset",
        b'\x03': "Network unreachable",
        b'\x04': "Host unreachable",
        b'\x05': "Connection refused",
        b'\x06': "TTL expired",
        b'\x07': "Command not supported",
        b'\x08': "Address type not supported",
        b'\x09': "to X'FF' unassigned",
}

# constants used in socks5 header field
SOCKS5VER = b'\x05';
SOCKS5RSV = b'\x00';
IPV4TYPE = b'\x01';
DOMAINTYPE = b'\x03';
IPV6TYPE = b'\x04'; # not supported

# proxy type
_PT_SOCKS5 = 'socks5'

# socks5 command
_SC_CONNECT = b'\x01'
_SC_BIND = b'\x02';
_SC_UDP = b'\x03';

# connection status
_CS_INIT = 'initialised';
_CS_NEGO = 'negotiated';
_CS_REP = 'replied';
_CS_BND_FIRST = 'first reply to bind command received';
_CS_BND_SECOND = 'second reply to bind command received, meanging successful listening';
_CS_DEAD = 'dead';

def checkIp(sHost):
    # check whether the host name is ip address
    sIpPattern = r'^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$'
    return bool(re.search(sIpPattern, sHost));

def readSock(sock, nSize):
    oriTimeout = sock.gettimeout();
    if (oriTimeout == 0):
        sock.settimeout(None);
    bData = b'';
    while len(bData) < nSize:
        bRecv = sock.recv(nSize - len(bData));
        if (bRecv):
            bData += bRecv;
        else:
            raise DeadConnectionError('socks5 connection lost');
    sock.settimeout(oriTimeout);
    return bData;

def writeSock(sock, bData):
    return sock.sendall(bData);

class GeneralError(Exception):
    pass

class DeadConnectionError(Exception):
    pass

class Socks5Error(Exception):
    pass

class Socket(socket.socket):
    # base class prevent that socket.socket is overwritten in executuion
    pass

class Socks(Socket):

    aDefaultProxy = None;

    def __init__(self, family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0):
        # the actual socket object used to do TCP related communication with the proxy server is self.negoSock, not self socket, while self.udpSock is used to send proxied UDP packet after UDP association
        assert family == socket.AF_INET;
        assert type in (socket.SOCK_STREAM, socket.SOCK_DGRAM);
        super().__init__(family, type, proto);
        # if sock.settimeout(x) with not None value as x, sock.type will be <SocketKind.SOCK_NONBLOCK: 2048>, not the originally <SocketKind.SOCK_RAW: 3>, <SocketKind.SOCK_DGRAM: 2>. So it's necessary to manually save the type to discern in the future.
        self._type = type;
        self.negoSock = None;
        self.udpSock = None;
        self.realSock = None;
        self.aDstAddr = None;
        self.aSrvAddr = None;
        self.aBndAddr = None;
        self.sProxyType = None;
        self.mSocks5 = {
                'methods': (),
                'method': b'',
        };
        self.mSocks5['methods'] = (b'\x00', b'\x02');
        self.sUsername = str(USERNAME) or '';
        self.sPassword = str(PASSWORD) or '';
        self.isRemoteDns = True;
        self.isBound = False;
        self.isSocks5Bound = False;
        self.isConnected = False;
        self.status = _CS_INIT;
        if (self.aDefaultProxy): self.setProxy(*self.aDefaultProxy);

    def __getattribute__(self, name):
        def realSocketWrapper():
            if ('sProxyType' in self.__dict__ and self.sProxyType and self.realSock):
                return object.__getattribute__(self.realSock, name);
            else:
                return object.__getattribute__(self, name);
        if (
                not name.startswith('__')
                and not name in self.__dict__
                and not name in type(self).__dict__
                and hasattr(super(), name)
                and hasattr(getattr(super(), name), '__call__')
        ):
            return realSocketWrapper();
        else:
            return object.__getattribute__(self, name);

    def setProxy(self, aSrvAddr, sType=_PT_SOCKS5):
        assert self.status == _CS_INIT;
        if (aSrvAddr and hasattr(aSrvAddr, '__iter__') and all(aSrvAddr)):
            sType = sType or _PT_SOCKS5;
            if (not sType == _PT_SOCKS5):
                raise NotImplementedError('only socks5 proxy is supported');
            aSrvAddr = tuple(aSrvAddr);
            assert (
                    len(aSrvAddr) == 2
                    and isinstance(aSrvAddr[0], str)
                    and isinstance(aSrvAddr[1], int) 
            );
            self.aSrvAddr = aSrvAddr;
            self.sProxyType = sType;
            self.negoSock = Socket(socket.AF_INET, socket.SOCK_STREAM);
            if (self._type == socket.SOCK_DGRAM):
                self.udpSock = Socket(socket.AF_INET, socket.SOCK_DGRAM);
                self.realSock = self.udpSock;
            elif (self._type == socket.SOCK_STREAM):
                self.realSock = self.negoSock;
            return True;
        else:
            # pass in None, 0 or (0, 0) as aSrvAddr to unset proxy
            self.aSrvAddr = None;
            self.sProxyType = None;
            if (self.negoSock):
                self.negoSock.close();
                self.negoSock = None;
            if (self.udpSock):
                self.udpSock.close();
                self.udpSock = None;
            self.realSock = None;
            return False;
    
    def getProxy(self):
        if (self.sProxyType):
            return (self.sProxyType, self.aSrvAddr);

    def unsetProxy(self):
        self.setProxy(None);
        return True;

    def setAuth(self, sUsername, sPassword):
        self.sUsername = str(sUsername);
        self.sPassword = str(sPassword);
        return True;

    def _passwordSubNego(self):
        assert self.sUsername and self.sPassword;
        PwdReq = namedtuple('pwdReq', ('ver', 'ulen', 'uname', 'plen', 'passwd'));
        ver = b'\x01';
        ulen = bytes([len(self.sUsername)]);
        uname = self.sUsername.encode();
        plen = bytes([len(self.sPassword)]);
        passwd = self.sPassword.encode();
        pwdReq = PwdReq(ver, ulen, uname, plen, passwd);
        bPwdReq = b''.join(pwdReq);
        writeSock(self.negoSock, bPwdReq);
        PwdRes = namedtuple('PwdRes', ('ver', 'status'));
        bRes = readSock(self.negoSock, 2);
        pwdRes = PwdRes(*struct.unpack('>cc', bRes));
        if (pwdRes.ver == b'\x01'):
            if (pwdRes.status == b'\x00'):
                # authentication pass
                return True;
            else:
                raise Socks5Error('authentication failed');
        else:
            raise Socks5Error('unexpected ver field in authentication response')
        

    def socks5SubNegotiate(self, bMethod):
        assert self.status == _CS_INIT;
        assert bMethod in self.mSocks5['methods'];
        if (bMethod == b'\x00'):
            # no authentication
            return True;
        elif (bMethod == b'\x01'):
            # GSSAPI
            raise NotImplementedError;
        elif (bMethod == b'\x02'):
            # username/password authentication
            return self._passwordSubNego();
        else:
            raise Socks5Error('not supported subnegotiation method');

    def _sendNego(self, bMethods):
        assert self.negoSock;
        sock = self.negoSock;
        try:
            sock.getpeername();
        except OSError:
            raise GeneralError('socket not connected');
        bVer = SOCKS5VER;
        bNmethods = bytes([len(bMethods)]);
        bNego = b''.join((bVer, bNmethods, bMethods));
        writeSock(sock, bNego);
        return True;

    def _recvNego(self):
        assert self.negoSock;
        sock = self.negoSock;
        bReply = readSock(sock, 2);
        negoRep = Socks5NegoRep(*struct.unpack('>cc', bReply));
        if (negoRep.ver != SOCKS5VER):
            raise Socks5Error('wrong version code');
        if (negoRep.method == b'\xff'):
            raise Socks5Error('no method accepted by the server');
        elif (negoRep.method in self.mSocks5['methods']):
            self.mSocks5['method'] = negoRep.method;
        else:
            raise Socks5Error('unexpected method');
        return True;

    def socks5Negotiate(self):
        assert self.status == _CS_INIT;
        assert self.aSrvAddr;
        if (not self.negoSock):
            self.negoSock = Socket(socket.AF_INET, socket.SOCK_STREAM);
        self.negoSock.connect(self.aSrvAddr);
        bMethods = b''.join(self.mSocks5['methods']);
        self._sendNego(bMethods);
        self._recvNego();
        bMethod = self.mSocks5['method'];
        if (bMethod and bMethod != b'\x00'):
            self.socks5SubNegotiate(bMethod);
        self.status = _CS_NEGO;
        return True;

    def _sendRequest(self, bCmd, aDstAddr, isRemoteDns=True):
        assert bCmd in mSocks5Cmd;
        assert self.negoSock;
        sock = self.negoSock;
        sDstHost, nDstPort = aDstAddr;
        if (isRemoteDns):
            if (checkIp(sDstHost)):
                bAtyp = IPV4TYPE;
                bDstaddr = socket.inet_aton(sDstHost);
            else:
                bAtyp = DOMAINTYPE;
                bDstHost = sDstHost.encode();
                bDstaddr = bytes([len(bDstHost)]) + bDstHost;
        else:
            bAtyp = IPV4TYPE;
            bDstaddr = socket.inet_aton(socket.gethostbyname(sDstHost))
        bDstport = struct.pack('>H', nDstPort);
        bReq = b''.join((SOCKS5VER, bCmd, SOCKS5RSV, bAtyp, bDstaddr, bDstport));
        return writeSock(sock, bReq);

    def _recvReply(self):
        assert self.negoSock;
        sock = self.negoSock;
        ver = readSock(sock, 1);
        assert ver == SOCKS5VER;
        rep = readSock(sock, 1);
        if (not rep == b'\x00'):
            raise Socks5Error('{}: {}'.format(rep, mSocks5Rep.get(rep, None)));
        rsv = readSock(sock, 1);
        assert rsv == SOCKS5RSV;
        atyp = readSock(sock, 1);
        assert atyp in mSocks5Atyp.keys();
        if (atyp == b'\x01'):
            # ipv4 address
            nAddrLength = 4;
            bAddr = readSock(sock, nAddrLength);
            sAddr = socket.inet_ntoa(bAddr);
        elif (atyp == b'\x03'):
            # domain name
            nAddrLength = ord(readSock(sock, 1));
            bAddr = readSock(sock, nAddrLength);
            sAddr = socket.gethostbyname(bAddr);
        elif (atyp == b'\x04'):
            # ipv6 address
            raise Socks5Error('ipv6 is not supported');
        else:
            raise Socks5Error('unexpected reply');
        port = readSock(sock, 2);
        nPort = struct.unpack('>H', port)[0];
        # some socks5 programme does not conform to the standard, such as the client side of ss-libev
        #assert nPort != 0;
        return (sAddr, nPort);

    def socks5Request(self, bCmd, aDstAddr, isRemoteDns=True):
        assert bCmd in mSocks5Cmd;
        assert self.negoSock;
        self._sendRequest(bCmd, aDstAddr, isRemoteDns);
        self.aBndAddr = self._recvReply();
        self.status = _CS_REP;
        return True

    def _sendUdp(self, bData, aDstAddr, isRemoteDns=True):
        #o  if ATYP is X'01' - 10+method_dependent octets smaller
        #o  if ATYP is X'03' - 262+method_dependent octets smaller
        #o  if ATYP is X'04' - 20+method_dependent octets smaller):
        assert self.sProxyType == _PT_SOCKS5;
        assert self._type == socket.SOCK_DGRAM;
        assert self.udpSock;
        if (self.status == _CS_INIT):
            self.socks5Negotiate()
        if (self.status == _CS_NEGO):
            aAnyAddr = ('0.0.0.0', 0)
            self.socks5Request(_SC_UDP, aAnyAddr, False);
        assert self.status == _CS_REP;
        if (self.aBndAddr[0] == '0.0.0.0'):
            self.aBndAddr[0] == self.aSrvAddr[0];
        sock = self.udpSock;
        bRsv = b'\x00\x00';
        bFrag = b'\x00';
        sDstHost, nDstPort = aDstAddr;
        if (isRemoteDns):
            if (checkIp(sDstHost)):
                bAtyp = IPV4TYPE;
                bDstaddr = socket.inet_aton(sDstHost);
            else:
                bAtyp = DOMAINTYPE;
                bDstHost = sDstHost.encode();
                bDstaddr = bytes([len(bDstHost)]) + bDstHost;
        else:
            bAtyp = IPV4TYPE;
            bDstaddr = socket.inet_aton(socket.gethostbyname(sDstHost))
        bDstport = struct.pack('>H', nDstPort);
        bUdp = b''.join((bRsv, bFrag, bAtyp, bDstaddr, bDstport, bData));
        return sock.sendto(bUdp, self.aBndAddr);

    def _recvUdp(self, bufsize):
        #o  if ATYP is X'01' - 10+method_dependent octets smaller
        #o  if ATYP is X'03' - 262+method_dependent octets smaller
        #o  if ATYP is X'04' - 20+method_dependent octets smaller):
        assert self.sProxyType == _PT_SOCKS5;
        assert self._type == socket.SOCK_DGRAM;
        assert self.udpSock;
        assert self.status == _CS_REP;
        # suppose the socks5 server only return ip address type, so bufsize should be 10 octets bigger
        bufsize += 10;
        sock = self.udpSock;
        # UDP packet should be received in one single I/O operation
        bData, aSrcAddr = sock.recvfrom(bufsize);
        mv = memoryview(bData);
        rsv = mv[:2];
        mv = mv[2:];
        if (not rsv == b'\x00' * 2):
            raise Socks5Error('rsv bytes should be all 0x00');
        frag = mv[:1];
        mv = mv [1:];
        if (not frag == b'\x00'):
            raise Socks5Error('FRAG field is not supported');
        atyp = mv[:1];
        mv = mv[1:];
        assert atyp in mSocks5Atyp;
        if (atyp == b'\x01'):
            # ipv4 address
            nAddrLength = 4;
            bAddr = mv[:nAddrLength];
            mv = mv[nAddrLength:];
            sAddr = socket.inet_ntoa(bAddr);
        elif (atyp == b'\x03'):
            # domain name
            nAddrLength = struct.unpack('>B', mv[:1])[0];
            bAddr = mv[1:1+nAddrLength].tobytes();
            mv = mv[1+nAddrLength:];
            sAddr = socket.gethostbyname(bAddr);
        elif (atyp == b'\x04'):
            # ipv6 address
            raise Socks5Error('ipv6 is not supported');
        else:
            raise Socks5Error('unexpected reply');
        port = mv[:2];
        nPort = struct.unpack('>H', port)[0];
        bData = mv[2:].tobytes();
        if (aSrcAddr == self.aBndAddr):
            return (bData, (sAddr, nPort));
        else:
            return None;

    # overwrite socket methods

    def listen(self, backlog=0):
        if (self.sProxyType == _PT_SOCKS5 and self.isSocks5Bound):
            pass
        elif (not self.sProxyType):
            return super().listen(backlog);

    def accept(self):
        if (self.sProxyType == _PT_SOCKS5 and self.isSocks5Bound):
            # receive second reply to bind command
            assert self.status == _CS_BND_FIRST;
            aDstAddr = self._recvReply();
            self.status = _CS_BND_SECOND;
            return (self, aDstAddr);
        elif (not self.sProxyType):
            return super().accept();

    def bind(self, aBndAddr, isSocks5Bind=False):
        # explanation of socks5 binding in rfc1928 is too sketchy and ambiguous
        # my binding implementation might differ form the RFC
        # socks5 binding is not tested
        assert not self.isBound;
        if (self.sProxyType == _PT_SOCKS5):
            if (self._type == socket.SOCK_DGRAM):
                assert self.udpSock;
                self.udpSock.bind(aBndAddr);
            elif (self._type == socket.SOCK_STREAM):
                if (isSocks5Bind):
                    if (self.status == _CS_INIT):
                        self.socks5Negotiate()
                    if (self.isSocks5Bound):
                        raise Socks5Error('this socks5 socket has already been bound');
                    self.socks5Request(_SC_BIND, aBndAddr, True);
                    self.isSocks5Bound = True;
                    self.status = _CS_BND_FIRST;
                else:
                    self.negoSock.bind(aBndAddr);
        elif (not self.sProxyType):
            super().bind(aBndAddr);
        self.isBound = True;

    def connect(self, aAddr):
        self.aDstAddr = aAddr;
        if (self.sProxyType == _PT_SOCKS5):
            assert self.aSrvAddr;
            if (self.status == _CS_INIT):
                self.socks5Negotiate()
            if (self._type == socket.SOCK_STREAM):
                # tcp
                assert not self.isConnected and not self.isSocks5Bound;
                self.socks5Request(_SC_CONNECT, aAddr, self.isRemoteDns);
                self.realSock = self.negoSock;
            elif (self._type == socket.SOCK_DGRAM):
                # udp
                assert self.udpSock;
                if (self.status == _CS_NEGO):
                    aAnyAddr = ('0.0.0.0', 0)
                    self.socks5Request(_SC_UDP, aAnyAddr, False);
                    self.realSock = self.udpSock;
                assert self.aBndAddr;
                self.udpSock.connect(self.aBndAddr);
        elif (not self.sProxyType):
            super().connect(aAddr);
        else:
            raise Socks5Error('not expected proxy type: {}'.format(self.sProxyType))
        self.isConnected = True;
        return True;

    def getpeername(self):
        if (self.sProxyType and self.aDstAddr):
            return self.aDstAddr;
        else:
            return super().getpeername();

    def getsockname(self):
        if (self.sProxyType):
            if (self._type == socket.SOCK_STREAM):
                return self.negoSock.getsockname();
            else:
                if (self.isSocks5Bound):
                    return self.aBndAddr;
                else:
                    return self.udpSock.getsockname();
        else:
            return super().getsockname();

    def recv(self, bufsize, *args, **kargs):
        'the maximum bufsize will be smaller than the original system limit due to additional socks5 header';
        if (self.sProxyType == _PT_SOCKS5):
            if (self._type == socket.SOCK_DGRAM):
                assert self.status == _CS_REP;
                bData, _ =  self._recvUdp(bufsize);
                return bData;
            elif (self._type == socket.SOCK_STREAM):
                assert self.status in (_CS_REP, _CS_BND_SECOND);
                return self.negoSock.recv(bufsize, *args, **kargs);
        elif (not self.sProxyType):
            return super().recv(bufsize, *args, **kargs);

    def recvfrom(self, bufsize, *args, **kargs):
        if (self.sProxyType == _PT_SOCKS5):
            if (self._type == socket.SOCK_DGRAM):
                assert self.status == _CS_REP;
                bData, aAddr = self._recvUdp(bufsize);
                return (bData, aAddr);
            elif (self._type == socket.SOCK_STREAM):
                assert self.status in (_CS_REP, _CS_BND_SECOND);
                return self.negoSock.recvfrom(bufsize, *args, **kargs);
        elif (not self.sProxyType):
            return super().recvfrom(bufsize, *args, **kargs);

    def recv_into(self, buffer, nbytes=0, *args, **kargs):
        # recv_into will be used by makefile method
        if (not nbytes):
            nbytes = 0;
        if (self.sProxyType == _PT_SOCKS5):
            if (self._type == socket.SOCK_DGRAM):
                assert self.status == _CS_REP;
                if (nbytes > 0 and len(buffer) > nbytes):
                    nSize = nbytes;
                else:
                    nSize = len(buffer)
                bData, _ =  self._recvUdp(nSize);
                buffer[:nSize] = bData;
                return nSize;
            elif (self._type == socket.SOCK_STREAM):
                assert self.status in (_CS_REP, _CS_BND_SECOND);
                return self.negoSock.recv_into(buffer, nbytes, *args, **kargs);
        elif (not self.sProxyType):
            return super().recv_into(buffer, nbytes, *args, **kargs);

    def send(self, bData):
        if (self.sProxyType == _PT_SOCKS5):
            assert self.isConnected;
            if (self._type == socket.SOCK_DGRAM):
                return self._sendUdp(bData, self.aDstAddr);
            elif (self._type == socket.SOCK_STREAM):
                assert self.status in (_CS_REP, _CS_BND_SECOND);
                return self.negoSock.send(bData);
        else:
            return super().send(bData);

    def sendall(self, bData):
        if (self.sProxyType == _PT_SOCKS5):
            assert self.isConnected;
            if (self._type == socket.SOCK_DGRAM):
                return self._sendUdp(bData, self.aDstAddr);
            elif (self._type == socket.SOCK_STREAM):
                assert self.status in (_CS_REP, _CS_BND_SECOND);
                return self.negoSock.sendall(bData);
        else:
            return super().sendall(bData);

    def sendto(self, bData, aAddr):
        if (self.sProxyType == _PT_SOCKS5):
            if (self._type == socket.SOCK_DGRAM):
                return self._sendUdp(bData, aAddr);
            elif (self._type == socket.SOCK_STREAM):
                assert self.status in (_CS_REP, _CS_BND_SECOND);
                self.negoSock.send(bData);
        elif (not self.sProxyType):
            return super().sendto(bData, aAddr);

    def settimeout(self, value):
        if (self.sProxyType == _PT_SOCKS5):
                assert self.realSock;
                return self.realSock.settimeout(value);
        elif (not self.sProxyType):
            return super().settimeout(value);

    def gettimeout(self):
        if (self.sProxyType == _PT_SOCKS5):
                assert self.realSock;
                return self.realSock.gettimeout();
        elif (not self.sProxyType):
            return super().gettimeout();

    def setsockopt(self, *args, **kargs):
        if (self.sProxyType == _PT_SOCKS5):
                assert self.realSock;
                return self.realSock.setsockopt(*args, **kargs);
        elif (not self.sProxyType):
            return super().setsockopt(*args, **kargs);

    def getsockopt(self, *args, **kargs):
        if (self.sProxyType == _PT_SOCKS5):
                assert self.realSock;
                return self.realSock.getsockopt(*args, **kargs);
        elif (not self.sProxyType):
            return super().getsockopt(*args, **kargs);

    def close(self):
        self.status = _CS_DEAD;
        super().close();
        if (self.negoSock):
            # if the _io_refs attribute of socket object comes to 0, the underline _socket.socket object will be really closed and it will no longer be readable
            # and due to the same reason, socket object might and should still be readable even after being closed sometimes, so don't assign None to it
            self.negoSock._io_refs = self._io_refs;
            self.negoSock.close();
            #self.negoSock = None;
        if (self.udpSock):
            self.udpSock._io_refs = self._io_refs;
            self.udpSock.close();
            #self.udpSock = None;
        #self.realSock = None;

class Socks5HttpConnection(http.client.HTTPConnection):
    def __init__(self, *args, aAddr=None, sType=None, aAuth=None, **kargs):
        # pass in None as aAddr to use default proxy setting
        # pass in sequence with any element corresponding to False as aAddr to disable proxy
        super().__init__(*args, **kargs);
        self._aProxy = None;
        self._aAuth = None;
        self.setProxy(aAddr, sType);
        self.setAuth(aAuth);
        # self._create_connection will be used by HTTPConnection.connect
        # the original _create_connection will do DNS lookup locally before make connection, so it should be overwriten to fulfil remote DNS lookup 
        self._create_connection = self.createRemoteDnsConnection;
    def setProxy(self, aAddr, sType=_PT_SOCKS5):
        if (aAddr):
            self._aProxy = (aAddr, sType);
        else:
            self._aProxy = None;
    def setAuth(self, aAuth):
        if (aAuth and len(aAuth) == 2 and all(aAuth)):
            self._aAuth = aAuth;
        else:
            self._aAuth = None;
    def createRemoteDnsConnection(self, address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None):
        sock = Socks();
        if (timeout is None or type(timeout) in (int, float)):
            sock.settimeout(timeout);
        if (self._aProxy):
            sock.setProxy(*self._aProxy);
        if (self._aAuth):
            sock.setAuth(*self._aAuth);
        if (source_address):
            sock.bind(source_address);
        sock.connect(address);
        return sock;

class Socks5HttpsConnection(http.client.HTTPSConnection, Socks5HttpConnection):
    def __init__(self, *args, aAddr=None, sType=None, aAuth=None, **kargs):
        # super() delegates __init__ to HTTPSConnection
        super().__init__(*args, **kargs);
        self._aProxy = None;
        self._aAuth = None;
        self.setProxy(aAddr, sType);
        self.setAuth(aAuth);
        self._create_connection = self.createRemoteDnsConnection;

class Socks5HttpHandler(urllib.request.HTTPHandler):
    def __init__(self, *args, aAddr=None, sType=None, aAuth=None, **kargs):
        super().__init__(*args, **kargs);
        self.aAddr = aAddr;
        self.sType = sType;
        self.aAuth = aAuth;
    def http_open(self, req):
        return self.do_open(Socks5HttpConnection, req, aAddr=self.aAddr, sType=self.sType, aAuth=self.aAuth);

class Socks5HttpsHandler(urllib.request.HTTPSHandler):
    def __init__(self, *args, aAddr=None, sType=None, aAuth=None, **kargs):
        super().__init__(*args, **kargs);
        self.aAddr = aAddr;
        self.sType = sType;
        self.aAuth = aAuth;
    def https_open(self, req):
        return self.do_open(Socks5HttpsConnection, req, context=self._context, check_hostname=self._check_hostname, aAddr=self.aAddr, sType=self.sType, aAuth=self.aAuth);

class Socks5Handler(Socks5HttpsHandler, Socks5HttpHandler):
    # the __init__ method to be invoked will be the https one, but its side effect shall not affcet functionality of the http one
    pass

def setDefaultProxy(aSrvAddr, sType= _PT_SOCKS5):
    Socks.aDefaultProxy = (aSrvAddr, sType);

def getDefaultProxy():
    return Socks.aDefaultProxy;

def test():
    # suppose that socks5 server is listening on localhost, probably port 1081

    import sys
    sHost = 'localhost';
    nPort = 1081;
    if (sys.argv[2:3]):
        sHost = str(sys.argv[1]);
        nPort = int(sys.argv[2]);
    elif (sys.argv[1:2]):
        nPort = int(sys.argv[1]);

    print('proxied socket operation:');
    tcpSock = Socks();
    tcpSock.setProxy((sHost, nPort));
    tcpSock.connect(('myip.ipip.net', 80));
    tcpSock.sendall((b'GET / HTTP/1.1\r\nHost: myip.ipip.net\r\n\r\n'));
    print(tcpSock.recv(4096).decode());
    tcpSock.close();

    print('proxy using http handler whose __init__ explictly specifies proxy server:');
    opener = urllib.request.build_opener(Socks5HttpHandler(aAddr=(sHost, nPort)));
    res = opener.open('http://myip.ipip.net/')
    print(res.read().decode())
    res.close();

    print('set in class level the default proxy server address');
    setDefaultProxy((sHost, nPort));

    print('proxy using https handler:');
    opener = urllib.request.build_opener(Socks5HttpsHandler);
    res = opener.open('https://myip.ipip.net/')
    print(res.read().decode())
    res.close()

    print('proxy using handler supporting both http and https and explicitly disable the default proxy setting while instantiate opener:');
    opener = urllib.request.build_opener(Socks5Handler(aAddr=(0, 0)));
    res = opener.open('https://myip.ipip.net/')
    print(res.read().decode())
    res.close()

    #print('access google using proxied opener');
    #opener = urllib.request.build_opener(Socks5Handler);
    #res = opener.open('https://www.google.com/')
    #print(res.read())
    #res.close()

    #udpSock = Socks(socket.AF_INET, socket.SOCK_DGRAM);
    #udpSock.setProxy((sHost, nPort));
    #udpSock.sendto(b'sdfds', ('localhost', 7777));
    #print(udpSock.recvfrom(4096));

    #bndSock = Socks();
    #bndSock.setProxy((sHost, nPort));
    #bndSock.bind(('0.0.0.0', 6666), True);
    #sock, aAddr = bndSock.accept();
    #print(sock, aAddr);
    #print(sock.recvfrom(4096));

    print('end');

if __name__ == '__main__':
    test()
