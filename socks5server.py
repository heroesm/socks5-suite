#! /usr/bin/env python3
#TODO: add GSSAPI support
#TODO: rewrite using transports or streams in separate .py file

import sys
import asyncio
import socket
import logging
import struct
import re
from collections import namedtuple, deque

# used as the default value for username/password subnegotiation
USERNAME = '';
PASSWORD = '';

PORT = 1081;

# time in seconds to wait before a connection complete its negotiation
NEGOTIMEOUT = 30;

LOGLEVEL = logging.DEBUG;

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

# server status
_SS_INIT = 'initialised';
_SS_START = 'started';
_SS_CLOSE = 'closed';

# connection status
_CS_INIT = 'initialised';
_CS_NEGO = 'negotiated';
_CS_REP = 'replied';
#_CS_BND_FIRST = 'first reply to bind command sent';
#_CS_BND_SECOND = 'second reply to bind command sent, meanging successful listening';
_CS_DEAD = 'dead';

log = None;

def prepare():
    global log
    log = logging.getLogger();
    log.setLevel(LOGLEVEL);
    logging.basicConfig(
            format= '    %(asctime)s %(levelname)-5s - %(filename)s:%(lineno)d: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
    );
    socket.setdefaulttimeout(0);
prepare();

def localAddr(sRemote=None):
    sock1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM);
    sRemote = sRemote or '1.1.1.1';
    sock1.connect((sRemote, 1));
    sAddr = sock1.getsockname()[0]
    sock1.close();
    return sAddr;

def checkIp(sHost):
    # check whether the host name is ip address
    sIpPattern = r'^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$'
    return bool(re.search(sIpPattern, sHost));

async def asyncRead(sock, nSize, loop=None):
    if (not loop):
        loop = asyncio.get_event_loop();
    oriTimeout = sock.gettimeout();
    if (oriTimeout != 0):
        sock.settimeout(0);
    bData = b'';
    while (len(bData) < nSize):
        bRecv = await loop.sock_recv(sock, nSize - len(bData));
        if (bRecv):
            bData += bRecv;
        else:
            raise DeadConnectionError('socks5 connection lost');
    sock.settimeout(oriTimeout);
    #print('read :{}'.format(bData));
    return bData;

async def asyncWrite(sock, bData, loop=None):
    if (not loop):
        loop = asyncio.get_event_loop();
    oriTimeout = sock.gettimeout();
    if (oriTimeout != 0):
        sock.settimeout(0);
    loop.sock_sendall(sock, bData);
    sock.settimeout(oriTimeout);
    #print('write :{}'.format(bData));
    return True;

class GeneralError(Exception):
    pass

class DeadConnectionError(Exception):
    pass

class Socks5Error(Exception):
    def __init__(self, msg, code=None):
        self.msg = msg;
        self.code = code;

class Socks5Connection():

    def __init__(self, server, cliSock, loop=None):
        if (not loop):
            loop = asyncio.get_event_loop();
        self.loop = loop;
        self.server = server; # Socks5Server object
        self.cliSock = cliSock; # socks5 negotiation socket
        self.aCliAddr = self.cliSock.getpeername();
        self.bndSock = None; # used in bind command as remote-bound socket
        self.incSock = None; # used in bind command to accept incoming connection
        self.tarSock = None; # associated with dstaddr and dstport
        self.udpSock = None; # delegated to relay UDP packet
        self.aValidAddr = None; # permited client address in UDP association
        self.aTarAddr = None; # normally equal to (dstaddr, dstport)
        self.bCommand = None;
        self.sCommand = None; # not used
        self.aTasks = []; # for cleanup
        self.status = _CS_INIT;

    def _wrapSocks5Udp(self, bData, aAddr):
        rsv = b'\x00\x00';
        frag = b'\x00';
        atyp = IPV4TYPE;
        sAddr, nPort = aAddr;
        dstaddr = socket.inet_aton(sAddr);
        dstport = struct.pack('>H', nPort);
        bData = b''.join((rsv, frag, atyp, dstaddr, dstport, bData));
        return bData;

    def _parseSocks5Udp(self, bData):
        mv = memoryview(bData);
        rsv, frag, atyp = struct.unpack('>HBc', mv[:4]);
        mv = mv[4:];
        if (rsv != 0 or frag != 0 or not atyp in (IPV4TYPE, DOMAINTYPE)):
            raise Socks5Error('invalid socks5 UDP header');
        if (atyp == IPV4TYPE):
            nAddrLength = 4;
            sAddr = socket.inet_ntoa(mv[:nAddrLength]);
            isDomainName = False;
            mv = mv[nAddrLength:];
        elif (atyp == DOMAINTYPE):
            nAddrLength = struct.unpack('>B', (mv[:1]))[0];
            sAddr = mv[1:1+nAddrLength].tobytes().decode();
            isDomainName = True;
            mv = mv[1+nAddrLength:];
        nPort = struct.unpack('>H', mv[:2])[0];
        data = mv[2:];
        return (data, (sAddr, nPort), isDomainName);

    async def udpForward(self):
        # there are no loop.sock_recvfrom interface, so if we need using recvfrom but don't want to use the high level Transports and Streams, we can utilise the low level methods like add_reader
        log.debug('starting UDP forward on {}'.format(self.udpSock.getsockname()));
        assert self.udpSock and self.aValidAddr;

        mDstToCli = {}; # {aDstAddr1: aSrcAddr, aDstAddr2: aSrcAddr, ...}
        backlogs = deque(); # ((bytearray1, aAddr1), (bytearray2, aAddr2), ...)
        domainQueue = asyncio.Queue(loop=self.loop);
        sValidHost = self.aValidAddr[0];
        nValidPort = self.aValidAddr[1];
        def reader():
            # within callback function of add_reader and add_writer, type of TCP socket and UDP socket will be altered to 2049 and 2050 respectively; mystical mechanism
            self.udpSock.settimeout(0);
            try:
                bData, aSrcAddr = self.udpSock.recvfrom(65536);
            except (BlockingIOError, InterruptedError):
                pass
            else:
                if (
                        sValidHost == aSrcAddr[0]
                        and (nValidPort == 0 or nValidPort == aSrcAddr[1])
                ):
                    # from client to destination
                    try:
                        bData, aDstAddr, isDomainName = self._parseSocks5Udp(bData);
                    except Socks5Error as e:
                        # malformed socks5 udp packet; silently drop it
                        pass
                    else:
                        if (isDomainName):
                            domainQueue.put_nowait(
                                    (bytearray(bData), aSrcAddr, aDstAddr)
                            );
                        else:
                            mDstToCli[aDstAddr] = aSrcAddr;
                            backlogs.append((bytearray(bData), aDstAddr));
                else:
                    # from destination to client
                    bData = self._wrapSocks5Udp(bData, aSrcAddr);
                    backlogs.append((bytearray(bData), mDstToCli[aSrcAddr]));
                self.loop.add_writer(self.udpSock, writer);
        def writer():
            self.udpSock.settimeout(0);
            if (backlogs):
                buffer, aAddr = backlogs[0];
                try:
                    nSend = self.udpSock.sendto(buffer, aAddr);
                except (BlockingIOError, InterruptedError):
                    pass
                else:
                    del buffer[:nSend];
                    if (not buffer):
                        backlogs.popleft();
            else:
                self.loop.remove_writer(self.udpSock)
        async def resolveDomainName():
            while self.status != _CS_DEAD:
                bData, aSrcAddr, aDstAddr = await domainQueue.get();
                addr = await self.loop.getaddrinfo(*aDstAddr, family=socket.AF_INET);
                aDstAddr = addr[0][-1];
                mDstToCli[aDstAddr] = aSrcAddr;
                backlogs.append((bytearray(bData), aDstAddr));
                self.loop.add_writer(self.udpSock, writer);
        self.loop.add_reader(self.udpSock, reader);
        self.loop.add_writer(self.udpSock, writer);
        self.aTasks.extend([
                self.loop.create_task(resolveDomainName())
        ]);

    async def tcpRelay(self, srcSock, dstSock):
        log.debug('starting TCP relay from {} to {}'.format(
            srcSock.getpeername(), dstSock.getpeername()
        ));
        while (self.status != _CS_DEAD):
            bData = await self.loop.sock_recv(srcSock, 65536);
            #print('relay from {} to {} : {}'.format(srcSock.getpeername(), dstSock.getpeername(), bData[:5]));
            await self.loop.sock_sendall(dstSock, bData);
            if (bData == b''):
                log.debug('TCP relay connection from {} to {} lost'.format(
                    srcSock.getpeername(), dstSock.getpeername()
                ));
                break;
        self.close();

    async def _sendError(self, bCode):
        log.debug('replying failure to {}'.format(self.aCliAddr));
        bReply = struct.pack('>ccccLH', SOCKS5VER, bCode, SOCKS5RSV, IPV4TYPE, 0, 0);
        await asyncWrite(self.cliSock, bReply, self.loop);

    async def _sendReply(self, aAddr):
        log.debug('replying success to {}'.format(self.aCliAddr));
        assert aAddr;
        assert checkIp(aAddr[0]);
        ver = SOCKS5VER;
        rep = b'\x00';
        rsv = SOCKS5RSV;
        atyp = IPV4TYPE;
        sAddr, nPort = aAddr;
        if (sAddr == '0.0.0.0'):
            # in UDP association, the UDP socket may be accessible to different interface in favour of forwarding, in which case sAddr shall be '0.0.0.0' and will be replaced with the address accessible to the client
            sAddr = localAddr(self.aCliAddr[0]);
        bndaddr = socket.inet_aton(sAddr);
        bndport = struct.pack('>H', nPort);
        bReply = b''.join((ver, rep, rsv, atyp, bndaddr, bndport));
        await asyncWrite(self.cliSock, bReply, self.loop);

    async def _doConnect(self):
        log.debug('handling Connect command');
        assert (self.bCommand == _SC_CONNECT);
        self.tarSock = socket.socket();
        self.tarSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1);
        self.tarSock.settimeout(0);
        await self.loop.sock_connect(self.tarSock, self.aTarAddr);

    async def _doBind(self):
        # this bind implementation does not conform to RFC 1928
        # it functions literally like remote-binding

        # indeed not asynchronous
        log.debug('handling Bind command');
        self.bndSock = socket.socket();
        self.bndSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1);
        self.bndSock.settimeout(0);
        try:
            # as RFC 1928, the aTarAddr should have been used to filter the address of incoming connection
            self.bndSock.bind(self.aTarAddr);
        except (PermissionError, OSError):
            pass
        self.bndSock.listen(0);

    async def _doUdpAssociation(self):
        # indeed not asynchronous
        log.debug('handling UDP Association');
        self.udpSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM);
        self.udpSock.settimeout(0);
        self.udpSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1);
        #sLocalHost = localAddr(self.aCliAddr[0]);
        self.udpSock.bind(('', 0));
        sHost, nPort = self.aTarAddr;
        if (sHost == '0.0.0.0' or not checkIp(sHost)):
            sHost = self.aCliAddr[0];
        self.aValidAddr = (sHost, nPort);

    async def _recvRequest(self):
        assert self.status == _CS_NEGO;
        ver = await asyncRead(self.cliSock, 1, self.loop);
        if (ver != SOCKS5VER):
            raise Socks5Error('wrong ver field in negotiation');
        cmd = await asyncRead(self.cliSock, 1, self.loop);
        if (not cmd in mSocks5Cmd):
            raise Socks5Error('unexpected socks5 command', b'\x07')
        self.bCommand = cmd;
        self.sCommand = mSocks5Cmd[cmd];
        rsv = await asyncRead(self.cliSock, 1, self.loop);
        if (rsv != SOCKS5RSV):
            raise Socks5Error('wrong rsv field');
        atyp = await asyncRead(self.cliSock, 1, self.loop);
        if (atyp == IPV4TYPE):
            nAddrLength = 4;
            bAddr = await asyncRead(self.cliSock, nAddrLength, self.loop);
            sAddr = socket.inet_ntoa(bAddr);
        elif (atyp == DOMAINTYPE):
            nAddrLength = ord(await asyncRead(self.cliSock, 1, self.loop));
            bAddr = await asyncRead(self.cliSock, nAddrLength, self.loop);
            sAddr = bAddr.decode();
            sAddr = (await self.loop.getaddrinfo(sAddr, None, family=socket.AF_INET))[0][-1][0];
        elif (atyp == IPV6TYPE):
            raise Socks5Error('IPV6 address is not supported', b'\x08');
        else:
            raise Socks5Error('unexpected atyp field in request', b'\x08');
        port = await asyncRead(self.cliSock, 2, self.loop);
        nPort = struct.unpack('>H', port)[0];
        self.aTarAddr = (sAddr, nPort);
        log.debug('received "{}" command request with dstaddr {}'.format(
            self.sCommand, self.aTarAddr
        ));

    async def process(self):
        try:
            await self._recvRequest();
        except Socks5Error as e:
            bCode = e.code or b'\x01';
            log.error('socks5 error {}: {}'.format(bCode, mSocks5Rep[bCode]));
            await self._sendError(bCode);
            raise;
        else:
            assert self.aTarAddr; # from dstaddr and dstport
            if (self.bCommand == _SC_CONNECT):
                await self._doConnect();
                self.aTasks.extend([
                    self.loop.create_task(self.tcpRelay(self.cliSock, self.tarSock)),
                    self.loop.create_task(self.tcpRelay(self.tarSock, self.cliSock)),
                    self.loop.create_task(self._sendReply(self.tarSock.getsockname())),
                ]);
            elif (self.bCommand == _SC_BIND):
                await self._doBind();
                await self._sendReply(self.bndSock.getsockname());
                self.incSock, aIncAddr = await self.loop.sock_accept(self.bndSock);
                self.aTasks.extend([
                    self.loop.create_task(self.tcpRelay(self.cliSock, self.incSock)),
                    self.loop.create_task(self.tcpRelay(self.incSock, self.cliSock)),
                    self.loop.create_task(self._sendReply(aIncAddr)),
                ]);
            elif (self.bCommand == _SC_UDP):
                await self._doUdpAssociation();
                self.aTasks.extend([
                    self.loop.create_task(self.udpForward()),
                    self.loop.create_task(self._sendReply(self.udpSock.getsockname())),
                ]);
            self.status = _CS_REP;
        return True;

    async def _pwdSubNego(self):
        log.debug('starting username/password sub-negotiation');
        VER = b'\x01';
        SUCCESS = b'\x00';
        FAILURE = b'\x01';
        sUsername = self.server.sUsername;
        sPassword = self.server.sPassword;
        assert sUsername and sPassword;
        ver = await asyncRead(self.cliSock, 1, self.loop);
        if (ver != VER):
            raise Socks5Error('wrong ver field in password subnegotiation');
        ulen = await asyncRead(self.cliSock, 1, self.loop);
        nLen = ord(ulen);
        uname = await asyncRead(self.cliSock, nLen, self.loop);
        plen = await asyncRead(self.cliSock, 1, self.loop);
        nLen = ord(plen);
        passwd = await asyncRead(self.cliSock, nLen, self.loop);
        if (uname.decode() == sUsername and passwd.decode() == sPassword):
            bRes = struct.pack('>cc', VER, SUCCESS);
            await asyncWrite(self.cliSock, bRes, self.loop);
            return True;
        else:
            bRes = struct.pack('>cc', VER, FAILURE);
            await asyncWrite(self.cliSock, bRes, self.loop);
            raise Socks5Error('authentication failed');

    async def subNego(self, bMethod):
        assert bMethod in self.server.aMethods;
        if (bMethod == b'\x00'):
            # no authentication
            return True;
        elif (bMethod == b'\x01'):
            # GSSAPI
            raise NotImplementedError;
        elif (bMethod == b'\x02'):
            # username/password authentication
            return await self._pwdSubNego();
        else:
            raise Socks5Error('not supported subnegotiation method');

    async def nego(self):
        log.debug('starting negotiation from {}'.format(self.aCliAddr));
        ver = await asyncRead(self.cliSock, 1, self.loop);
        if (ver != SOCKS5VER):
            raise Socks5Error('wrong ver field in negotiation');
        nmethods = await asyncRead(self.cliSock, 1, self.loop);
        nLength = ord(nmethods);
        methods = await asyncRead(self.cliSock, nLength, self.loop);
        aMethods = [bytes([x]) for x in methods];
        for bMethod in self.server.aMethods:
            if (bMethod) in aMethods:
                break;
        else:
            raise Socks5Error('no acceptable method');
        bReply = b''.join((SOCKS5VER, bMethod));
        await asyncWrite(self.cliSock, bReply, self.loop);
        if (bMethod != b'\x00'):
            await self.subNego(bMethod);
        self.status = _CS_NEGO;

    async def start(self):
        try:
            self.loop.call_later(NEGOTIMEOUT, self.negoTimeoutCheck);
            await self.nego();
            await self.process();
        except (Socks5Error, DeadConnectionError) as e:
            log.error(e);
            self.close();

    def negoTimeoutCheck(self):
        if (self.status == _CS_INIT):
            self.close();
            log.debug('negotiation timeout, connection closed');

    def close(self):
        if (self.status == _CS_DEAD):
            return False;
        else:
            log.debug('closing connection from {}'.format(self.aCliAddr));
            self.status = _CS_DEAD;
            if (self.udpSock):
                self.loop.remove_reader(self.udpSock);
                self.loop.remove_writer(self.udpSock);
            for task in self.aTasks:
                if (not task.cancelled()):
                    self.loop.call_soon_threadsafe(task.cancel);
            self.aTasks = [];
            if (self.cliSock):
                # if the cliSock is closed immediately, subsequent other socks5 connection's i/o operation may fail silently
                self.loop.call_later(0.1, self.cliSock.close);
            if (self.tarSock):
                self.loop.call_later(0.1, self.tarSock.close);
            if (self.udpSock):
                self.udpSock.close();
            log.debug('connection from {} closed'.format(self.aCliAddr));
            return True;

class Socks5Server():

    def __init__(self, aSrvAddr, loop=None, aMethods=None, sUsername=None, sPassword=None):
        if (not loop):
            loop = asyncio.get_event_loop();
        self.loop = loop;
        self.aSrvAddr = aSrvAddr;
        self.srvSock = None;
        # preceding method in aMethods will be preferred
        self.aMethods = aMethods or [b'\x02', b'\x00'];
        self.sUsername = sUsername or USERNAME;
        self.sPassword = sPassword or PASSWORD;
        if (b'\x02' in self.aMethods):
            if (not self.sUsername or not self.sPassword):
                del self.aMethods[self.aMethods.index(b'\x02')];
        self.aConnections = [];
        self.status = _SS_INIT;

    async def listen(self):
        log.info('socks5 server lisening on {}'.format(self.srvSock.getsockname()));
        while self.status !=_SS_CLOSE:
            (cliSock, aCliAddr) = await self.loop.sock_accept(self.srvSock);
            socks5Conn = Socks5Connection(self, cliSock, self.loop);
            self.aConnections.append(socks5Conn);
            self.loop.create_task(socks5Conn.start());

    def start(self):
        if (not self.srvSock):
            self.srvSock = socket.socket();
        self.srvSock.settimeout(0);
        self.srvSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1);
        self.srvSock.bind(self.aSrvAddr);
        self.srvSock.listen(500);
        self.loop.create_task(self.listen());
        self.status = _SS_START;
        try:
            self.loop.run_forever();
        except KeyboardInterrupt as e:
            pass
        finally:
            self.close();

    def close(self):
        log.info('closing socks5 server...');
        self.status = _SS_CLOSE;
        self.srvSock.close();
        for conn in self.aConnections:
            conn.close();
        self.aConnections = [];
        for task in asyncio.Task.all_tasks():
            if (not task.cancelled()):
                task.cancel();
        self.loop.run_until_complete(asyncio.sleep(0));
        self.loop.close();

def main():
    nPort = PORT;
    if (sys.argv[1:2]):
        nPort = int(sys.argv[1]);
    assert nPort;
    loop = asyncio.get_event_loop();
    #loop.set_debug(True);
    server = Socks5Server(('', nPort), loop);
    server.start();

if __name__ == '__main__':
    main()
