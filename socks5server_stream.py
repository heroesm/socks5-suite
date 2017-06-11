#! /usr/bin/env python3
#TODO: add GSSAPI support

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

class GeneralError(Exception):
    pass

class DeadConnectionError(Exception):
    pass

class Socks5Error(Exception):
    def __init__(self, msg, code=None):
        self.msg = msg;
        self.code = code;

class TcpStream():

    def __init__(self, reader=None, writer=None, loop=None):
        loop = loop or asyncio.get_event_loop();
        self.loop = loop;
        self.reader = reader;
        self.writer = writer;
        if (self.writer):
            self.aDstAddr = self.writer.get_extra_info('peername');
            self.aBndAddr = self.writer.get_extra_info('sockname');

    async def connect(self, aAddr):
        sHost, nPort = aAddr;
        self.reader, self.writer = await asyncio.open_connection(
                sHost, nPort, loop=self.loop, family=socket.AF_INET
        );
        self.aDstAddr = self.writer.get_extra_info('peername');
        self.aBndAddr = self.writer.get_extra_info('sockname');

    async def readAll(self, bSize, isExact=True):
        bOut = b'';
        n = bSize - len(bOut);
        while (n > 0):
            bOut += await self.reader.read(n);
            n = bSize - len(bOut);
            if (not isExact):
                break;
        #print('read from {}: {}', self.aDstAddr, bOut);
        return bOut;

    async def writeAll(self, bData):
        self.writer.write(bData);
        #print('written to {}: {}', self.aDstAddr, bData)
        await self.writer.drain();

    def close(self):
        self.reader.feed_eof();
        self.writer.close();

class Socks5Connection():

    def __init__(self, server, reader, writer, loop=None):
        if (not loop):
            loop = asyncio.get_event_loop();
        self.loop = loop;
        self.server = server; # Socks5Server object
        self.reader = reader;
        self.writer = writer;
        self.aCliAddr = self.writer.get_extra_info('sockname');
        self.stream = TcpStream(reader, writer, loop=loop);
        self.bndSrv = None;
        self.incoming = None;
        self.target = None;
        self.udpSock = None; # delegated to relay UDP packet
        self.aValidAddr = None; # permited client address in UDP association
        self.aTarAddr = None; # normally equal to (dstaddr, dstport)
        self.bCommand = None;
        self.sCommand = None; # not used
        self.aTasks = []; # for cleanup
        self.status = _CS_INIT;

    async def readAll(self, bSize, isExact=True):
        bOut = b'';
        n = bSize - len(bOut);
        while (n > 0):
            bOut += await self.reader.read(n);
            n = bSize - len(bOut);
            if (not isExact):
                break;
        return bOut;

    async def writeAll(self, bData):
        self.writer.write(bData);
        await self.writer.drain();

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
            nAddrLength = struct.unpack('>B', mv[:1])[0];
            sAddr = mv[1:1+nAddrLength].tobytes().decode();
            isDomainName = True;
            mv = mv[1+nAddrLength:];
        nPort = struct.unpack('>H', mv[:2])[0];
        data = mv[2:].tobytes();
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
        self.udpSock.settimeout(0);
        def reader():
            # within callback function of add_reader and add_writer, type of TCP socket and UDP socket will be altered to 2049 and 2050 respectively; mystical mechanism
            #self.udpSock.settimeout(0);
            try:
                bData, aSrcAddr = self.udpSock.recvfrom(65536);
            except (BlockingIOError, InterruptedError):
                pass
            else:
                if (aSrcAddr in mDstToCli):
                    # from destination to client
                    bData = self._wrapSocks5Udp(bData, aSrcAddr);
                    backlogs.append((bytearray(bData), mDstToCli[aSrcAddr]));
                elif (
                        sValidHost == aSrcAddr[0]
                        and (nValidPort == 0 or nValidPort == aSrcAddr[1])
                ):
                    # from client to destination
                    try:
                        bData, aDstAddr, isDomainName = self._parseSocks5Udp(bData);
                    except Socks5Error as e:
                        # malformed socks5 udp packet; silently drop it
                        pass
                    except Exception as e:
                        log.error('error happened in UDP unwrapping: {}'.format(e));
                    else:
                        if (isDomainName):
                            domainQueue.put_nowait(
                                    (bytearray(bData), aSrcAddr, aDstAddr)
                            );
                        else:
                            mDstToCli[aDstAddr] = aSrcAddr;
                            backlogs.append((bytearray(bData), aDstAddr));
                else:
                    # UDP packet from neither client nor target of client; silently drop it
                    pass
                self.loop.add_writer(self.udpSock, writer);
        def writer():
            #self.udpSock.settimeout(0);
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
                try:
                    addr = await self.loop.getaddrinfo(*aDstAddr, family=socket.AF_INET);
                except socket.gaierror as e:
                    log.debug('error in resolving domain name: {}'.format(e));
                    continue;
                aDstAddr = addr[0][-1];
                mDstToCli[aDstAddr] = aSrcAddr;
                backlogs.append((bytearray(bData), aDstAddr));
                self.loop.add_writer(self.udpSock, writer);
        self.loop.add_reader(self.udpSock, reader);
        self.loop.add_writer(self.udpSock, writer);
        self.aTasks.extend([
                self.loop.create_task(resolveDomainName())
        ]);

    async def tcpRelay(self, source, destination):
        log.debug('starting TCP relay from {} to {}'.format(
                source.aDstAddr, destination.aDstAddr
        ));
        while (self.status != _CS_DEAD):
            bData = await source.readAll(65536, isExact=False);
            #print('relay from {} to {} : {}'.format(source.aDstAddr, destination.aDstAddr, bData[:5]));
            await destination.writeAll(bData);
            if (bData == b''):
                log.debug('TCP relay connection from {} to {} lost'.format(
                        source.aDstAddr, destination.aDstAddr
                ));
                break;
        self.loop.create_task(self.close());

    async def _sendError(self, bCode):
        log.debug('replying failure to {}'.format(self.aCliAddr));
        bReply = struct.pack('>ccccLH', SOCKS5VER, bCode, SOCKS5RSV, IPV4TYPE, 0, 0);
        await self.writeAll(bReply);

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
        await self.writeAll(bReply);

    async def _doConnect(self):
        log.debug('handling Connect command');
        assert (self.bCommand == _SC_CONNECT);
        self.target = TcpStream(loop=self.loop);
        await self.target.connect(self.aTarAddr);

    async def _doBind(self):
        # this bind implementation does not conform to RFC 1928
        # it functions literally like remote-binding

        log.debug('handling Bind command');
        madeFuture = self.loop.create_future();
        def accept(reader, writer):
            stream = TcpStream(reader, writer, loop=self.loop);
            madeFuture.set_result(stream);
        try:
            # as RFC 1928, the aTarAddr should have been used to filter the address of incoming connection
            # but it is used to designate the listening address here
            self.bndSrv = await asyncio.start_server(
                    accept,
                    *self.aTarAddr,
                    loop=self.loop,
                    family=socket.AF_INET,
                    backlog=1
            );
        except (PermissionError, OSError):
            raise GeneralError('can not bind to specified address');
        else:
            madeFuture.add_done_callback(lambda fut: self.bndSrv.close());
            return madeFuture;

    async def _doUdpAssociation(self):
        # there are no UDP suport in asyncio stream
        # so still use the low level asyncio socket operation

        # indeed not asynchronous
        log.debug('handling UDP Association');
        self.udpSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM);
        self.udpSock.settimeout(0);
        self.udpSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1);
        self.udpSock.bind(('', 0));
        sHost, nPort = self.aTarAddr;
        if (sHost == '0.0.0.0' or not checkIp(sHost)):
            sHost = self.aCliAddr[0];
        self.aValidAddr = (sHost, nPort);

    async def _recvRequest(self):
        assert self.status == _CS_NEGO;
        ver = await self.readAll(1);
        if (ver != SOCKS5VER):
            raise Socks5Error('wrong ver field in negotiation');
        cmd = await self.readAll(1);
        if (not cmd in mSocks5Cmd):
            raise Socks5Error('unexpected socks5 command', b'\x07')
        self.bCommand = cmd;
        self.sCommand = mSocks5Cmd[cmd];
        rsv = await self.readAll(1);
        if (rsv != SOCKS5RSV):
            raise Socks5Error('wrong rsv field');
        atyp = await self.readAll(1);
        if (atyp == IPV4TYPE):
            nAddrLength = 4;
            bAddr = await self.readAll(nAddrLength);
            sAddr = socket.inet_ntoa(bAddr);
        elif (atyp == DOMAINTYPE):
            nAddrLength = ord(await self.readAll(1));
            bAddr = await self.readAll(nAddrLength);
            sAddr = bAddr.decode();
            try:
                sAddr = (await self.loop.getaddrinfo(
                        sAddr, None, family=socket.AF_INET
                ))[0][-1][0];
            except socket.gaierror as e:
                raise Socks5Error('can not resolve domain name', b'\x04');
        elif (atyp == IPV6TYPE):
            raise Socks5Error('IPV6 address is not supported', b'\x08');
        else:
            raise Socks5Error('unexpected atyp field in request', b'\x08');
        port = await self.readAll(2);
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
                    self.loop.create_task(self._sendReply(self.target.aBndAddr)),
                    self.loop.create_task(self.tcpRelay(self.stream, self.target)),
                    self.loop.create_task(self.tcpRelay(self.target, self.stream)),
                ]);
            elif (self.bCommand == _SC_BIND):
                madeFuture = await self._doBind();
                await self._sendReply(self.bndSrv.sockets[0].getsockname());
                self.incoming = await madeFuture;
                self.aTasks.extend([
                    self.loop.create_task(self._sendReply(self.incoming.aDstAddr)),
                    self.loop.create_task(self.tcpRelay(self.stream, self.incoming)),
                    self.loop.create_task(self.tcpRelay(self.incoming, self.stream)),
                ]);
            elif (self.bCommand == _SC_UDP):
                await self._doUdpAssociation();
                self.aTasks.extend([
                    self.loop.create_task(self._sendReply(self.udpSock.getsockname())),
                    self.loop.create_task(self.udpForward()),
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
        ver = await self.readAll(1);
        if (ver != VER):
            raise Socks5Error('wrong ver field in password subnegotiation');
        ulen = await self.readAll(1);
        nLen = ord(ulen);
        uname = await self.readAll(nLen);
        plen = await self.readAll(1);
        nLen = ord(plen);
        passwd = await self.readAll(nLen);
        if (uname.decode() == sUsername and passwd.decode() == sPassword):
            bRes = struct.pack('>cc', VER, SUCCESS);
            await self.writeAll(bRes);
            return True;
        else:
            bRes = struct.pack('>cc', VER, FAILURE);
            await self.writeAll(bRes);
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
        ver = await self.readAll(1);
        if (ver != SOCKS5VER):
            raise Socks5Error('wrong ver field in negotiation');
        nmethods = await self.readAll(1);
        nLength = ord(nmethods);
        methods = await self.readAll(nLength);
        aMethods = [bytes([x]) for x in methods];
        for bMethod in self.server.aMethods:
            if (bMethod) in aMethods:
                break;
        else:
            raise Socks5Error('no acceptable method');
        bReply = b''.join((SOCKS5VER, bMethod));
        await self.writeAll(bReply);
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
            await self.close();

    def negoTimeoutCheck(self):
        if (self.status == _CS_INIT):
            self.loop.create_task(self.close());
            log.debug('negotiation timeout, connection closed');

    async def close(self):
        if (self.status == _CS_DEAD):
            return False;
        else:
            log.debug('closing connection from {}'.format(self.aCliAddr));
            self.status = _CS_DEAD;
            if (self.udpSock):
                self.loop.remove_reader(self.udpSock);
                self.loop.remove_writer(self.udpSock);
            if (self.bndSrv):
                self.bndSrv.close();
            if (self.stream):
                self.stream.close();
            if (self.incoming):
                self.incoming.close();
            if (self.target):
                self.target.close();
            if (self.aTasks):
                for task in self.aTasks:
                    if (not task.cancelled()):
                        self.loop.call_soon_threadsafe(task.cancel);
                await asyncio.wait(self.aTasks);
            if (self.udpSock):
                self.udpSock.close();
            log.debug('connection from {} closed'.format(self.aCliAddr));
            return True;

class Socks5Server():

    def __init__(self, aSrvAddr, loop=None, aMethods=None, sUsername=None, sPassword=None):
        if (not loop):
            loop = asyncio.get_event_loop();
        self.loop = loop;
        self.server = None;
        self.aSrvAddr = aSrvAddr;
        # preceding method in aMethods will be preferred
        if (aMethods):
            self.aMethods = aMethods.copy();
        else:
            self.aMethods = [b'\x02', b'\x00'];
        self.sUsername = sUsername or USERNAME;
        self.sPassword = sPassword or PASSWORD;
        if (b'\x02' in self.aMethods):
            if (not self.sUsername or not self.sPassword):
                del self.aMethods[self.aMethods.index(b'\x02')];
        self.aConnections = [];
        self.status = _SS_INIT;

    def handleConn(self, reader, writer):
        socks5Conn = Socks5Connection(self, reader, writer, loop=self.loop);
        self.aConnections.append(socks5Conn);
        self.loop.create_task(socks5Conn.start());

    def start(self):
        self.server = self.loop.run_until_complete(asyncio.start_server(
                self.handleConn, *self.aSrvAddr, loop=self.loop, family=socket.AF_INET
        ));
        log.info('socks5 server lisening on {}'.format(self.aSrvAddr));
        self.status = _SS_START;
        try:
            self.loop.run_forever();
        except KeyboardInterrupt as e:
            pass
        finally:
            self.close();
            self.loop.close();

    def close(self):
        # to be modified
        log.info('closing socks5 server...');
        self.status = _SS_CLOSE;
        self.server.close();
        aClosing = [];
        for conn in self.aConnections:
            aClosing.append(self.loop.create_task(conn.close()));
        if (aClosing):
            self.loop.run_until_complete(asyncio.wait(aClosing));
        aClosing = [];
        self.aConnections = [];
        aCancelling = [];
        for task in asyncio.Task.all_tasks():
            if (not task.cancelled()):
                task.cancel();
                aCancelling.append(task);
        if (aCancelling):
            self.loop.run_until_complete(asyncio.wait(aCancelling));
        aCancelling = [];
        log.info('socks5 server closed');

def main():
    nPort = PORT;
    if (sys.argv[1:2]):
        nPort = int(sys.argv[1]);
    assert nPort;
    sHost = '';
    loop = asyncio.get_event_loop();
    #loop.set_debug(True);
    server = Socks5Server((sHost, nPort), loop);
    server.start();

if __name__ == '__main__':
    main()
