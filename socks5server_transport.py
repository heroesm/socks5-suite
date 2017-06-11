#! /usr/bin/env python3
#TODO: add GSSAPI support

import sys
import asyncio
import socket
import logging
import struct
import re
from collections import namedtuple
from functools import partial

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

class UdpProtocol(asyncio.DatagramProtocol):

    def __init__(self, loop=None):
        self.loop = loop or asyncio.get_event_loop();
        self.transport = None;
        self.readBuffer = asyncio.Queue(loop=self.loop);
        self.drainFuture = None;

    def connection_made(self, transport):
        self.transport = transport;
        sock = self.transport.get_extra_info('socket');
        sock.bind(('', 0));
        self.transport.set_write_buffer_limits(low=0);
        self.transport.recvAll = self.recvAll;
        self.transport.sendAll = self.sendAll;
        self.transport.drain = self.drain;
        self.transport.aAddr = sock.getsockname();
    
    def datagram_received(self, data, addr):
        self.readBuffer.put_nowait((data, addr));

    def error_received(self, exc):
        pass

    def connection_lost(self, exc):
        pass

    def resume_writing(self):
        # not actually resume or stop writing, just used in drain check
        if (self.drainFuture and not self.drainFuture.done()):
            self.drainFuture.set_result(None);
            self.drainFuture = None;

    async def drain(self):
        if (self.transport.get_write_buffer_size() == 0):
            return True;
        else:
            if (not self.drainFuture):
                self.drainFuture = self.loop.create_future();
            await self.drainFuture;
            return True;

    async def recvAll(self):
        data, addr = await self.readBuffer.get();
        #print('received from {}: {}'.format(addr, data));
        return (data, addr);

    async def sendAll(self, bData, aAddr):
        self.transport.sendto(bData, aAddr);
        await self.drain();

class TcpProtocol(asyncio.Protocol):

    def __init__(self, loop=None):
        self.loop = loop or asyncio.get_event_loop();
        self.aSrcAddr = None;
        self.sDstAddr = None;
        self.transport = None;
        self.readBuffer = asyncio.Queue(loop=self.loop);
        self.tipBytes = bytearray();
        self.drainFuture = None;

    def connection_made(self, transport):
        self.transport = transport;
        self.transport.set_write_buffer_limits(low=0);
        self.transport.readAll = self.readAll;
        self.transport.writeAll = self.writeAll;
        self.transport.drain = self.drain;
        self.transport.aSrcAddr = transport.get_extra_info('sockname');
        self.transport.aDstAddr = transport.get_extra_info('peername');
    
    def data_received(self, data):
        self.readBuffer.put_nowait(data);

    def eof_received(self):
        pass

    def connection_lost(self, exc):
        pass

    def resume_writing(self):
        # not actually resume or stop writing, just used in drain check
        if (self.drainFuture and not self.drainFuture.done()):
            self.drainFuture.set_result(None);
            self.drainFuture = None;

    async def drain(self):
        if (self.transport.get_write_buffer_size() == 0):
            return True;
        else:
            if (not self.drainFuture):
                self.drainFuture = self.loop.create_future();
            await self.drainFuture;
            return True;

    async def readAll(self, bSize, isExact=True):
        bOut = b'';
        n = bSize - len(bOut);
        while (n > 0):
            if (self.tipBytes):
                bOut += self.tipBytes[:n]
                del self.tipBytes[:n];
                n = bSize - len(bOut);
                if (not isExact and self.readBuffer.empty()):
                    break;
            else:
                self.tipBytes = bytearray(await self.readBuffer.get());
        return bOut;

    async def writeAll(self, bData):
        self.transport.write(bData);
        await self.drain();

class BindProtocol(TcpProtocol):
    def __init__(self, madeFuture, loop=None):
        self.madeFuture = madeFuture;
        self.loop = loop or asyncio.get_event_loop();
        self.aSrcAddr = None;
        self.sDstAddr = None;
        self.transport = None;
        self.readBuffer = asyncio.Queue(loop=self.loop);
        self.tipBytes = bytearray();
        self.drainFuture = None;
    def connection_made(self, transport):
        self.transport = transport;
        self.transport.set_write_buffer_limits(low=0);
        self.transport.readAll = self.readAll;
        self.transport.writeAll = self.writeAll;
        self.transport.drain = self.drain;
        self.transport.aSrcAddr = transport.get_extra_info('sockname');
        self.transport.aDstAddr = transport.get_extra_info('peername');
        self.madeFuture.set_result(transport);
    def connection_lost(self, exc):
        pass

class ClientProtocol(asyncio.Protocol):

    def __init__(self, server, aMethods, loop=None, sUsername=None, sPassword=None):
        self.server = server;
        self.aSrvAddr = server.aSrvAddr;
        self.aMethods = aMethods;
        self.loop = loop or asyncio.get_event_loop();
        self.sUsername = sUsername;
        self.sPassword = sPassword;
        self.transport = None;
        self.tarTrans = None;
        self.udpTrans = None;
        self.incTrans = None;
        self.bndSrv = None;
        self.readBuffer = asyncio.Queue(loop=self.loop);
        self.tipBytes = bytearray();
        self.drainFuture = None;
        self.aCliAddr = None;
        self.aValidAddr = None;
        self.aTarAddr = None;
        self.bCommand = None;
        self.sCommand = None;
        self.aTasks = [];
        self.status = _CS_INIT;
        self.server.aConnections.append(self);

    def connection_made(self, transport):
        self.transport = transport;
        self.transport.set_write_buffer_limits(low=0);
        self.transport.readAll = self.readAll;
        self.transport.writeAll = self.writeAll;
        self.transport.drain = self.drain;
        self.transport.aSrcAddr = transport.get_extra_info('sockname');
        self.transport.aDstAddr = transport.get_extra_info('peername');
        self.aCliAddr = transport.get_extra_info('peername');
        self.loop.create_task(self.start());
    
    def data_received(self, data):
        self.readBuffer.put_nowait(data);

    def eof_received(self):
        pass

    def connection_lost(self, exc):
        self.loop.create_task(self.close());

    def resume_writing(self):
        # not actually resume or stop writing, just used in drain check
        if (self.drainFuture and not self.drainFuture.done()):
            self.drainFuture.set_result(None);
            self.drainFuture = None;

    async def drain(self):
        if (self.transport.get_write_buffer_size() == 0):
            return True;
        else:
            if (not self.drainFuture):
                self.drainFuture = self.loop.create_future();
            await self.drainFuture;
            return True;

    async def readAll(self, bSize, isExact=True):
        bOut = b'';
        n = bSize - len(bOut);
        while (n > 0):
            if (self.tipBytes):
                bOut += self.tipBytes[:n]
                del self.tipBytes[:n];
                n = bSize - len(bOut);
                if (not isExact and self.readBuffer.empty()):
                    break;
            else:
                self.tipBytes = bytearray(await self.readBuffer.get());
        return bOut;

    async def writeAll(self, bData):
        self.transport.write(bData);
        await self.drain();

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
        assert self.udpTrans and self.aValidAddr;
        log.debug('starting UDP forward on {}'.format(self.udpTrans.aAddr));
        mDstToCli = {}; # {aDstAddr1: aSrcAddr, aDstAddr2: aSrcAddr, ...}
        sValidHost = self.aValidAddr[0];
        nValidPort = self.aValidAddr[1];
        while self.status != _CS_DEAD:
            bData, aSrcAddr = await self.udpTrans.recvAll();
            #print('udp got {}: {}'.format(aSrcAddr, bData));
            if (aSrcAddr in mDstToCli):
                # from destination to client
                bData = self._wrapSocks5Udp(bData, aSrcAddr);
                await self.udpTrans.sendAll(bData, mDstToCli[aSrcAddr]);
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
                        try:
                            addr = await self.loop.getaddrinfo(
                                    *aDstAddr, family=socket.AF_INET
                            );
                            aDstAddr = addr[0][-1];
                        except socket.gaierror as e:
                            log.debug('error in resolving domain name: {}'.format(e));
                            continue;
                    mDstToCli[aDstAddr] = aSrcAddr;
                    await self.udpTrans.sendAll(bData, aDstAddr);
            else:
                # UDP packet from neither client nor target of client; silently drop it
                pass

    async def tcpRelay(self, srcTrans, dstTrans):
        log.debug('starting TCP relay from {} to {}'.format(
            srcTrans.aDstAddr, dstTrans.aDstAddr
        ));
        while (self.status != _CS_DEAD):
            bData = await srcTrans.readAll(65536, isExact=False);
            #print('relay from {} to {} : {}'.format(srcTrans.aDstAddr, dstTrans.aDstAddr));
            await dstTrans.writeAll(bData);
            if (bData == b''):
                log.debug('TCP relay connection from {} to {} lost'.format(
                        srcTrans.aDstAddr,
                        dstTrans.aDstAddr
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
        self.tarTrans, _ = await self.loop.create_connection(
                partial(TcpProtocol, self.loop),
                *self.aTarAddr,
                family=socket.AF_INET
        );

    async def _doBind(self):
        # this bind implementation does not conform to RFC 1928
        # it functions literally like remote-binding

        log.debug('handling Bind command');
        madeFuture = self.loop.create_future();
        try:
            # as RFC 1928, the aTarAddr should have been used to filter the address of incoming connection
            # but it is used to designate the listening address here
            self.bndSrv = await self.loop.create_server(
                    partial(BindProtocol, madeFuture, self.loop),
                    *self.aTarAddr,
                    family=socket.AF_INET,
                    backlog=1
            );
        except (PermissionError, OSError):
            raise GeneralError('can not bind to specified address');
        else:
            madeFuture.add_done_callback(lambda fut: self.bndSrv.close());
            return madeFuture;

    async def _doUdpAssociation(self):
        log.debug('handling UDP Association');
        self.udpTrans, _ = await self.loop.create_datagram_endpoint(
                partial(UdpProtocol, self.loop), family=socket.AF_INET
        );
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
                    self.loop.create_task(self._sendReply(self.tarTrans.aSrcAddr)),
                    self.loop.create_task(self.tcpRelay(self.transport, self.tarTrans)),
                    self.loop.create_task(self.tcpRelay(self.tarTrans, self.transport)),
                ]);
            elif (self.bCommand == _SC_BIND):
                madeFuture = await self._doBind();
                await self._sendReply(self.bndSrv.sockets[0].getsockname());
                self.incTrans = await madeFuture;
                self.aTasks.extend([
                    self.loop.create_task(self._sendReply(self.incTrans.aDstAddr)),
                    self.loop.create_task(self.tcpRelay(self.transport, self.incTrans)),
                    self.loop.create_task(self.tcpRelay(self.incTrans, self.transport)),
                ]);
            elif (self.bCommand == _SC_UDP):
                await self._doUdpAssociation();
                self.aTasks.extend([
                    self.loop.create_task(self._sendReply(self.udpTrans.aAddr)),
                    self.loop.create_task(self.udpForward()),
                ]);
            self.status = _CS_REP;
        return True;

    async def _pwdSubNego(self):
        log.debug('starting username/password sub-negotiation');
        VER = b'\x01';
        SUCCESS = b'\x00';
        FAILURE = b'\x01';
        sUsername = self.sUsername;
        sPassword = self.sPassword;
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
        assert bMethod in self.aMethods;
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
        for bMethod in self.aMethods:
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
        except (Socks5Error, DeadConnectionError, GeneralError) as e:
            log.error(e);
            await self.close();

    def negoTimeoutCheck(self):
        if (self.status == _CS_INIT):
            self.loop.create_task(self.close());
            log.debug('negotiation timeout, close connection');

    async def close(self):
        if (self.status == _CS_DEAD):
            return False;
        else:
            log.debug('closing connection from {}'.format(self.aCliAddr));
            self.status = _CS_DEAD;
            if (self.bndSrv):
                self.bndSrv.close();
            if (self.transport):
                self.transport.close();
            if (self.tarTrans):
                self.tarTrans.close();
            if (self.udpTrans):
                self.udpTrans.close();
            if (self.incTrans):
                self.incTrans.close();
            for task in self.aTasks:
                if (not task.cancelled()):
                    self.loop.call_soon_threadsafe(task.cancel);
            if (self.aTasks):
                await asyncio.wait(self.aTasks);
            self.aTasks = [];
            log.debug('connection from {} closed'.format(self.aCliAddr));
            return True;

class Socks5Server():
    def __init__(self, aSrvAddr, loop=None, aMethods=None, sUsername=None, sPassword=None):
        self.loop = loop or asyncio.get_event_loop();
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

    def start(self):
        sHost, nPort = self.aSrvAddr;
        factory = partial(ClientProtocol, self, self.aMethods, self.loop, self.sUsername, self.sPassword);
        makeServer = self.loop.create_server(factory, sHost, nPort, family=socket.AF_INET);
        self.server = self.loop.run_until_complete(makeServer);
        self.status = _SS_START;
        try:
            self.loop.run_forever();
        except KeyboardInterrupt as e:
            pass;
        finally:
            self.loop.run_until_complete(self.close());
            self.loop.close();

    async def close(self):
        log.info('closing socks5 server...');
        self.server.close();
        await self.server.wait_closed();
        for conn in self.aConnections:
            await conn.close();
        self.aConnections = [];
        aCancelling = [];
        for task in asyncio.Task.all_tasks():
            if (not task.cancelled() and task is not asyncio.Task.current_task(self.loop)):
                self.loop.call_soon_threadsafe(task.cancel);
                aCancelling.append(task);
        if (aCancelling):
            await asyncio.wait(aCancelling);
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
