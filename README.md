# socks5-suite

Socks5-related scripts in Python3

* TODO: add GSSAPI support
* TODO: write 2-hops socks5 server whose communication through pubic network shall be encryted

**in those scripts, the implemented SOCKS5 BIND command is different from what described in RFC1928**

## socks5server.py
Socks5 server script which makes use of low level asyncio functions, supporting username/password authentication and all socks5 command including CONNECT, BIND and UDP ASSOCIATION. Not compatible with IPv6.

It defaults to listening on port 1081 in all interfaces.

## socks5server_tranpsport.py
Rewritten script of socks5server.py using relatively high level asyncio transport and protocol functions.

## socks5server_stream.py
Rewritten script of socks5server.py using high level asyncio stream functions.

## socks5client.py

Socks5 client script which makes Python itself able to do socket- and http-related operations through socks5 proxy 

see test() for usage demonstration:

```python
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
```
