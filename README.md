# socks5-suite

Socks5-related scripts in Python3

* TODO: add GSSAPI support
* TODO: complete socks5 server
* TODO: write 2-hops socks5 server whose communication through pubic network shall be encryted

## socks5client.py

Socks5 client script which makes Python itself able to do socket- and http-related operations through socks5 proxy 

see test() for usage demonstration:

```python
def test():
    # suppose that socks5 server is listening on localhost, probably port 1080
    import sys
    if (sys.argv[1:2]):
        nPort = int(sys.argv[1]);
    else:
        nPort = 1080;

    print('proxied socket operation:');
    tcpSock = Socks();
    tcpSock.setProxy(('localhost', nPort));
    tcpSock.connect(('myip.ipip.net', 80));
    tcpSock.sendall((b'GET / HTTP/1.1\r\nHost: myip.ipip.net\r\n\r\n'));
    print(tcpSock.recv(4096).decode());

    print('proxy using http handler whose __init__ explictly specifies proxy server:');
    opener = urllib.request.build_opener(Socks5HttpHandler(aAddr=('localhost', nPort)));
    res = opener.open('http://myip.ipip.net/')
    print(res.read().decode())
    res.close();

    print('set in class level the default proxy server address');
    setDefaultProxy(('localhost', nPort));

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

    print('access google using proxied opener');
    opener = urllib.request.build_opener(Socks5Handler);
    res = opener.open('https://www.google.com/')
    print(res.read())
    res.close()

    print('end');
```
