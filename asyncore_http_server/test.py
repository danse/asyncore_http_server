class RequestSample(object):
    '''
    Request samples useful to test classes derived from RequestHandler
    '''
    empty_get  = '''GET / HTTP/1.1\r\nHost: localhost:8888\r\nUser-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:11.0) Gecko/20100101 Firefox/11.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-us,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\n\r\n'''
    query_get  = '''GET /index?a=3&b=%20 HTTP/1.1\r\nHost: localhost:8888\r\nUser-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:11.0) Gecko/20100101 Firefox/11.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-us,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\n\r\n'''
    post       = '''POST /login.jsp HTTP/1.1\r\nHost: www.mysite.com\r\nUser-Agent: Mozilla/4.0\r\nContent-Length: 27\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuserid=joe&password=guessme'''
    post_octet = '''POST /login.jsp HTTP/1.1\r\nHost: www.mysite.com\r\nUser-Agent: Mozilla/4.0\r\nContent-Length: 27\r\nContent-Type: application/octet-stream\r\n\r\nArbitrary Content'''
