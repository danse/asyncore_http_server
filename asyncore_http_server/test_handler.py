from unittest import TestCase
import logging

from asyncore_http_server.Server import HTTPServer
from asyncore_http_server.test import RequestSample

logging.basicConfig()

class Receiver(object):
    def callback(self, request, callback):
        self.request, self.callback = request, callback

class TestHandler(TestCase):

    def setUp(self):
        self.receiver = Receiver()
        self.handler = HTTPServer(None, ('0.0.0.0', 1234), None, self.receiver.callback)

    def test_empty_get(self):
        self.handler.inject(RequestSample.empty_get)
        self.assertEqual(self.receiver.request, {'headers': None, 'params': None, 'postdata': None, 'path': '/'})

    def test_query_get(self):
        self.handler.inject(RequestSample.query_get)
        self.assertEqual(self.receiver.request, {'headers': None, 'params': {'a': ['3'], 'b': [' ']}, 'postdata': None, 'path': '/index'})

    def test_post(self):
        self.handler.inject(RequestSample.post)
        self.assertEqual(self.receiver.request, {'headers': {'Host': 'www.mysite.com', 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': '27', 'User-Agent': 'Mozilla/4.0'}, 'params': None, 'postdata': {'password': ['guessme'], 'userid': ['joe']}, 'path': '/login.jsp'})

if __name__=='__main__':
    test = TestHandler('test_post')
    import pdb; pdb.set_trace()
    test.debug()
