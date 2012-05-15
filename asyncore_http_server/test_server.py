from unittest import TestCase

from granpa_http import HTTPReceiver

from asyncore_http_server.test import RequestSample
from asyncore_http_server.ProxyServer import serverd

class NodeMock(object):
    def process_message(self, message, callback, args):
        self.message, self.callback, self.args = message, callback, args

class TestReceiver(TestCase):

    def setUp(self):
        self.node   = NodeMock()
        self.server = serverd(self.node)
        self.handler = self.server.generate_handler(None, ('0.0.0.0', 1234))

    def test_empty_get(self):
        self.handler.inject(RequestSample.empty_get)
        expected = {'headers': None, 'params': None, 'postdata': None, 'path': '/'}
        self.assertEqual(self.node.message, expected)

    def test_query_get(self):
        self.handler.inject(RequestSample.query_get)
        expected = {'headers': None, 'params': {'a': ['3'], 'b': [' ']}, 'postdata': None, 'path': '/index'}
        self.assertEqual(self.node.message, expected)

    def test_post(self): # TODO params are not correctly parsed
        self.handler.inject(RequestSample.post)
        expected = {'headers': {'Host': 'www.mysite.com', 'Content-Type': 'application/x-www-form-urlencode', 'Content-Length': '27', 'User-Agent': 'Mozilla/4.0'}, 'params': None, 'postdata': '', 'path': '/login.jsp'}
        self.assertEqual(self.node.message, expected)

    def tearDown(self):
        self.server.socket.close()
