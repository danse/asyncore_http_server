from unittest import TestCase

from asyncore_http_server import RequestHandler
from asyncore_http_server.test import RequestSample

class TestHandler(TestCase):

    def setUp(self):
        self.handler = RequestHandler(None, ('0.0.0.0', 1234), None)

    def test_empty_get(self):
        self.handler.inject(RequestSample.empty_get)

    def test_query_get(self):
        self.handler.inject(RequestSample.query_get)

    def test_post(self):
        self.handler.inject(RequestSample.post)

if __name__=='__main__':
    test = TestHandler('test_empty_get')
    test.debug()
