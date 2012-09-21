import cgi
import socket
import logging
import asyncore
from asyncore import compact_traceback

#from granpa.node.legacy.LogMessage import LogMessage, REMOTE2LOCAL
class LogMessage:
    
    def __init__(self, format, *args, **kwargs):
        self.format = format
        self.args = args
        self.kwargs = kwargs        
        
    def __str__(self):
        args = []
        for i in self.args:
            if isinstance(i,tuple):
                args.append(i[0](*i[1:]))
            else:
                args.append(i)
        return self.format % tuple(args)
REMOTE2LOCAL='<=='

from asyncore_http_server import RequestHandler

class Codes:
    
    # successful
    OK_200 = 200
    Created_201                     = 201
    Accepted_202                    = 202
    NonAuthoritativeInformation_203 = 203
    NoContent_204                   = 204
    ResetContent_205                = 205
    PartialContent_206              = 206
    Continue_100                    = 100
    SwitchingProtocols_101          = 101
    
    # redirection
    MultipleChoices_300   = 300
    MovedPermanently_301  = 301
    Found_302             = 302
    SeeOther_303          = 303
    NotModified_304       = 304
    UseProxy_305          = 305
    Unused_306            = 306
    TemporaryRedirect_307 = 307
    
    # client error
    BadRequest_400                   = 400
    Unauthorized_401                 = 401
    PaymentRequired_402              = 402
    Forbidden_403                    = 403
    NotFound_404                     = 404
    MethodNotAllowed_405             = 405
    NotAcceptable_406                = 406
    ProxyAuthenticationRequired_407  = 407
    RequestTimeout_408               = 408
    Conflict_409                     = 409
    Gone_410                         = 410
    LengthRequired_411               = 411
    PreconditionFailed_412           = 412
    RequestEntityTooLarge_413        = 413
    RequestURITooLong_414            = 414
    UnsupportedMediaType_415         = 415
    RequestedRangeNotSatisfiable_416 = 416
    ExpectationFailed_417            = 417
    
    # server error
    InternalServerError_500     = 500
    NotImplemented_501          = 501
    BadGateway_502              = 502
    ServiceUnavailable_503      = 503
    GatewayTimeout_504          = 504
    HTTPVersionNotSupported_505 = 505

class HTTPServer(RequestHandler):
                
    def __init__(self, conn, addr, server, callback, logger=None):
        # Initialize the ProxyNode (Receiver)
        RequestHandler.__init__(self, conn, addr, server)
        self.mainlog = logger or logging
        self.callback = callback
        
    def get_local_address(self):
        try:
            return self.socket.getsockname()
        except Exception as e:
            self.mainlog.error(str(e))
            return '', ''
        
    def get_remote_address(self):
        try:
            return self.socket.getpeername()
        except Exception as e:
            self.mainlog.error(str(e))
            return '', ''
            
    def log_message(self, format, *args):
        self.mainlog.debug("%s - - [%s] %s \"%s\" \"%s\"\n" % \
                      (self.address_string(),
                       self.log_date_time_string(),
                       format%args,
                       self.headers.get('referer', ''),
                       self.headers.get('user-agent', '')))
        
        try:
            msg = str(self.body)
            self.log_msg(msg, REMOTE2LOCAL)
        except Exception as e:
            self.mainlog.error(str(e))
        
    def log_msg(self, msg, direction):      
        self.mainlog.info(LogMessage("[%s] %s [%s] %s", (self.get_local_address,), direction, (self.get_remote_address,), msg))  
        self.mainlog.debug("Message: "+msg)  
        
    def handle_data(self):
        if self.use_favicon and self.path == '/favicon.ico':
            self.send_response(200)
            self.send_header("Content-type", 'text/html')
            self.send_header("Content-Length", len(favicon))
            self.end_headers()
            self.log_request(self.code, len(favicon))
            self.outgoing.append(favicon)
            self.outgoing.append(None)
            return
        try:       
            # Parse message and check errors
            request = self.parse_data()
            # Send message to the current sender and check errors
            self.callback(request, self.process_reply)
        except Exception as e:
            self.mainlog.exception()
            self.handle_error()

    ################################################
    ###    Processing Reply Callbacks            ###
    ################################################
    
    def process_reply(self, args=None):
        """ Process reply response from sender, starting from lower level """
        args = args or []
        (status_code, content_type, message_body) = self.parse_args(args)
        self.push_final(status_code, content_type, message_body)       

    def handle_error(self, code=None):
        if not code:
            code = Codes.InternalServerError_500
        if not isinstance(v, socket.error):
            self.push_final(code, 'text/plain', 'server error')
        
    def push_final(self, status_code=200, ctype="text/html", entity_body=""):
        self.mainlog.info("Status-Code: %s, Content-Type %s, Entity-Body: %s" % \
            (status_code, ctype, entity_body)) 
        
        self.send_response(status_code)
        self.send_header("Content-type", ctype)
        self.send_header("Content-Length", len(entity_body))
        self.end_headers()
        self.log_request(entity_body, len(entity_body))
        self.update_b(len(entity_body))
        self.outgoing.append(entity_body)
        self.outgoing.append(None)                    

    ################################################
    ###    Utilities                             ###
    ################################################
    
    def parse_args(self, args):
        '''status_code, content_type, message_body'''
        return args[:3]
        
    def parse_data(self):
        """ Given a GET or a POST extract contents from it and returns a dict 
        containing all the data
        """
        
        request = {
            'headers' : None,
            'postdata' : None,
            'params' : None,
            'path' : self.path,
            }
        if self.command == 'GET':
            try:
                request['params'] = self.body
            except Exception as e:
                self.mainlog.error(str(e))
        elif self.command == "POST":
            try:
                qspos = self.path.find('?')
                if qspos>=0:
                    request['params'] = cgi.parse_qs(self.path[qspos+1:], keep_blank_values=1)
                    request['path'] = self.path[:qspos]
                request['headers'] = self.headers
                request['postdata'] = self.body
            except Exception as e:
                self.mainlog.error(str(e))
        msg =  "%s - %s - %s " % (request['headers'],
                                  request['postdata'],
                                  request['params'])
        self.log_msg(msg, "==>")
        return request

    def do_POST(self):
        ctype, pdict = cgi.parse_header(self.headers.getheader('content-type'))
        length = int(self.headers.getheader('content-length'))
        if ctype == 'multipart/form-data':
            self.body = cgi.parse_multipart(self.rfile, pdict)
        elif ctype == 'application/x-www-form-urlencoded':
            qs = self.rfile.read(length)
            self.body = cgi.parse_qs(qs, keep_blank_values=1)
        elif ctype in ('text/xml', 'application/octet-stream', 'application/xml'):
            self.body = self.rfile.getvalue()
        else:
            self.body = ''
            self.mainlog.error('Unknown Content-Type: {0}'.format(ctype))
        self.handle_data()
        
class serverd( asyncore.dispatcher ):
        
    def __init__ (self, callback, port=8080, logger=None):
        asyncore.dispatcher.__init__ ( self )          
        
        logger = logger or logging
        self.logger = logger

        self.inHost = '0.0.0.0'
        self.inPort = port
        
        self.here = ( self.inHost, self.inPort )    
        self.create_socket ( socket.AF_INET, socket.SOCK_STREAM )
        self.set_reuse_addr()
        self.bind ( self.here )
        self.listen ( 5 )
        
        self.callback = callback
    
    def handle_accept(self): 
        conn, addr = self.accept()
        self.logger.debug( '[%s] Incoming connection from %s' % ( self.inPort, repr( addr ) ) )
        return self.generate_handler(conn, addr)

    def generate_handler(self, conn, addr):
        return HTTPServer(
            conn,
            addr,
            self,
            self.callback,
            logger=self.logger,
            )
    
if __name__=='__main__':
    server = serverd()
    while True: asyncore.loop()
