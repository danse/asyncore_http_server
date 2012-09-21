""" The <httpProxyServer> process data from an http client connection starting 
from lower level.

For each message received, in the 'process_data' the <httpProxyServer> builds a 
dict with data inside and route it to the Receiver specified in conf: see
Scheduler specified in the server section. 

Details:
'process_data' calls 'parse_message' that retrieves GET or POST contents and 
returns a dict with the data inside.

'process_data' calls 'send_msg_to_sender' that retrieves connection for routing
and sends the dict using 'connection.process_message'. Connection is the class
Receiver of the dict. 
"""
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

class HTTPCodes:
    
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

# Logical errors during process

ROUTER_ERROR = "Router Error" 
PARSER_ERROR = 'Parser Error' 
POLICY_ERROR = 'Policy Error' 
MEMORY_ERROR = 'Memory Error' 
MEMORY_DUPLICATE_ERROR = 'Duplicate entry' 
SCHEDULER_ERROR = 'Scheduler Error' 
SENDER_ERROR = 'Sender Error'
CONTEXT_ERROR = 'Context Error'
UNKNOWN_ERROR = 'Unknown Error'
CACHING_ERROR = 'Caching Error'
EXPIRED_ERROR = 'Expired Error'

class NodeErrors(object):
    """
    A set of internal granpa codes, useful have an entry
    node different from SMTP
    """
    # A generic error which can be retried
    RETRY             = 'Retry Error'
    ROUTER            = ROUTER_ERROR 
    PARSER            = PARSER_ERROR 
    POLICY            = POLICY_ERROR 
    MEMORY            = MEMORY_ERROR 
    MEMORY_DUPLICATE  = MEMORY_DUPLICATE_ERROR 
    SCHEDULER         = SCHEDULER_ERROR
    SENDER            = SENDER_ERROR
    CONTEXT           = CONTEXT_ERROR
    CACHING           = CACHING_ERROR
    # A generic error which can not be retried
    UNKNOWN           = UNKNOWN_ERROR


class NodeError(Exception):
    """ Exception class to manage processing error """

    def __init__(self, args):
        self.status = args[0] # Status code
        self.error = args[1] # Text error string
        self.flist = args[2] # List of (functor_name, (functor_args))
        # ((f1,(f1_p1, f1_p2, ..)),(f2,(f2_p1, f2_p2, ..)))

# Reply codes related to the logical errors during process
PROCESS_ERRORS = {
    NodeErrors.ROUTER : HTTPCodes.InternalServerError_500,
    NodeErrors.PARSER : HTTPCodes.InternalServerError_500,
    NodeErrors.POLICY : HTTPCodes.InternalServerError_500,
    NodeErrors.MEMORY : HTTPCodes.InternalServerError_500,
    NodeErrors.MEMORY_DUPLICATE : HTTPCodes.InternalServerError_500,
    NodeErrors.SCHEDULER : HTTPCodes.InternalServerError_500,
    NodeErrors.SENDER : HTTPCodes.InternalServerError_500,
    NodeErrors.CACHING : HTTPCodes.InternalServerError_500,
    NodeErrors.CONTEXT : HTTPCodes.InternalServerError_500,
    NodeErrors.UNKNOWN : HTTPCodes.InternalServerError_500 }
    
class HTTPServer(RequestHandler):
                
    def __init__(self, conn, addr, server, callback, logger=None):
        # Initialize the ProxyNode (Receiver)
        RequestHandler.__init__(self, conn, addr, server)
        
        self.raise_flist = ((self.reset_internal_data, ()), )
        self.reset_internal_data()            

        self.mainlog = logger or logging

        self.callback = callback
        
    def raise_args(self, error):
        pe = PROCESS_ERRORS[NodeErrors.UNKNOWN]
        if PROCESS_ERRORS.has_key(error):
            pe = PROCESS_ERRORS[error]
        return pe, error, self.raise_flist
        
    def reset_internal_data(self):  
        self._channel_msgid = 0
        self._sender_args = {}
        self._sender_msg = None
        
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
            self.process_data()
        except Exception as e:
            self.mainlog.error(str(e))
            return self.handle_error()

    def handle_error(self):
        nil, t, v, tbinfo = compact_traceback()
        http_status_code = HTTPCodes.OK_200
        error = tbinfo
        flist = []
        
        if isinstance(v, NodeError):
            http_status_code = v.status
            error = v.error
            flist = v.flist
        
        self.mainlog.error('[%s] %s %s' % (str('here'), error, str(v)))
        
        if not isinstance(v, socket.error):
            self.push_final(http_status_code, 'text/plain', 'server error')
        
        for functor, args in flist:
            # sometimes a user functor method will crash.
            try:
                functor(*args)
            except Exception as e:
                self.mainlog.error(str(e))
                
    ################################################
    ###    Processing Data Callbacks             ###
    ################################################
    
    def process_data(self, msg=""): 
        """ Process data from client connection, starting from lower level """  
        
        try:
            
            # Parse message and check errors
            self._sender_msg, error = self.parse_message()
            if error:
                raise NodeError(self.raise_args(error))
    
            # Get message id and update the private data
            if self._sender_msg.has_key('Message-ID'):
                self._channel_msgid = self._sender_msg['Message-ID']       
            
            # Prepare args for sendere connection
            self._sender_args = {'fileno' : self._fileno,}

            # Send message to the current sender and check errors
            error = self.callback(self._sender_msg, self.process_reply)
            if error:
                raise NodeError(self.raise_args(error))
            
        except Exception as e:
            self.mainlog.error(str(e))
            return self.handle_error()
            
    ################################################
    ###    Processing Reply Callbacks            ###
    ################################################
    
    def process_reply(self, args=None):
        """ Process reply response from sender, starting from lower level """
        args = args or []
        (status_code, content_type, message_body) = self.parse_args(args)
        self.push_final(status_code, content_type, message_body)       

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
        self.reset_internal_data()

    ################################################
    ###    Utilities                             ###
    ################################################
    
    def parse_args(self, args):
        '''status_code, content_type, message_body'''
        return args[:3]
        
    def parse_message(self, msg="", route=""):
        """ Given a GET or a POST extract contents from it and returns a dict 
        containing all the data
        """
        
        dataDict = {}
        
        try :   
            dataDict['headers'] = None
            dataDict['postdata'] = None
            dataDict['params'] = None
            dataDict['path'] = self.path
            if self.command == 'GET':
                try:
                    dataDict['params'] = self.body
                except Exception as e:
                    self.mainlog.error(str(e))
            elif self.command == "POST":
                try:
                    qspos = self.path.find('?')
                    if qspos>=0:
                        dataDict['params'] = cgi.parse_qs(self.path[qspos+1:], keep_blank_values=1)
                        dataDict['path'] = self.path[:qspos]
                    dataDict['headers'] = self.headers
                    dataDict['postdata'] = self.body
                except Exception as e:
                    self.mainlog.error(str(e))
            msg =  "%s - %s - %s " % (dataDict['headers'],
                                      dataDict['postdata'],
                                      dataDict['params'])
            self.log_msg(msg, "==>")
        except Exception as e:
            self.mainlog.error(str(e))
            return None, NodeErrors.PARSER
        
        return dataDict, None

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
