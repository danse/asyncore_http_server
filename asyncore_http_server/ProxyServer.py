import asyncore
import socket
import logging

#from granpa.node.legacy.TTLMap import TTLMap
#from granpa.node.test import ReceiverTester

from Server import HTTPServer
        
class serverd( asyncore.dispatcher ):
        
    def __init__ (self, next_node=None, port=8080, logger=None):
        asyncore.dispatcher.__init__ ( self )          
        
        logger = logger or logging
        self.logger = logger

        #self.cache = TTLMap(ttl=100)
        self.inHost = '0.0.0.0'
        self.inPort = port
        
        self.here = ( self.inHost, self.inPort )    
        self.create_socket ( socket.AF_INET, socket.SOCK_STREAM )
        self.set_reuse_addr()
        self.bind ( self.here )
        self.listen ( 5 )
        
        self.next_node = next_node#or ReceiverTester()
    
    def handle_accept(self): 
        conn, addr = self.accept()
        self.logger.debug( '[%s] Incoming connection from %s' % ( self.inPort, repr( addr ) ) )
        return self.generate_handler(conn, addr)

    def generate_handler(self, conn, addr):
        return HTTPServer(
            self.next_node,
            conn,
            addr,
            self,
            self.here,
            self.logger,
            )
    
    def do_sweep( self ):
        """ Searching for expired messages """
        pass
#       for k, i in self.cache.expired():
#           self.logger.info( "Expired seq. num.: 0x%08X" % k )
#           self.logger.debug( "Cache : %s" % str( self.cache.data ) )
#           self.logger.debug( "Cache : %s" % str( self.cache.data ) )

if __name__=='__main__':
    server = serverd()
    while True: asyncore.loop()
