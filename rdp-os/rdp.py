#!/usr/bin/env python27

import socket
import sys

print '''
  ____  ____  ____                       _       _ _   
 |  _ \|  _ \|  _ \       _____  ___ __ | | ___ (_) |_ 
 | |_) | | | | |_) |____ / _ \ \/ / '_ \| |/ _ \| | __|
 |  _ <| |_| |  __/_____|  __/>  <| |_) | | (_) | | |_ 
 |_| \_\____/|_|         \___/_/\_\ .__/|_|\___/|_|\__|
                                  |_|                 
                                           By Greekn
'''

def run():
    address = (str(sys.argv[1]), int(3389))
    rdp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    rdp.settimeout(10)
    rdp.connect(address)
    rdp.send('\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x0b\x00\x00\x00')
    data = rdp.recv(19)
    print '[!] Data transmission success!'
    try:            
        if data == '\x03\x00\x00\x0b\x06\xd0\x00\x00\x124\x00':
            print '[+] Windows xp os'
        
        elif data == '\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x03\x00\x08\x00\x02\x00\x00\x00':
            print '[+] Windows 2003 os'
        
        elif data == '\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x02\x01\x08\x00\x02\x00\x00\x00':
            print '[+] Windows 2008r2 os'
        
        elif data == '\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x02\t\x08\x00\x02\x00\x00\x00':
            print '[+] Windows7 os'
      
    except:
        print 'Address cannot be accessed!'
       
if __name__ == '__main__':
	run()