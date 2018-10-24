#!/usr/bin/python
#coding=utf-8

import optparse
import socket
import time
from socket import *
from threading import *

flag = 1
pMessage = []
screenLock = Semaphore(value=1)

def connScan(tgtHost,tgtPort):
	global flag,port
	global pMessage
	
	flag = 1
	try:
		connSkt = socket(AF_INET,SOCK_STREAM)
		connSkt.connect((tgtHost,tgtPort))
		connSkt.send('WFUCK\r\n')
		result = connSkt.recv(100)
		
		screenLock.acquire()
 
		print '[*] %d/tcp open'%tgtPort
		print '[*] Banner: ' + str(result) + '\r\n'
		pMessage.append(tgtPort)
	except:
		screenLock.acquire()
	finally:
		flag = tgtPort
		screenLock.release()
		connSkt.close()
 
def portScan(tgtHost):
	global pMessage

	try:
		tgtIP = gethostbyname(tgtHost)
	except:
		print "[-] Cannot resolve '%s' : Unknown host"%tgtHost
		return
 
	try:
		tgtName = gethostbyaddr(tgtIP)
		print '\n[+] Scan Results for: ' + tgtName[0]
	except:
		print '\n[+] Scan Results for: ' + tgtIP
 
	setdefaulttimeout(1)
	aflag = 1
	
	a =  '''
	+------------------------------+
	|     Combie Security Team     |
	+------------------------------+
	'''
	print a
	
	while aflag == 1:
		message = ''
		pMessage = []
		print '\r\n[+] New scan start!!\r\n'
		for tgtPort in range(65536):
			t = Thread(target=connScan,args=(tgtHost,tgtPort))
			t.start()
		inflag = 0
		while flag != 65535:
			inflag = inflag + 1
			print '[+] Waiting... Port:%d'%flag
			if inflag == 10:
				break
			time.sleep(3)
		if len(pMessage) != 0:
			message = message + '\r\n' + str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) 
			message = message + '\r\n+------------------------------+\r\n'
			message = message + '|     Combie Security Team     |\r\n'
			message = message + '+------------------------------+\r\n'
			for pstr in pMessage:
				message = message + '| OPEN: ' + str(pstr) + ' '*(32-len('| OPEN: '+str(pstr))-1) + '|\r\n'
			message = message + '+------------------------------+\r\n'
			print message
			
			with open(tgtHost + '.ini','a') as f:
				f.write(message)
		else:
			print '[+] No port is opening'
		
		print '[+] Wait for next scan with 60s'
		time.sleep(60)
 
def main():
	parser = optparse.OptionParser("[*] Usage : ./portmonitor.py -H <target host>")
	parser.add_option('-H',dest='tgtHost',type='string',help='specify target host')
	(options,args) = parser.parse_args()
	tgtHost = options.tgtHost
	if tgtHost == None:
		print parser.usage
		exit(0)
	portScan(tgtHost)
 
if __name__ == '__main__':
	main()
