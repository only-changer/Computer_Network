from socket import *
import sys
import base64
#!/usr/bin/python2.7 
# -*- coding: utf-8 -*- 
# Create a server socket, bind it to a port and start listening
tcpSerSock = socket(AF_INET, SOCK_STREAM)
# Fill in start.
tcpSerSock.bind(("0.0.0.0",6789))
tcpSerSock.listen(5)
# Fill in end.
a = 0
tcpCliSock = socket()
while True:
	# Strat receiving data from the client
	print 'Ready to serve...'
	tcpCliSock, addr = tcpSerSock.accept()
	print 'Received a connection from:', addr
	message = tcpCliSock.recv(2147483)# Fill in start. # Fill in end.
	#print message
	if (not message):
		continue
	# Extract the filename from the given message
	print message.split()[1]
	filename = message.split()[1].partition("/")[2]
	print filename
	fileExist = "false"
	filetouse = "/" + filename
	print filetouse
	try:
		# Check wether the file exist in the cache
		f = open(filename.replace('/' , ''), "r")
		outputdata = f.read()
		fileExist = "true"
		# ProxyServer finds a cache hit and generates a response message
		#tcpCliSock.send("HTTP/1.1 200 OK\r\n")
		# Fill in start.
		tcpCliSock.send(outputdata)
		# Fill in end.
		print 'Read from cache'
	# Error handling for file not found in cache
	except IOError:
		if fileExist == "false":
			# Create a socket on the proxyserver
			# Fill in start. # Fill in end.
			hostn = filename
			#hostn = filename.replace("www.","",1)
			hostn = hostn.split('/')[0]
			
			print hostn
			check = 1
			try:
				while True:
					# Connect to the socket to port 80
					# Fill in start.
					filename = message.split('\n')[0]
					filename = filename.split(' ')[1]
					filename = filename.replace('/' , '')
					message = message.replace(hostn,"",1)
					message = message.replace("Host: 127.0.0.1:6789","Host: " + hostn,1)
					print(message)
					print(hostn)
					c = socket(AF_INET, SOCK_STREAM)
					c.connect((hostn,80))
					if (message != ""):	
						c.send(message)
						# Fill in end.
						# Create a temporary file on this socket and ask port 80 for the file requested by the client
						fileobj = c.makefile('r', 0)
						fileobj.write("GET "+"http://" + filename + "HTTP/1.1\n\n")
						# Read the response into buffer
						# Fill in start.

						message = c.recv(214748)
						start = message.find("Content-Length: ")
						i = start + 16
						strlen = ""
						while (message[i] >= '0' and message[i] <= '9'):
							strlen = strlen + message[i]
							i = i + 1
						if (strlen != ""):
							length = int(strlen)
							while (len(message) < length):
								message = message + c.recv(214748)

						#message = message.replace("Server: GitHub.com","Server: 127.0.0.1:6789",1)
					
						# Fill in end.
						# Create a new file in the cache for the requested file.
						# Also send the response in the buffer to client socket and the corresponding file in the cache
						tmpFile = open("./" + filename,"wb")
						# Fill in start.
						tmpFile.write(message)
						tcpCliSock.send(message)
						message = ""
						tcpCliSock.settimeout(1)
					else:
						break
					c.close()
					try:
						message	= tcpCliSock.recv(214748)
					except:
						tcpCliSock.close()
						try:
							tcpCliSock, addr = tcpSerSock.accept()
							message	= tcpCliSock.recv(214748)
						except:
							check = 0
							break
					# Fill in end.
			except:
				if (check == 0):
					message = "HTTP/1.1 404 Not Found\n\n"
					tcpCliSock.send(message)
				
		else:
			print "Illegal request"		
	# Close the client and the server sockets
	tcpCliSock.close()
# Fill in start.
tcpSerSock.close()
# Fill in end