#import socket module
from socket import *
import time
serverSocket = socket(AF_INET, SOCK_STREAM)
#Prepare a sever socket
#Fill in start
serverSocket.bind(("0.0.0.0",6788))
serverSocket.listen(5)
#Fill in end
while True:
	#Establish the connection
	print 'Ready to serve...'
	connectionSocket, addr = serverSocket.accept() #Fill in start #Fill in end
	try:
		message = connectionSocket.recv(1024) #Fill in start #Fill in end
		print(message)
		filename = message.split()[1]
		f = open(filename[1:])
		outputdata = f.read() #Fill in start #Fill in end
		#Send one HTTP header line into socket
		#Fill in start
		message = "HTTP/1.1 200 OK\r\n"
		message = message + "Connection: close\r\n"
		message = message + "Date: " + time.strftime('%Y-%m-%d',time.localtime(time.time())) + "\r\n"
		message = message + "Server: WSL\r\n"
		message = message + "Last-Modified: " + time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time())) + "\r\n"
		message = message + "Content-Length: " + str(len(outputdata)) + "\r\n"
		message = message + "Content-Type: text/html" + "\r\n"
		message = message + "\r\n"
		connectionSocket.send(message)
		#Fill in end
		#Send the content of the requested file to the client
		for i in range(0, len(outputdata)):
			connectionSocket.send(outputdata[i])
		connectionSocket.close()
	except IOError:
		#Send response message for file not found
		#Fill in start
		message = "HTTP/1.1 404 Not Found\n\n"
		connectionSocket.send(message)
		#Fill in end
		#Close client socket
		#Fill in start
		connectionSocket.close()
		#Fill in end
serverSocket.close()