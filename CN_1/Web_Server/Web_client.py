from socket import *
ip_port = ('127.0.0.1',6789)
clientSocket = socket(AF_INET, SOCK_STREAM)
clientSocket.connect(("127.0.0.1",6789))
message = "GET /HelloWorld.html HTTP/1.1\r\n"
message = message + "Host: 127.0.0.1:6789\r\n"
message = message + "Connection: keep-alive\r\n"
clientSocket.sendto(message,ip_port)
message =  clientSocket.recv(1024)
print(message),
k = message.find("Content-Length:") + 15
str_len = ""
while (message[k] != '\r'):
	str_len = str_len + message[k]
	k = k + 1
length = int(str_len)
data = ""
for i in range(length):
	data = data +  clientSocket.recv(1024)
print(data)
clientSocket.close()