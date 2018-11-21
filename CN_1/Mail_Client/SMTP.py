from socket import *
import base64
msg = "\r\n I love computer networks!"
endmsg = "\r\n.\r\n"
# Choose a mail server (e.g. Google mail server) and call it mailserver 
mailserver = ("smtp.qq.com" , 587)#Fill in start #Fill in end
# Create socket called clientSocket and establish a TCP connection with mailserver
#Fill in start
clientSocket = socket(AF_INET, SOCK_STREAM)
clientSocket.connect(mailserver)
#Fill in end
recv = clientSocket.recv(1024)
print("connectCommand : " + recv)
if recv[:3] != '220':
	print '220 reply not received from server.'
# Send HELO command and print server response.
heloCommand = 'HELO Alice\r\n'
clientSocket.send(heloCommand)
recv1 = clientSocket.recv(1024)
print("heloCommand : " + recv1)
if recv1[:3] != '250':
	print '250 reply not received from server.'
# Send MAIL FROM command and print server response.
# Fill in start
starttlsCommand = 'starttls enable\r\n'
clientSocket.send(starttlsCommand)
recv2 = clientSocket.recv(1024)
print("starttlsCommand : " + recv2)

authenticationCommand = 'auth login\r\n'
clientSocket.send(authenticationCommand)
recv2 = clientSocket.recv(1024)
print("authenticationCommand : " + recv2)

userCommand = str(base64.b64encode('964700351@qq.com')) + '\r\n' 
clientSocket.send(userCommand)
recv2 = clientSocket.recv(1024)
print("userCommand : " + recv2)

passwordCommand = str(base64.b64encode('iienzjrntujbbfed')) + '\r\n' 
clientSocket.send(passwordCommand)
recv2 = clientSocket.recv(1024)
print("passwordCommand : " + recv2)

mailfromCommand = 'MAIL FROM:<964700351@qq.com>\r\n'
clientSocket.send(mailfromCommand)
recv2 = clientSocket.recv(1024)
print("mailfromCommand : " + recv2)
# Fill in end
# Send RCPT TO command and print server response.
# Fill in start
recptoCommand = 'RCPT TO:<only-changer@sjtu.edu.cn>\r\n'
clientSocket.send(recptoCommand)
recv3 = clientSocket.recv(1024)
print("recptoCommand : " + recv3)
# Fill in end
# Send DATA command and print server response.
# Fill in start
dataCommand = 'DATA\r\n'
clientSocket.send(dataCommand)
recv4 = clientSocket.recv(1024)
print("dataCommand : " + recv4)
# Fill in end
# Send message data.
# Fill in start
clientSocket.send(msg)
# Fill in end
# Message ends with a single period.
# Fill in start
clientSocket.send(endmsg)
# Fill in end
# Send QUIT command and get server response.
# Fill in start
quitCommand = 'QUIT\r\n'
clientSocket.send(quitCommand)
recv5 = clientSocket.recv(1024)
print("quitCommand : " + recv5)
# Fill in end