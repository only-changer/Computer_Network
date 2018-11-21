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
recv3 = clientSocket.recv(1024)
print("authenticationCommand : " + recv3)

userCommand = str(base64.b64encode('964700351@qq.com')) + '\r\n' 
clientSocket.send(userCommand)
recv4 = clientSocket.recv(1024)
print("userCommand : " + recv4)

passwordCommand = str(base64.b64encode('iienzjrntujbbfed')) + '\r\n' 
clientSocket.send(passwordCommand)
recv5 = clientSocket.recv(1024)
print("passwordCommand : " + recv5)

mailfromCommand = 'MAIL FROM:<964700351@qq.com>\r\n'
clientSocket.send(mailfromCommand)
recv6 = clientSocket.recv(1024)
print("mailfromCommand : " + recv6)
# Fill in end
# Send RCPT TO command and print server response.
# Fill in start

recptoCommand = 'RCPT TO:<only-changer@sjtu.edu.cn>\r\n'

clientSocket.send(recptoCommand)
recv7 = clientSocket.recv(1024)
print("recptoCommand : " + recv7)
# Fill in end
# Send DATA command and print server response.
# Fill in start
dataCommand = 'DATA\r\n'
clientSocket.send(dataCommand)
recv8 = clientSocket.recv(1024)
print("dataCommand : " + recv8)

mailHead = 'From: <964700351@qq.com>\r\nTo:<only-changer@sjtu.edu.cn>\r\nSubject: Do you require my assistance?\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed;boundary="sjtu"\r\n'
clientSocket.send(mailHead)

dataHead = '\r\n\r\n--sjtu\r\nContent-Type: image/jpeg; name=aha.jpg\r\nContent-Transfer-Encoding: base64\r\n\r\n'
clientSocket.send(dataHead)
with open('aha.jpg', 'rb') as f:
    img_data = base64.b64encode(f.read())
    clientSocket.send(img_data)

dataHead = '\r\n\r\n--sjtu\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\n'
data = '\r\n AHA! \n I love computer networks!\r\n'
clientSocket.send(dataHead)
clientSocket.send(data)


# Fill in end
# Send message data.
# Fill in start

# Fill in end
# Message ends with a single period.
# Fill in start
clientSocket.send(endmsg)
# Fill in end
# Send QUIT command and get server response.
# Fill in start
quitCommand = 'QUIT\r\n'
clientSocket.send(quitCommand)
recv9 = clientSocket.recv(1024)
print("quitCommand : " + recv9)
# Fill in end