from socket import *
import time
import numpy as np
ip_port = ('127.0.0.1',8081)

clientSocket = socket(AF_INET, SOCK_DGRAM)
while True:
    RRTs = []
    for i in range(10):
    	print ("TRY PING " + str(i + 1))
    	try:
            message = "Ping " + str(i + 1) + "\n"
            time_start = time.time()
            clientSocket.sendto(message,ip_port)
            clientSocket.settimeout(1.0)
            message =  clientSocket.recv(1024)
            time_end = time.time()
            RRTs.append(time_end - time_start)
            print("MESSAGE : " + message),
            print("RRT : " + str(RRTs[len(RRTs) - 1]))
    	except:
    		print("OPPS ! Request timed out")
    	print
    print("RRT MINIMUM : " + str(np.min(RRTs)))
    print("RRT MAXIMUM : " + str(np.max(RRTs)))
    print("RRT AVERAGE : " + str(np.mean(RRTs)))
    print("PACKAGE LOSS RATE : " + str((10 - len(RRTs)) * 10) + "%")
    break
clientSocket.close()