# We will need the following module to generate randomized lost packets
import random
import time
from socket import *
import numpy as np
# Create a UDP socket
# Notice the use of SOCK_DGRAM for UDP packets
serverSocket = socket(AF_INET, SOCK_DGRAM)
# Assign IP address and port number to socket
serverSocket.bind(('0.0.0.0', 8080))
while True:
    print 'Ready to serve...'
    HB_Number = []
    serverSocket.settimeout(None)
    message, address = serverSocket.recvfrom(1024)
    time_start = time.time()
    RRTs = []
    while (time.time() - time_start < 1):
        try:
            HB_Number.append(message.split()[0])
            RRTs.append(time.time() - float(message.split()[1]))
            serverSocket.settimeout(1.0)
            message = serverSocket.recv(1024)
        except:
            break
    print("RRT MINIMUM : " + str(np.min(RRTs)))
    print("RRT MAXIMUM : " + str(np.max(RRTs)))
    print("RRT AVERAGE : " + str(np.mean(RRTs)))
    print("PACKAGE LOSS RATE : " + str((10 - len(RRTs)) * 10) + "%")
    print

serverSocket.close()