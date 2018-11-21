from socket import *
import time
import numpy as np
import random
def folat2str(f):
    X = int(f)
    Y = f - X
    str_X = str(X)
    str_Y = str(Y)
    str_f = str_X + str_Y[1:]
    return str_f
ip_port = ('127.0.0.1',8080)

clientSocket = socket(AF_INET, SOCK_DGRAM)
while True:

    for i in range(10):

        message = str(i + 1) + "\n"
        message = message + folat2str(time.time()) + "\n"

        rand = random.randint(0, 10)
        if rand < 4:
            continue

        clientSocket.sendto(message,ip_port)
    print("HeartBeat Done ! ")
    time.sleep(2)
    
clientSocket.close()