import socket as s     #Socket
import re              #Regex
import datetime

class VPN:
    def __init__(self,ip,span):
        self.ip = ip
        self.span = span
        self.filter()   #call the method when the object initialise
        

    def filter(self):
        x = re.search("((127.0.0.1))", self.ip) 
        if x:
            f = open("VPN_log.log","a")
            f.write("\n"+self.ip+"\t"+str(span))
            f.close()
        else:
            return 0

ip = "127.0.0.1" # Alterable
port = 9999      # Alterable

socket = s.socket(s.AF_INET,s.SOCK_STREAM)
socket.setsockopt(s.SOL_SOCKET, s.SO_REUSEADDR, 1)
socket.bind((ip,port))
socket.listen()

while True:
    conn,ip  = socket.accept()
    conn.send("Proxy server".encode())
    span = datetime.datetime.now()  #IP login time
    vpn = VPN(ip[0],span)
    conn.close()
    socket.close()
    break
    