import socket as s  # Socket
import re  # Regex
import datetime
from threading import Thread
import requests,mimetypes

resp_on = """HTTP/1.1 200 OK
Connection: Keep-Alive
Content-Type: text
Accept-Ranges: bytes
Content-Length: {length}
Vary: Accept-Encoding

{body}

"""


class VPN:
    def __init__(self, ip, span):
        self.ip = ip
        self.span = span
        self.filter()  # call the method when the object initialise

    def filter(self):
        flag = 0
        if (flag == 0):
            iplist = open("ip.txt", "r")
            for IP in iplist:
                x = re.search("(({}))".format(IP.strip()), self.ip)
                if x:
                    f = open("VPN_log.log", "a")
                    f.write("\n"+self.ip+"\t"+str(self.span))
                    f.close()
                    flag =1
                    break
        elif (flag == 0):
            iplist = open("subnet.txt","r")
            for IP in iplist:
                IP = IP.strip()
                R1 = re.search("\A2.", self.ip)
                R2 = re.search("\A3.", self.ip)
                R3 = re.search("\A5.", self.ip)
                if R1 or R2 or R3:
                    f = open("VPN_log.log", "a")
                    f.write("\n"+self.ip+"\t"+str(self.span))
                    f.close()
                    break

class Balancer(Thread):
    def __init__(self,conn,ip):
        Thread.__init__(self)
        self.conn = conn
        self.ip = ip

    def run(self):
        data = conn.recv(4098)
        #req = data.decode()
        resp = requests.get("http://127.0.0.1/")
        with open('buffer.html','w') as buffer:
            buf = buffer.write(resp.text) 
        with open('buffer.html','r') as buffer:
            buf = buffer.read()
        conn.sendall(resp_on.format(type=mimetypes.guess_type(buf)[0],length=len(buf),body=buf).encode())
        


ip = "127.0.0.1"
port = 9999

socket = s.socket(s.AF_INET, s.SOCK_STREAM)
socket.setsockopt(s.SOL_SOCKET, s.SO_REUSEADDR, 1)
socket.bind((ip,port))
socket.listen()

    
while True:
    conn, ip = socket.accept()
    #conn.send("Proxy server".encode())
    span = datetime.datetime.now()  # IP login time
    VPN(ip[0], span)  #Object constructed
    Balancer(conn,ip).start()
            
            
"""            while True:
                data = conn.recv(1024)
                print(data.decode())
            #conn.close()
            #socket.close()
            break  """
