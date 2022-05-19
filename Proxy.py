import socket as s  # Socket
import re  # Regex
import datetime,time
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
        self.log()  # call the method when the object initialise

    def log(self):
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
        req = data.decode()
        #print(req)
        resp = requests.get("http://127.0.0.1/")
        with open('buffer.html','w') as buffer:
            buf = buffer.write(resp.text) 
        with open('buffer.html','r') as buffer:
            buf = buffer.read()
        conn.sendall(resp_on.format(type=mimetypes.guess_type(buf)[0],length=len(buf),body=buf).encode())
        conn.close()


ip = "127.0.0.1"
port = 9999
connINTime = []   #connections seconds log in LIST for DOS Mitigation

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

    def ConnInlogTime(ip):    #this method for appending time+ip in a list and passing to DOSMitigation method
        sec = str(time.time())
        sec = sec.split(".")
        connInSec = sec[0]+" "+ip
        connINTime.append(connInSec)
        DosMitigation(connINTime)

    def DosMitigation(connINTime):    #this method gets time+ip list and do process
        sec = connINTime
        val = 0
        if(len(sec) == 6):            #It's check if a request is comes more than enough within a second
            for i in sec:
                span = i.split(" ")
                val = int(span[0]) - val 
                #val = abs(val)
            
            if(val < 1):            #If a rquest is malicious it will append the IPs in a IPCHECK list
                IPCHECK = []
                for i in sec:
                    ip = i.split(" ")
                    ip = ip[1]
                    IPCHECK.append(ip)
                    
                if len(set(IPCHECK)) == 1:  #If the request is from same IPs it will write the IP in a BlockIP file
                    with open("BlockIP.txt","a") as file:
                        f = file.write(IPCHECK[0]+"\n")     
                connINTime.clear()                          #Clear the list for every given list size is exceeds
            else:
                connINTime.clear()

    ConnInlogTime(ip[0])   

