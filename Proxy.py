import socket as s  # Socket
import re  # Regex
import datetime

class VPN:
    def __init__(self, ip, span):
        self.ip = ip
        self.span = span
        self.filter()  # call the method when the object initialise

    def filter(self):
        iplist = open("iplist.txt", "r")
        for IP in iplist:
            x = re.search("(({}))".format(IP.strip()), self.ip)
            if x:
                f = open("VPN_log.log", "a")
                f.write("\n"+self.ip+"\t"+str(self.span))
                f.close()
                break

class Proxy(VPN):
    def __init__(self, ip, port):
        self.ip = ip          # Alterable
        self.port = port      # Alterable
        self.socket()

    def socket(self):
        socket = s.socket(s.AF_INET, s.SOCK_STREAM)
        socket.setsockopt(s.SOL_SOCKET, s.SO_REUSEADDR, 1)
        socket.bind((self.ip,self.port))
        socket.listen()

        while True:
            conn, ip = socket.accept()
            conn.send("Proxy server".encode())
            span = datetime.datetime.now()  # IP login time
            vpn = VPN(ip[0], span)
            conn.close()
            socket.close()
            break

ip = "127.0.0.1"
port = 9999
p1 = Proxy(ip,port)