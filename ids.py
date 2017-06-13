#! /usr/bin/env python2.7
from scapy.all import *
from netfilterqueue import NetfilterQueue
from re import *
import urllib
import logging

regex_to_match = [
    "'\s*--(\s|')",
    "'\s*(and|or|xor|&&|\|\|)\s*\(?\s*('|[0-9]|`?[a-z\._-]+`?\s*(=|like)|[a-z]+\s*\()",
    "'\s*(not\s+)?in\s*\(\s*['0-9]",
    "union(\s+all)?(\s*\(\s*|\s+)select(`|\s)",
    "select(\s*`|\s+)(\*|[a-z0-9_\, ]*)(`\s*|\s+)from(\s*`|\s+)[a-z0-9_\.]*",
    "insert\s+into(\s*`|\s+).*(`\s*|\s+)(values\s*)?\(.*\)",
    "update(\s*`|\s+)[a-z0-9_\.]*(`\s*|\s+)set(\s*`|\s+).*=",
    "delete\s+from(\s*`|\s+)[a-z0-9_\.]*`?"
]

def print_red(prt): print("\033[91m {}\033[00m" .format(prt))
def print_green(prt): print("\033[92m {}\033[00m" .format(prt))

def http_headers(load):
    load = repr(load)[1:-1]
    headers, body = load.split(r"\r\n\r\n", 1)
    header_lines = headers.split(r"\r\n")
    return header_lines

def parse_post(load):
    load = repr(load)[1:-1]
    headers, body = load.split(r"\r\n\r\n", 1)
    header_lines = headers.split(r"\r\n")
    return body

def get_host(headers):
    for header in headers:
        if "Host" in header:
            return header

def get_request(headers):
    for req in headers:
        if "GET" in req or "POST" in req:
            return req

def url_decode(enc):
    dec = urllib.unquote(enc)
    dec = dec.replace('+', ' ')
    return dec

def detect_sqli(url, body):
    count = 0
    for reg in regex_to_match:
        # compile regex
        pattern = re.compile(reg, re.IGNORECASE)
        
        #check for url
        res = re.search(pattern, url)
        if res is not None:
            count += len(res.groups())

        #check for body
        if body is not '':
            res = re.search(pattern, body)
            if res is not None:
                count += len(res.groups())

        if(count > 0):
            return True
    return False

def handle_packet(packet):
    pkt = IP(packet.get_payload())
    wasDrop = False
    if pkt.haslayer(Raw):
        if pkt.haslayer(TCP):
            dport = pkt[TCP].dport
            sport = pkt[TCP].sport
            ack = pkt[TCP].ack
            seq = pkt[TCP].seq
            load = pkt[Raw].load

            if dport == 80 or sport == 80:
                
                headers = http_headers(load)
                request = get_request(headers)
                host = get_host(headers)
                body = ''
                method = request.split(' ')[0]
                url = url_decode(request.split(' ')[1])
                
                message = "TCP - ACK : " + str(ack) + " | HTTP : " + method + " Request on " + host + " with Url : " + url
            
                if method == "POST" and "ocsp" not in host:
                    body = parse_post(load)
                    body = url_decode(body)
                    message = message + " and Body : " + body
            
                logging.info(message)
                print message
                
                if detect_sqli(url, body):
                    #packet.drop()
                    
                    message = "TCP Packet with ACK : " + str(ack) + " has been dropped, SQLi detected!"
                    logging.info(message)
                    print_red(message)

                    #wasDrop = True
                else:
                    print_green("Http Packet is clean, continuing... :)")
    if not wasDrop:
        packet.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(0, handle_packet)

logging.basicConfig(level=logging.INFO, filename='ids.log', format='%(asctime)s %(message)s')
try:
    print "[*] SQLi Defender is awating..."
    nfqueue.run()
except KeyboardInterrupt:
    pass