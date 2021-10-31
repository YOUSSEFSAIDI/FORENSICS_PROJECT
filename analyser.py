#!/usr/bin/env python

# Suppress warnings about missing IPv6 route and tcpdump bin
import logging
logging.getLogger("scapy.loading").setLevel(logging.ERROR)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
import sys
import dns.resolver



blacklist_list = []
blacklist_checked = []
contacted_address = []
domain_contacted = []
domain_list = []
domain_checked_online = []

#-----------------------------------------------------------------------------------------------------------------------------------------------
       #####################Check the validity of the query response(respect the form of an ip address)#####################
#-----------------------------------------------------------------------------------------------------------------------------------------------
def validate_ip(s):
    a = s.split('.')
    if len(a) != 4:
        return False
    for x in a:
        if not x.isdigit():
            return False
        i = int(x)
        if i < 0 or i > 255:
            return False
    return True
#------------------------------------------------------------------------------------------------------------------------
                         #####################Check Black List Using A Local List Of IP Addresses#####################
#------------------------------------------------------------------------------------------------------------------------
def check_local_blacklist(packet):
    src = packet[IP].src
    if src in blacklist_list:
       if src not in blacklist_checked:
          print """\033[1m \033[33m IP ADDRESS: %s IS Locally blacklisted\033[0m""" %(src)
          blacklist_checked.append(src)
   
    dst = packet[IP].dst
    #print socket.gethostbyname(dst.strip())
    if dst in blacklist_list:
       if dst not in blacklist_checked:
          print """\033[1m \033[33m IP ADDRESS: %s IS Locally blacklisted\033[0m""" %(dst)
          blacklist_checked.append(dst)
########Read Blacklist ########################
def read_list(filename, lists):
    with open(filename) as myfile:
        lines = myfile.readlines()
        
    for addr in lines:
        lists.append(addr[:-1])
#------------------------------------------------------------------------------------------------------------------------
                         #####################Check Black List Online#####################
#------------------------------------------------------------------------------------------------------------------------
def check_online_blacklist(packet):
    bls = ["zen.spamhaus.org"]
    myIP = packet[IP].src
    for bl in bls:
        try:
           my_resolver = dns.resolver.Resolver()
           query = '.'.join(reversed(str(myIP).split("."))) + "." + bl
           answers = my_resolver.query(query, "A")
           answer_txt = my_resolver.query(query, "TXT")
           if myIP not in domain_checked_online:
              print """\033[1m \033[33mIP: %s IS listed in %s (%s: %s)\033[0m""" %(myIP, bl, answers[0], answer_txt[0])
              domain_checked_online.append(myIP)
        except dns.resolver.NXDOMAIN:
               continue
#------------------------------------------------------------------------------------------------------------------------
                          #####################Check Destination Unreacheable#####################
#------------------------------------------------------------------------------------------------------------------------
def Check_destination(packet, packet_count, hasprinted_destination):
      icmp_type = packet[ICMP].type
      if icmp_type == 3:
         if not hasprinted_destination:
                print """\033[1m \033[33m There is Destination Unreachable And It is on The Trace in packet Number:\033[0m"""
         print packet_count
         
def color(color_code, text):
    return '\033[{}m{}\033[0m'.format(color_code, text)
#------------------------------------------------------------------------------------------------------------------------
                        #####################Check DNS query Responses and Get Hardcoded Addresses#####################
#------------------------------------------------------------------------------------------------------------------------
def get_query_response(packet):
    a_count = packet[DNS].ancount
    i = a_count + 4
    while i > 4:
          dom = packet[0][i].rrname
          domain_contacted.append(dom)
          s = packet[0][i].rdata
          if validate_ip(s):
             contacted_address.append(s)
          else:
              domain_contacted.append(s)                    
          i -= 1   
def hardcoded_add(packet, packet_count):
    ip_dst=packet[IP].dst
    dst_port= packet[TCP].dport
    if (dst_port is 80) and (ip_dst not in contacted_address):
       print str(ip_dst) + '  In Packet Number  ' + str(packet_count)

#------------------------------------------------------------------------------------------------------------------------
                          #####################Main#####################
#------------------------------------------------------------------------------------------------------------------------
def main():
    options =['-bl', '-bo', '-h' , '-d', '-hd','-a']
    hasprinted_destination = False
    myfile = sys.argv[2] 
    option = sys.argv[1] 
    if option not in options:
       os.system('python setup.py') 
       return
    read_list("IP_blacklist.txt", blacklist_list)
    read_list("domain_blacklist.txt", domain_list)
    #print myfile
    packet_count = 0
    total_size = 0
    all_packets = rdpcap(myfile)
    if option=='-h':
       print """\033[1m \033[33m Hardcoded Addresses Are:\033[0m"""
    for packet in all_packets:
        packet_count += 1
        total_size += len(packet) 
        if packet.haslayer(DNSRR):
           get_query_response(packet)
 
        if IP in packet:
           if option == '-bl':
              check_local_blacklist(packet)
           elif option == '-bo':
                check_online_blacklist(packet)

        if (ICMP in packet) and (option == '-d'):
           Check_destination(packet, packet_count, hasprinted_destination)
           hasprinted_destination = True
        
        if (TCP in packet) and (option == '-h'):
            hardcoded_add(packet, packet_count)
    if (option == '-a'):
       print """\033[1m \033[33m Anoumalous Domains That are Contacted\033[0m"""
       for i in domain_list:
           if i in domain_contacted:
              print i
               

        
    # overall summary about packets  
    print """
-----------------------------------------------------------------------------------------------------------------------
********************************************SUMMARY OF THE ANALYSIS****************************************************
-----------------------------------------------------------------------------------------------------------------------"""  
    print "Analyzed " + str(packet_count) + " packets, " + str(total_size) + " bytes"
        
        
        
# run the code

main()

