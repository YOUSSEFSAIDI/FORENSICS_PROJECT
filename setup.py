#!/usr/bin/env python
import argparse
banner = """ \033[1m \033[33m
 ######   #####    ##     ######    ##    #     #    ##    #      #   #  ######  ######  ######
 #    #  #        #  #    #    #   #  #   ##    #   #  #   #      #   #  #       #       #    #
 ######  #       #    #   ######  #    #  # #   #  #    #  #       # #   #       #       #    # 
 #       #       ######   #       ######  #  #  #  ######  #        #    ######  ######  ###### 
 #       #       #    #   #       #    #  #   # #  #    #  #        #         #  #       #    #
 #       #       #    #   #       #    #  #    ##  #    #  #        #         #  #       #     #
###       #####  #    #  ###      #    #  #     #  #    #  ######   #    ######  ######  #     #
************************************************************************************************
Author: YOUSSEF SAIDI & AZMI HAMADI
Built With: Python and Scapy \033[0m
\033[33m************************************************************************************************
Usage: python analyser.py [options] [pcapfile]
Options:
      -bl, --blacklist_locally          Blacklistiong using local database
      -bo, --blacklist_online           Blacklisting using online database "zen.spamhaus.org"
      -d , --destination_unreacheable   Detecting ICMP Destination Unreacheable
      -h , --hardcoded_addresses        Detecting Hardcoded Address based on DNS Responses
      -a , --anomalous_DNS_values       Detecting Anomalous Contacted Domains\033[0m
	 """
print banner
parser = argparse.ArgumentParser(description='Short sample app')
parser.add_argument('-b', action="store", dest="b")
args = parser.parse_args()
print args
