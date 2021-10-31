# Forensics Project [F5]: Detection of suspicious behaviors from a pcap file

# Writers: Youssef Saidi &&& Azmi Hamadi

## What this program provides

* Blacklistiong using local database
* Blacklisting using online database "zen.spamhaus.org"
* Detecting ICMP Destination Unreacheable
* Detecting Hardcoded Address based on DNS Responses
* Detecting Anomalous Contacted Domains

## Set-up requirements:

### Scapy Installation:
This program is a python based program that requires the scapy module which is a powerful module of network paquets analysis.
here is the link to the moule installation:
[Scapy Installation](https://scapy.readthedocs.io/en/latest/installation.html)

### Dns.resolver Installation
```
git clone https://github.com/rthalley/dnspython
cd dnspython/
python setup.py install

```
## How the program works
```
python setup.py

```
this will display how the program works.

