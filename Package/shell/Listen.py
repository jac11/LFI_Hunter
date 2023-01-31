#!/usr/bin/env python3
import os
import time

with open ('./Package/shell/.port','r') as port:
          port = port.read().replace('\n','')
           
with open (str(os.getcwd())+'/Package/Banner','r') as read:
    print(read.read())

info = ''
info +='='*20+'\n'
info +='[+] netcat listener \n'
info +='='*30+'\n'
info +='[!] IP   : .............| : 0.0.0.0\n'
info +='[+] Port : .............| : '+port+'\n'
info +='='*40+'\n'
print(info,end='')
line = '┌──(Netcat)-[~/LFT_Hunter]\n'
line +='└─$ \n'
print(line)
line1 ='nc -nvlp  '+port
os.remove('./Package/shell/.port')
command = os.system(line1)

