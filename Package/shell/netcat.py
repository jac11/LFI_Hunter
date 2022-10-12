#!/usr/bin/env python3
import os
import time
with open (str(os.getcwd())+'/Package/Banner','r') as read:
     print(read.read())
info = ''
info +='='*20+'\n'
info +='[+] netcat lislner \n'
info +='='*30+'\n'
info +='[!] IP   : .............| : 0.0.0.0\n'
info +='[+] Port : .............| : 7777\n'
info +='='*40+'\n'
print(info)
line = '┌──(Netcat)-[~/LFT_Hunter]\n'
line +='└─$ \n'
print(line)
line1 ='nc -nvlp  7777'
command = os.system(line1)

   
   
 

