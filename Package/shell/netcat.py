#!/usr/bin/env python3
import os
import time
port  = None
with open ('./Package/Banner','r') as read:
     print(read.read())
try:
     with open ('./Package/shell/.port','r') as port:
         port = port.read().replace('\n','')  
except Exception:
   pass         
info = ''
info +='='*20+'\n'
info +='[+] netcat listener \n'
info +='='*30+'\n'
info +='[!] IP   : .............| : 0.0.0.0\n'
if port == None:
  info +='[+] Port : .............| : 7777\n'
else:
      info +='[+] Port : .............| : '+ str(port)+'\n'
info +='='*40+'\n'
print(info,end='')
line = '┌──(Netcat)-[~/LFT_Hunter]\n'
line += '└─$ '
if  port == None :
   line1 ='nc -nvlp  7777'
else: 
     line1 = f'nc -nvlp {port}'
print(line)     
command = os.system(line1)
