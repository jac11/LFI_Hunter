#!/usr/bin/env python3
import configparser
import argparse
import re
import sys

with open('./Package/Banner','r') as banner:
    print(banner.read())

class Hannter_LFI:
      
      def __init__(self):
         self.control()
        
         if self.args.readuser :
            try:
                with open(self.args.readuser,'r') as username:
                      self.args.user = username.read().replace('/n','')
            except FileNotFoundError as e :
                print('\n'+'='*20+"\n[*] ERROR-INFO "+'\n'+'='*30+'\n')
                print("[*] Error : ",e )
                print('\n'+'='*10+"\n[*] Solution "+'\n'+'='*14+'\n')
                print("[*] find the correct Path ")
                exit()          
         if self.args.readpass :
            try : 
                with open(self.args.readpass,'r') as password:
                   self.args.password = password.read().replace('/n','')  
            except FileNotFoundError as e :
                print('\n'+'='*20+"\n[*] ERROR-INFO "+'\n'+'='*30+'\n')
                print("[*] Error : ",e )
                print('\n'+'='*10+"\n[*] Solution "+'\n'+'='*14+'\n')
                print("[*] find the correct Path ")  
                exit()   
         if self.args.Aggressiv :
               from Package.aggressiv import Aggressiv  

               if self.args.auth and self.args.Vulnurl\
                  and self.args.password and self.args.user\
                  and self.args.Cookie and self.args.loginurl\
                  and self.args.Aggressiv or self.args.config :  

                     Aggressiv.__init__(self,args = self.control)          
                     Aggressiv.Login_auth(self,args = self.control)
                     Aggressiv.url_request(self,args = self.control)
                     Aggressiv.Scan_result(self,aegs = self.control) 

               elif not self.args.auth and self.args.Vulnurl\
               and not self.args.password and not self.args.user and self.args.Cookie\
               and self.args.Aggressiv or self.args.config:
                  Aggressiv.__init__(self,args = self.control)
                  Aggressiv.url_request(self,args = self.control)
                  Aggressiv.Scan_result(self,aegs = self.control)

               else:
                  print('\n'+'='*20+"\n[*] ERROR-INFO "+'\n'+'='*30+'\n')
                  print("[*] Error :  Bad argument Logic command  Error" )
                  print('\n'+'='*10+"\n[*] Solution "+'\n'+'='*14+'\n')
                  print('[+] To use LFI with login     : --auth --loginurl --Vulnurl --user --password --filelist --Cookie ') 
                  print('[+] To use LFI without  login : --Vulnurl --filelist --Cookie') 
                  print("[*] ckeck Readme file at      : https://www.github/jac11/LFI_Hunter.git")
                  exit()  
         elif self.args.fuzzing  :
              from Package.main_lfi import Local_File_In
              Local_File_In.__init__(self,args = self.control)
              Local_File_In.url_request(self,args = self.control)
              Local_File_In.Scan_result(self,aegs = self.control)
      
         elif self.args.read :
              from Package.one_read import Read_File
              Read_File.__init__(self,args = self.control)  
              Read_File.Login_auth(self,aegs = self.control)
              Read_File.Scan_result(self,aegs = self.control)
         elif self.args.PARAME :
            from Package.parameters import UrlParameters
            UrlParameters.Fprint_Print(self,args=self.control) 
            UrlParameters.URL_separated(self,args=self.control)
                                 
      def control(self): 
         try: 
            parser = argparse.ArgumentParser(
               description="Usage: [Option] [arguments] [-w] [arguments]",
                epilog="Example: python LFI_Hunter.py -FP file1.php"
           )
            parser.add_argument("--man", action='store_true', help="see man page")
            parser.add_argument("-UV", "--Vulnurl", action="store", required=False, help="Target URL for the vulnerable web application")
            parser.add_argument("--auth", action='store_true', help="Enable authentication mode")
            parser.add_argument("-F", "--filelist", action="store", help="Read from an LFI wordlist file")
            parser.add_argument("-C", "--Cookie", action="store", required=False, help="Provide the login session cookie")
            parser.add_argument("-B", "--base64", action='store_true', help="Enable decoding of base64-filtered PHP code")
            parser.add_argument("-R", "--read", action="store", help="Specify a file to read from the target machine")
            parser.add_argument("-UF", "--UserForm", action="store", help="Specify the HTML login form username field")
            parser.add_argument("-PF", "--PassForm", action="store", help="Specify the HTML login form password field")
            parser.add_argument("-P", "--password", action="store", help="Specify a password")
            parser.add_argument("-p", "--readpass", action="store", help="Read a password from a file")
            parser.add_argument("-LU", "--loginurl", action="store", help="Provide the login URL for authentication mode")
            parser.add_argument("-U", "--user", action="store", help="Specify a username")
            parser.add_argument("-u", "--readuser", action="store", help="Read a username from a file")
            parser.add_argument("-A", "--Aggressiv", action='store_true', help="Enable aggressive mode")
            parser.add_argument("--port", action="store", help="Set the port for netcat")
            parser.add_argument("-S", "--shell", action="store", help="Set up a reverse shell connection")
            parser.add_argument("-Z", "--fuzzing", action='store_true', help="Enable brute-force mode")
            parser.add_argument("--config", action='store', help="Use a configuration file with all options")
            parser.add_argument("-FP","--PARAME", action='store', help="parameter fuzzing [replace the parameter with PARAME in url]\
             [Fuzzed URL: http://example.com/vulnerabilities/fi/?PARAME=file1.php]")
            parser.add_argument("-PL","--paramslist", action='store', help="parameter fuzzing wordlist")
          
            self.args = parser.parse_args() 
            if self.args.man:
                from Package.lfi_info import ManPage
                ManPage.man_info(self,args=self.control)
                exit()
            try: 
               if not self.args.config:
                  dlink = str(re.search(r'https?://(www\.)?([a-zA-Z0-9]+)(\.[a-zA-Z0-9.-]+)', self.args.Vulnurl)).split()
                  ip_re = (dlink[-1][7:-2])
                  ip_re = ip_re[7:]
            except Exception :
                try:
                   ip_re = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',self.args.Vulnurl)
                   ip_re = ip_re.group()   
                except Exception:
                    try:
                       dlink = str(re.search(r'https?://(www\.)?([a-zA-Z0-9]+)(\.[a-zA-Z0-9.-]+)', self.args.PARAME)).split()
                       ip_re = (dlink[-1][7:-2])
                       ip_re = ip_re[7:]
                    except Exception:
                        try:
                            ip_re = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',self.args.PARAME)
                            ip_re = ip_re.group()  
                        except Exception:
                            exit()       
            if len(sys.argv) > 1 and not self.args.config:
               config = configparser.ConfigParser()
               if   self.args.Cookie:
                      config['Cookie']={}
                      config['Cookie']['Cookie']= self.args.Cookie                   
               if   self.args.Vulnurl:
                      config['Vulnurls']={}
                      config['Vulnurls']['Vulnurl']= self.args.Vulnurl             
               if   self.args.filelist:
                      config['filelist']={}
                      config['filelist'][ 'filelist']= self.args.filelist                     
               if   self.args.read:
                      config['read']={}
                      config['read'][ 'read']= self.args.read                      
               if   self.args.UserForm:
                      config['UserForm']={}
                      config['UserForm'][ 'UserForm']= self.args.UserForm                     
               if   self.args.PassForm:
                      config['PassForm']={}
                      config['PassForm'][ 'PassForm']= self.args. PassForm                 
               if   self.args.password:
                      config['password']={}
                      config['password'][ 'password']= self.args.password               
               if   self.args.loginurl:
                      config['loginurl']={}
                      config['loginurl'][ 'loginurl']= self.args.loginurl                
               if   self.args.user:
                      config['user']={}
                      config['user'][ 'user']= self.args.user                   
               if   self.args.port:
                      config['port']={}
                      config['port'][ 'port']= self.args.port                      
               if   self.args.shell:
                      config['shell']={}
                      config['shell'][ 'shell']= self.args.shell                    
               if   self.args.readpass:
                      config['readpass']={}
                      config['readpass'][ 'readpass']= self.args.readpass
               if   self.args.fuzzing:
                      config['fuzzing']={}
                      config['fuzzing'][ 'fuzzing']= "True" 
               if   self.args.Aggressiv:
                      config['Aggressiv']={}
                      config['Aggressiv'][ 'Aggressiv']= "True" 
               if self.args.auth:
                      config['auth']={}
                      config['auth']['auth'] ="True"
               if self.args.base64:
                      config['base64']={}
                      config['base64']['base64'] ="True"     
               if self.args.readuser:
                      config['readuser'] ={}
                      config['readuser']['readuser']= self.args.readuser  
               if self.args.PARAME:
                      config['PARAME'] ={}
                      config['PARAME']['PARAME']= self.args.PARAME
               if self.args.paramslist:
                      config['paramslist'] ={}
                      config['paramslist']['paramslist']= self.args.paramslist 

               with open("./Package/ConfigFile/"+ip_re+'.ini', 'w') as configfile:
                    config.write(configfile)  
            elif len(sys.argv) > 1 and self.args.config:
               config = configparser.ConfigParser()
               config.read("./Package/ConfigFile/"+self.args.config)
               if not self.args.Vulnurl and 'Vulnurls' in config:
                  self.args.Vulnurl = config['Vulnurls'].get('Vulnurl')
               if not self.args.Cookie and 'Cookie' in config:
                   self.args.Cookie = config['Cookie'].get('Cookie')
               if not self.args.filelist and 'filelist' in config:
                   self.args.filelist = config['filelist'].get('filelist')
               if not self.args.read and 'read' in config:
                   self.args.read = config['read'].get('read')
               if not self.args.UserForm and 'UserForm' in config:
                   self.args.UserForm = config['UserForm'].get('UserForm')
               if not self.args.PassForm and 'PassForm' in config:
                   self.args.PassForm = config['PassForm'].get('PassForm')
               if not self.args.password and 'password' in config:
                   self.args.password = config['password'].get('password')
               if not self.args.loginurl and 'loginurl' in config:
                   self.args.loginurl = config['loginurl'].get('loginurl')
               if not self.args.user and 'user' in config:
                   self.args.user = config['user'].get('user')
               if not self.args.port and 'port' in config:
                   self.args.port = config['port'].get('port')
               if not self.args.shell and 'shell' in config:
                   self.args.shell = config['shell'].get('shell')
               if not self.args.readpass and 'readpass' in config:
                   self.args.readpass = config['readpass'].get('readpass')
               if not self.args.readuser and 'readuser' in config:
                   self.args.readuser = config['readuser'].get('readuser')
               if not self.args.PARAME and 'PARAME' in config:
                   self.args.PARAME = config['PARAME'].get('PARAME')   
               if not self.args.paramslist and 'paramslist' in config:
                   self.args.paramslist = config['paramslist'].get('paramslist')    
               if not self.args.fuzzing and 'fuzzing' in config:
                   self.args.fuzzing = config['fuzzing'].getboolean('fuzzing')
               if not self.args.Aggressiv and 'Aggressiv' in config:
                   self.args.Aggressiv = config['Aggressiv'].getboolean('Aggressiv')
               if not self.args.base64 and 'base64' in config:
                   self.args.base64 = config['base64'].getboolean('base64')
               if not self.args.auth and 'auth' in config:
                   self.args.auth = config['auth'].getboolean('auth')
            else:
               parser.print_help()      
               exit()

         except AssertionError as a :
            print('\n'+'='*20+"\n[*] ERROR-INFO "+'\n'+'='*30+'\n')
            print("[*] Error :  Bad argument" )
            print('\n'+'='*10+"\n[*] Solution "+'\n'+'='*14+'\n')
            print("[*] try to use --help")
            print("[*] Check Readme file at : https://www.github/jac11/LFI_Hunter.git")
            exit()           
if __name__=='__main__':
    Hannter_LFI()