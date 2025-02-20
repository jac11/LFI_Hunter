#!/usr/bin/env python3

import argparse
import mechanize
import ssl
import time
import os 
import sys
import re
ssl._create_default_https_context = ssl._create_unverified_context


class  UrlParameters:
    def __init__(self,**kwargs):
        
        self.Fprint_Print()
        self.URL_separated()
    def Fprint_Print(self,**kwargs):
        print("[+] Mothead                    : ................ | : Fuzzing Parameters") 
        print("[+] Parameters url             : ................ | : "+self.args.PARAME)
        try:
            dlink = str(re.search(r'https?://(www\.)?([a-zA-Z0-9]+)(\.[a-zA-Z0-9.-]+)', self.args.PARAME)).split()
            self.ip_re = (dlink[-1][7:-2])
            self.ip_re = self.ip_re[7:]
        except Exception:
            self.ip_re = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',self.args.PARAME)
            self.ip_re = self.ip_re.group()
    def URL_separated(self,**kwargs):
        try:
            try:   
                if self.args.Cookie  or self.args.config:
                    with open(self.args.Cookie,'r') as Cookie_file :
                      self.Cookie =  Cookie_file.read()
                elif not self.args.Cookie or self.args.config:
                    with open("./Package/ConfigFile/.Cookie.txt",'r') as Cookie_file :
                        self.Cookie =  Cookie_file.read()   
                print("[+] Cookie                     : ................ | : "+self.Cookie.replace('\n',''))               
            except Exception as e :
                   print('\n'+'='*20+"\n[*] ERROR-INFO "+'\n'+'='*30+'\n')
                   print("[*] Error : ",e )
                   print('\n'+'='*10+"\n[*] Solution "+'\n'+'='*14+'\n')
                   print("[*] Chech the File Name or File Path  to your Cookies File")
                   exit()
            keyword = "PARAME"            
            if  keyword not  in  self.args.PARAME :
                print('\n'+'='*20+"\n[*] ERROR-INFO "+'\n'+'='*30+'\n')
                print("[*] Error : PARAME Key Word Not in url ")
                print('\n'+'='*10+"\n[*] Solution "+'\n'+'='*14+'\n')
                print("[*] replace the part of url parameter by PARAME ") 
                print("[*] http://172.17.0.2/vulnerabilities/fi/?PARAME=file1.php  ")  
                exit() 

            self.url = self.args.PARAME
            if "PARAME" in self.url:
                partlink0,partlink1 = self.url.split("PARAME")
            if not self.args.paramslist :
                self.args.paramslist = "./Package/parames.txt" 

            else:  
                 pass   
            print("[+] wordlist                   : ................ | : "+self.args.paramslist)
            if self.args.status:
                print("[+] Filter Response Status     : ................ | : "+self.args.status)
            count = 0 
            listPar = []
            listlink = []
            listLen = []
            try: 
                with open (self.args.paramslist,'r',encoding = "ISO-8859-1")  as paramslist :  
                    paramslist = paramslist.readlines()
            except FileNotFoundError  as e :
                print('\n'+'='*20+"\n[*] ERROR-INFO "+'\n'+'='*30+'\n')
                print("[*] Error : ",e )
                print('\n'+'='*10+"\n[*] Solution "+'\n'+'='*14+'\n')
                print("[*] find the correct Path ")  
                exit()  
            print('\n'+'='*20+"\n[*] Test Parameters"+'\n'+'='*30+'\n')    
            print(" "+"-"*149)
            print("|  "+f"{'   Parameters    ':<23}","|"+f"{'  Length ':<10}","|"+f"{'  Status ':<10}","|",f"{'  Full-URL   ':<96}","|")
            print(" "+"-"*149)   
            param1 =  "GOOO"
            link = f'{partlink0}{param1}{partlink1}'
            request = mechanize.Browser()
            request.set_handle_robots(False)
            request.set_handle_redirect(False)
            request.set_handle_refresh(True, max_time=1)
            request.addheaders = [('User-agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1'),
            ('Cookie',self.Cookie.replace('\n','')),
            ]  
            try:
                response = request.open(link)
                response_content = response.read() 
                listLen.append(len(response_content))
            except Exception :
                listLen.append(101)    
            for param in paramslist:
                if '#'in param:
                    pass
                else:                  
                    param = param.replace('\n','')
                    link = f'{partlink0}{param}{partlink1}'
                    request = mechanize.Browser()
                    request.set_handle_robots(False)
                    request.set_handle_redirect(False)
                    request.set_handle_refresh(True, max_time=1)
                    request.addheaders = [('User-agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1'),
                    ('Cookie',self.Cookie.replace('\n','')),
                    ] 
                    if not self.args.status:
                        try:
                            response = request.open(link)
                            response_code = response.getcode()  
                            response_content = response.read() 
                            if response_code != 200:
                                pass
                            else:    
                                print("|  "+f"{  param[0:20]     :<23}","| "+f"{  len(response_content) :<10}"+"| "+f"{  response_code :<10}"+"| "+f"{   link[0:]   :<96}","|") 
                                sys.stdout.write('\x1b[1A')
                                sys.stdout.write('\x1b[2K')        
                                if len(response_content) in listLen :
                                    pass
                                else:    
                                    listLen.append(len(response_content))
                                if len(response_content) == listLen[0]  :
                                   pass
                                else:    
                                    count += 1
                                    listPar.append(param)
                                    listlink.append(response.geturl() + " >> Code 200")
                                    Lget = response_content
                                    Cget = response_code
                                    GLink = response.geturl()
                                    PGet = param 
                                    print("|  "+f"{  PGet[0:20]     :<23}","| "+f"{  len(Lget) :<10}"+"| "+f"{  Cget :<10}"+"| "+f"{    GLink [0:]   :<96}","|") 
                        except Exception as e :
                            if '302' in str(e):
                                Lget = 1042
                                code = 302
                                count += 1
                                listPar.append(param)
                                print("|  "+f"{ param[0:20]     :<23}","| "+f"{  Lget :<10}"+"| "+f"{  code :<10}"+"| "+f"{    link  :<96}","|") 
                                listlink.append(link + " >> Code 302")
                            if "301" in str(e):
                                Lget = 1042
                                code = 301
                                count += 1  
                                print("|  "+f"{  param[0:20]     :<23}","| "+f"{  Lget :<10}"+"| "+f"{  code :<10}"+"| "+f"{    link    :<96}","|") 
                                listPar.append(param)
                                listlink.append(link + " >> Code 301")
                            if "500" in str(e):
                                Lget = 1042
                                code = 500
                                count += 1  
                                print("|  "+f"{  param[0:20]     :<23}","| "+f"{  Lget :<10}"+"| "+f"{  code :<10}"+"| "+f"{    link    :<96}","|") 
                                listPar.append(param)
                                listlink.append(link + " >> Code 500")    
                            if "404" in str(e) :
                                Lget = 230
                                Cget = 404
                                print("|  "+f"{  param[0:20]     :<23}","| "+f"{  Lget :<10}"+"| "+f"{  Cget  :<10}"+"| "+f"{   link  :<96}","|") 
                                sys.stdout.write('\x1b[1A')
                                sys.stdout.write('\x1b[2K')
                                        
                    elif self.args.status:
                        try:
                            response = request.open(link)
                            response_code = response.getcode()  
                            response_content = response.read()   
                            print("|  "+f"{  param[0:20]     :<23}","| "+f"{  len(response_content) :<10}"+"| "+f"{  response_code :<10}"+"| "+f"{   link[0:]   :<96}","|") 
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K') 
                            
                            if self.args.status == str(response_code):
                                if len(response_content) in listLen :
                                    pass
                                else:    
                                    listLen.append(len(response_content))
                                if len(response_content) == listLen[0]  :
                                   pass
                                else:    
                                    count += 1
                                    listPar.append(param)
                                    listlink.append(response.geturl() + " >> Code 200")
                                    Lget = response_content
                                    Cget = response_code
                                    GLink = response.geturl()
                                    PGet = param 
                                    print("|  "+f"{  PGet[0:20]     :<23}","| "+f"{  len(Lget) :<10}"+"| "+f"{  Cget :<10}"+"| "+f"{    GLink [0:]   :<96}","|")  
                        except Exception as e:
                            Lget = 230
                            Cget =  500
                            print("|  "+f"{  param[0:20]     :<23}","| "+f"{  Lget :<10}"+"| "+f"{  Cget  :<10}"+"| "+f"{   link  :<96}","|") 
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K')
                time.sleep(.02)
        except KeyboardInterrupt : 
            pass  
        if count == 0 :   
           print('\n'+'='*20+"\n[*] Parameters Found  "+'\n'+'='*30+'\n')
           print("[+] Parameters Found              : ................ | : no Parameters found")
           exit()
        else:
            print('\n'+'='*20+"\n[*] Parameters Found  "+'\n'+'='*30+'\n')
            print("[+] Parameters Count          : ................ | : "+str(count)+'\n')
            print("[+] Parameter name            : ................ | : "+listPar[0])
            N = len(listPar)-1
            for _ in range(N) :
                print("\t\t\t\t\t\t | : "+listPar[N]) 
                N -=1 
            print()    
            print("[+] Full Url                  : ................ | : "+listlink[0])   
            N = len(listlink)-1 
            for _ in range(N) :
                print("\t\t\t\t\t\t | : "+listlink[N]) 
                N -=1 
            path = ('file://'+os.getcwd()+'/FileStore/')
            if not os.path.exists('./FileStore/'+self.ip_re+"/"):
                    os.makedirs('./FileStore/'+self.ip_re+"/")
                    with open('./FileStore/'+self.ip_re+"/"+self.ip_re+'-Parameters','w') as PARAMET:
                            PARAMET = PARAMET.write(str("\n".join(listlink)))     
            else:
                with open('./FileStore/'+self.ip_re+"/"+self.ip_re+'-Parameters','w') as PARAMET:
                        PARAMET = PARAMET.write(str("\n".join(listlink))) 

            print("\n[+] Data Save\t\t\t\t\t | : "+path+self.ip_re+'/'+self.ip_re+'-Parameters')                 
if __name__=='__main__':
   UrlParameters()

