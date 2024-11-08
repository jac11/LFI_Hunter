#!/usr/bin/env python3

import argparse
import mechanize
import ssl
import time
import os 
import sys
import re
ssl._create_default_https_context = ssl._create_unverified_context
print(0000)

class  UrlParameters:
    def __init__(self,**kwargs):
        
        self.Fprint_Print()
        self.URL_separated()
    def Fprint_Print(self,**kwargs):
        print("[+] Mothead             : ................ | : Fuzzing Parameters") 
        print("[+] Parameters url      : ................ | : "+self.args.PARAME)
        try:
            dlink = str(re.search(r'https?://(www\.)?([a-zA-Z0-9]+)(\.[a-zA-Z0-9.-]+)', self.args.PARAME)).split()
            self.ip_re = (dlink[-1][7:-2])
            self.ip_re = self.ip_re[7:]
        except Exception:
            self.ip_re = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',self.args.PARAME)
            self.ip_re = self.ip_re.group()
    def URL_separated(self,**kwargs):
        try:
            if self.args.Cookie  or self.args.config:
                try: 
                    with open(self.args.Cookie,'r') as Cookie:
                        self.args.Cookie = Cookie.read().strip()
                        print("[+] Cookie              : ................ | : "+self.args.Cookie)
                except FileNotFoundError as e :
                    print('\n'+'='*20+"\n[*] ERROR-INFO "+'\n'+'='*30+'\n')
                    print("[*] Error : ",e )
                    print('\n'+'='*10+"\n[*] Solution "+'\n'+'='*14+'\n')
                    print("[*] find the correct Path ")  
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
            print("[+] wordlist            : ................ | : "+self.args.paramslist)
            count = 0 
            listPar = []
            listlink = []
            try: 
                with open (self.args.paramslist,'r')  as paramslist :  
                    paramslist = paramslist.readlines()
            except FileNotFoundError  as e :
                print('\n'+'='*20+"\n[*] ERROR-INFO "+'\n'+'='*30+'\n')
                print("[*] Error : ",e )
                print('\n'+'='*10+"\n[*] Solution "+'\n'+'='*14+'\n')
                print("[*] find the correct Path ")  
                exit()  
            for param in paramslist:
                if '#'in param:
                    pass
                else:                  
                    param = param.replace('\n','')
                    link = f'{partlink0}{param}{partlink1}'
                    print('\n'+'='*20+"\n[*] Test Parameters"+'\n'+'='*30+'\n')
                    print("[+] Parameter           : ................ | : "+param)
                    print("[+] try url             : ................ | : "+link)
                    if count > 0 :
                        print("[+] Parameters Found\t: ................ | : "+str(count))
                        for _ in range(8) :  
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K')
                    else:             
                        for _ in range(7) :
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K') 
                    request = mechanize.Browser()
                    request.set_handle_robots(False)
                    request.set_handle_redirect(False)
                    request.set_handle_refresh(True, max_time=1)
                    request.addheaders = [('User-agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1'),
                    ('Cookie',self.args.Cookie),
                    ] 
                    try:
                        if not self.args.status:
                            try:
                                response = request.open(link)
                                response_code = response.getcode()  
                                count += 1
                                listPar.append(param)
                                listlink.append(response.geturl() + " >> Code 200")
                            except Exception as e:
                                if '302' in str(e):
                                    count += 1
                                    listPar.append(param)
                                    listlink.append(link + " >> Code 302")
                        elif self.args.status:
                            try:
                                response = request.open(link)
                                response_code = response.getcode()  
                                if self.args.status == str(response_code):
                                    count += 1
                                    listPar.append(param)
                                    listlink.append(response.geturl() + " >> Code " + str(response_code))
                            except Exception as e:
                                if self.args.status in str(e):
                                    count += 1
                                    listPar.append(param)
                                    listlink.append(link + " >> " + self.args.status)
                    except KeyboardInterrupt :
                        exit()   
                time.sleep(.02)
        except KeyboardInterrupt : 
            pass  
        if count == 0 :
           sys.stdout.write('\x1b[1A')
           sys.stdout.write('\x1b[2K')   
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

