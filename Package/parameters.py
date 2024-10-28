#!/usr/bin/env python3

import argparse
import mechanize
import ssl
import time
import sys
ssl._create_default_https_context = ssl._create_unverified_context


class  UrlParameters:
    def __init__(self,**kwargs):
        self.Fprint_Print()
        self.URL_separated()
    def Fprint_Print(self,**kwargs):
        print("[+] Mothead             : ................ | : Fuzzing Parameters") 
        print("[+] Parameters url      : ................ | : "+self.args.PARAME)
    def URL_separated(self,**kwargs):
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
        with open (self.args.paramslist,'r')  as paramslist :
            paramslist = paramslist.readlines()
        for param in paramslist:
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
                response = request.open(link)
                count +=1
              
                listPar.append(param)
                listlink.append(response.geturl())
            except Exception as e :
               pass
            time.sleep(.02)
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
 
if __name__=='__main__':
   UrlParameters()