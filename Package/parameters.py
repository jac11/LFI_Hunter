#!/usr/bin/env python3

import argparse
import mechanize
import ssl
import time
ssl._create_default_https_context = ssl._create_unverified_context


class  UrlParameters:
   
    def URL_separated(self,**kwargs):
        if self.args.Cookie  or self.args.config:
            with open(self.args.Cookie,'r') as Cookie:
                self.args.Cookie = Cookie.read().strip()
        self.url = self.args.PARAME
        print(self.url)
        if "PARAME" in self.url:
            partlink0,partlink1 = self.url.split("PARAME")
        if not self.args.paramslist :
            self.args.paramslist = "./Package/parames.txt" 
        else:  
             pass      
        with open (self.args.paramslist,'r')  as paramslist :
            paramslist = paramslist.readlines()
        for param in paramslist:
            param = param.replace('\n','')
            link = f'{partlink0}{param}{partlink1}'
            request = mechanize.Browser()
            request.set_handle_robots(False)
            request.set_handle_redirect(False)
            request.set_handle_refresh(True, max_time=1)
            request.addheaders = [('User-agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1'),
            ('Cookie',self.args.Cookie),
            ] 
            try:
               response = request.open(link)
               print(response.geturl())
            except Exception as e :
               pass
            time.sleep(.02)
if __name__=='__main__':
   UrlParameters()
