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
from subprocess import Popen, PIPE, check_output, Popen

ssl._create_default_https_context = ssl._create_unverified_context

class WebShellInteract:

    def Soures_Web(self,**kwargs):
        print('\n'+'='*20+"\n[*] WebShell Interact "+'\n'+'='*30+'\n')
        print("[+] Mothead             : ................ | : WebShell Active ")    
        print("[+] WebShell            : ................ | : <?php system(['cmd']);?>")
        print("[+] file access         : ................ | : "+self.args.read.replace("_",'/'))
        print("[+] Mothead             : ................ | : SSH Interact")   
        from Package.LFT_Shell_connect import Shell_conncet
        Shell_conncet.Connect_SSh_Shell(self ,**kwargs)
        time.sleep(4)
        path   =  "/usr/bin/python3  ./Package/shell/webshell.py" 
        run    = 'gnome-terminal  -- '+path
        xterm  = subprocess.call( run ,shell=True,stderr=subprocess.PIPE) 

    def WebShell(self,**kwargs):
        print('\n'+'='*20+"\n[*] WebShell Interact "+'\n'+'='*30+'\n')
        print("[+] Mothead             : ................ | : WebShell Active ")    
        print("[+] WebShell            : ................ | : <?php system(['cmd']);?>")
        print("[+] file access         : ................ | : "+self.args.read.replace("_",'/'))
            
        path   =  "/usr/bin/python3  ./Package/shell/webshell.py" 
        run    = 'gnome-terminal  -- '+path
        xterm  = subprocess.call( run ,shell=True,stderr=subprocess.PIPE) 
        
           
if __name__=='__main__':
   WebShellInteract()       
