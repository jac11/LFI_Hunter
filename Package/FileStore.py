#!/usr/bin/env /python

import os
import  base64
import re
import difflib
import sys
class FileManager():

    def __init__(self,):
        self.FileRStore_Write()
    def FileRStore_Write(self,**kwargs):
        if not self.args.read :
            self.args.read = self.url.split('/')[-1].strip()
        if  os.path.exists('./FileStore/'+self.ip_re+'/'+self.args.read):  
            os.remove('./FileStore/'+self.ip_re+'/'+self.args.read)   
        with open('.index.txt','w') as html:
            html.write(str(self.Get_Oregnal_URL).replace("b'",''))     
        if self.args.base64 : 
            import base64 
            with open('.index.txt', 'r') as f:
                file1_lines = f.read().split("\\n")
            with open(".RQData", 'r') as Rqreder:
                file2_lines = Rqreder.read().split("\\n")  
         #   if "<generator object unified_diff" in str(diff):
            diff = difflib.unified_diff(file1_lines, file2_lines, fromfile='index.txt', tofile='.RQData', lineterm='')
            for line in diff:
                matches = re.findall(r'[A-Za-z0-9+/=]{20,}', line) 
                for match in matches:
                    try:
                        decoded_line = base64.b64decode(match).decode('utf-8')
                        with open('./FileStore/' + self.ip_re + '/' + self.args.read, 'a') as file:
                            file.write(decoded_line + '\n')     
                    except Exception as e:
                        print("Error decoding base64 content in match:", e)
            if os.path.exists('.index.txt'):
                os.remove('.index.txt')  
                os.remove('.RQData')               
        elif not self.args.base64  :   

            with open('.index.txt', 'r') as f:
                file1_lines = f.read().split("\\n")
            with open(".RQData", 'r') as Rqreder:
                file2_lines = Rqreder.read().split("\\n")  
            diff = difflib.unified_diff(file1_lines, file2_lines, fromfile='index.txt', tofile='.RQData', lineterm='')
            for line in diff:
                if line.startswith('-'):
                    with open('./FileStore/' + self.ip_re+'/'+self.args.read,'a')as file:
                        if line.startswith('-'):
                           cleaned_content = line[1:]
                           cleaned_content = re.sub(r'<[^>]+>', '', cleaned_content)
                           cleaned_content = re.sub(r'-- index.txt', '',       cleaned_content,flags=re.MULTILINE)
                           cleaned_content = re.sub(r'\s+', ' ', cleaned_content).strip()
                           file.write(cleaned_content+'\n')

            if os.path.exists('.index.txt'):
                os.remove('.index.txt')  
                os.remove('.RQData')   
if __name__=="__main__":
    FileManager()