#!/usr/bin/env /python

import os
import  base64
import re
import difflib
class FileManager():

    def __init__(self,):
        self.FileRStore_Write()
    def FileRStore_Write(self,**kwargs):
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
            diff = difflib.unified_diff(file1_lines, file2_lines, fromfile='index.txt', tofile='.RQData', lineterm='')
            for line in diff:
                if line.startswith('-'):
                    with open('./FileStore/' +self.ip_re+'/'+self.args.read,'a')as file:
                        cleaned_content = "".join(re.findall('-+[a-zA-Z_]+.\w.+',  line))
                        cleaned_content = re.sub(r'^-', '',              cleaned_content, flags=re.MULTILINE) 
                        cleaned_content = re.sub(r'\\r', '',       cleaned_content,flags=re.MULTILINE)
                        read_data= bytes(cleaned_content.encode())                                                      
                        decoded64 = str(base64.b64decode(read_data.decode())).replace('b','').replace("'",'').split("\\n")
                        for data in decoded64 :
                            file.write(data+'\n')
             
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
                        cleaned_content = re.sub(r'-<br\s*/?>', '', line)
                        cleaned_content = re.sub(r'<!DOCTYPE html>\\r', '',  cleaned_content,flags=re.MULTILINE)
                        cleaned_content = re.sub(r'<br />\\r', '',           cleaned_content,flags=re.MULTILINE)
                        cleaned_content = re.sub(r'--- index.txt', '',       cleaned_content,flags=re.MULTILINE)
                        cleaned_content = re.sub(r'<html>', '',              cleaned_content,flags=re.MULTILINE)
                        cleaned_content = re.sub(r'^-','',                   cleaned_content,flags=re.MULTILINE)
                        cleaned_content = re.sub(r'^-    ', '',              cleaned_content, flags=re.MULTILINE) 
                        cleaned_content = re.sub(r'\\r', '',                 cleaned_content, flags=re.MULTILINE)
                        cleaned_content = cleaned_content.strip() 
                        file.write(cleaned_content+'\n')
           
            if os.path.exists('.index.txt'):
                os.remove('.index.txt')  
                os.remove('.RQData')   
if __name__=="__main__":
    FileManager()