#!/usr/bin/env python 
'''
import time
import sys
import mechanize
import ssl
import urllib
import re
import os
import  base64
import difflib
with open("./Package/shell/.response.txt",'r') as f:
        file1_lines = f.read().split("\\n")
with open("./Package/shell/.response2.txt",'r') as Rqreder:
    file2_lines = Rqreder.read().split("\\n")  
DataList = []
diff = difflib.unified_diff(file1_lines, file2_lines, fromfile='.repones2.txt', tofile='.repones1.txt', lineterm='')
for line in diff:
    if line.startswith('+') and not line.startswith('+++') and not line.startswith('++'):  
        cleaned_content= line[1:]
        cleaned_text = re.sub(r'\w.+\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b..+\s.+\d\D\d\S.+','' , cleaned_content)
        cleaned_content = re.sub(r"^\w+.+\d:\d.+:\s+\w...........",'', cleaned_content)
        cleaned_content = re.sub(r'\+\s+', '', cleaned_content)
       # cleaned_text = re.sub(r"\(uid=0\)",'' , cleaned_content)
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

print("web_response  : "+ DataList[0].replace('\n','').replace('(',''))
for l in DataList[1:] :
   print("\t\t"+l.replace('\n','').replace('(',''))           
if os.path.exists ("./Package/shell/.data")  :
   os.remove("./Package/shell/.data")

'''
import mechanize
import threading

class YourClass:
    def __init__(self, vulnurl, url):
        self.args = type("Args", (object,), {"Vulnurl": vulnurl})
        self.url = url

    def fetch_with_timeout(self, timeout=10.0):
        try:
            timer = threading.Timer(timeout, self.raise_timeout)
            timer.start()

            # First request
            first_req = mechanize.Browser().open(self.args.Vulnurl).read()
            print("First request completed.")

            # Second request
            self.Get_Oregnal_URL = mechanize.Browser().open(self.url).read()
            print("Second request completed.")

        except TimeoutError:
            print("Request timed out!")
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            timer.cancel()

    def raise_timeout(self):
        raise TimeoutError("Operation timed out.")

# Example usage
vulnurl = "http://example.com/vuln"
url = "http://example.com"
obj = YourClass( "http://83.136.254.158:34442/index.php?page=","http://83.136.254.158:34442/index.php?page=")
obj.fetch_with_timeout(timeout=10.0)
