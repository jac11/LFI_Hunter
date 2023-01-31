#!/usr/bin/env python3

import argparse
import sys

from Package.main_lfi import Local_File_In
from Package.aggressiv import Aggressiv
with open('./Package/Banner','r') as banner:
     print(banner.read())
class Hannter_LFI:
      
       def __init__(self):
         self.control()
         if self.args.aggress:
             run =Aggressiv()
         else:    
             run = Local_File_In()       
       def control(self): 
         try: 
           parser = argparse.ArgumentParser(description="Usage: [OPtion] [arguments] [ -w ] [arguments]")             
           parser.add_argument("-UV","--Vulnurl"    , action=None         ,required=False      ,help ="url Targst web") 
           parser.add_argument("--auth"             , action='store_true'                    ,help ="auth mautrd web") 
           parser.add_argument("-F","--filelist"    , action=None                            ,help ="read fron lfi wordlsit ")
           parser.add_argument("-C","--Cookie"      , action=None        ,required=True      ,help ="Login sesion Cookie")  
           parser.add_argument("-B","--base64"      , action='store_true'                    ,help ="decode filter php  base64")  
           parser.add_argument("-R","--read"        , action=None                            ,help ="use to read file on the traget machine")  
           parser.add_argument("-UF","--UserForm"   , action=None                            ,help =" add name of the HTML Form Login User")
           parser.add_argument("-PF","--PassForm"   , action=None                            ,help ="add name of the HTML Form Login Passord")
           parser.add_argument("-P","--password"    , action=None                            ,help ="use specific Passowrd")   
           parser.add_argument("-LU","--loginurl"   , action=None                            ,help =" add login url for auth motted") 
           parser.add_argument("-U","--user"        , action=None                            ,help ="use specific username ")
           parser.add_argument("-A","--aggress"     ,action='store_true'                     ,help ="  use aggressiv mode  ")
           parser.add_argument("--port"             ,action=None                             ,help ="  set port for netcat ")
           parser.add_argument("-D","--Domain"      ,action=None                             ,help ="  use target url domain not as ip 'http://www.anyDomain.com'")
           parser.add_argument("-S","--shell"       , action=None                            ,help ="  to connent reverseshell   ")
           self.args = parser.parse_args()     
           if len(sys.argv)!=1 :
              pass
           else:
              parser.print_help()         
              exit()
         except AssertionError as a :
            print('\n'+'='*20+"\n[*] ERROR-INFO "+'\n'+'='*30+'\n')
            print("[*] Error :  Bad argument" )
            print('\n'+'='*10+"\n[*] Solution "+'\n'+'='*14+'\n')
            print("[*] try to use --help")
            print("[*] ckeck Readme file at : https://www.github/jac11/LFI_Hunter.git")
            exit()
            
            exit()                
if __name__=='__main__':
    Hannter_LFI()

