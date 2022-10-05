#!/usr/bin/env python3

import argparse
import sys

from Package.main_lfi import Local_File_In
from Package.aggressiv import Aggressiv
class Hannter_LFI:
           
       def __init__(self):
         self.control()
         if self.args.aggress:
             run =Aggressiv()
         else:    
             run = Local_File_In()
       def control(self): 
           parser = argparse.ArgumentParser(description="Usage: [OPtion] [arguments] [ -w ] [arguments]") 
           parser.add_argument("-UV ","--Vulnurl"     , action=None         ,required=True     ,help ="url Targst web") 
           parser.add_argument("--auth"               , action='store_true'                    ,help ="url Targst web") 
           parser.add_argument("-F","--filelist"      , action=None                            ,help ="read fron lfi wordlsit ")
           parser.add_argument("-C","--Cookie"        , action=None                            ,help ="Login sesion Cookie")  
           parser.add_argument("-B64","--base64"      , action='store_true'                    ,help ="Login sesion base64")  
           parser.add_argument("-R","--read"          , action=None                            ,help ="Login sesion base64")  
           parser.add_argument("-UF ","--UserForm"    , action=None                            ,help =" add name of the HTML Form Login User")
           parser.add_argument("-PF ","--PassForm"    , action=None                            ,help ="add name of the HTML Form Login Passord")
           parser.add_argument("-P  ","--password"    , action=None                            ,help ="use specific Passowrd")   
           parser.add_argument("-LU  ","--loginurl"   , action=None                            ,help ="use specific Passowrd") 
           parser.add_argument("-U  ","--user"        , action=None                            ,help ="use specific username ")
           parser.add_argument("-A","--aggress"     ,action='store_true'                    ,help ="use specific username ")
           self.args = parser.parse_args()     
           if len(sys.argv)!=1 :
              pass
           else:
              parser.print_help()         
              exit()                   
if __name__=='__main__':
    Hannter_LFI()

