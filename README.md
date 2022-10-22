# LFI_Hunter
still under processing 
# PlainHash
PlanHash tool help to carck the password Hash by using wordlist passwords 
genterate hash for ecth passowrd and campare it with oranale password 
suppot crypto hash 
* PlainHash written by python 3.9.1

## info 
* plainHash script help to  crack hash by using wordlist
* PlainHash use Secure hashes and message digests 'hashlib'
* PlainHash use for salt hash 'crypt' 

##  Hash Support : 
* MD4
* MD5  - SHA_1 - SHA_256
* SHA3_384 - BLAKE2c - SHA_3_512
* SHA_512  - BLAKE2b - BLAKE2b 
* SHA3_224 - SHA3_224  - SHA_3_256
### Salt Hash Support:
* MD5-CRYPT  - BCRYPT-[Y]
* SHA1-CRYPT - SHA256-CRYPT 
* SHA512-CRYPT  - bcrypt-2y
* yescrypt - Version: yescrypt 1.1.0 
## Note :
*  pip install pycryptodome 
* python3 disable MD4 HASh so ' pip install pycryptodome' To can crack MD4 hash
### Windows-Hash
* Windows-NTLM-V1 MD4 Encode[UTF-16LE]
### Hash Message Authentication Code "HMAC" : 
 
* HMAC-MD5       - HMAC-SHA1  
* HMAC-SHA_224   - HMAC-SHA3_224
* HMAC-SHA_256   - HMAC-SHA3_256
* HMAC-SHA_384   - HMAC-SHA3_384   
* HMAC-SHA_512   - HMAC-SHA3_512
* HMAC-BLAKE2b   - HMAC-BLAKE2s


## How to use :
* git clone https://github.com/jac11/PlainHash
* cd PlainHash/
* chmod +x PlainHash.py
* to check all  option open help menu by typing ./PlainHash.py -h or --help
* you can use input hash Example: ./PlainHash.py -H dfd5f9139a820075df69d7895015360b76d0360f3d4b77a845689614 -w wordlist
* or you can use as file input ./PlainHash.py -r hash.txt -w wordlist
* use ./PlainHash.py  -i info  or ./PlainHash.py  --info info for more information
* to set color of the PlaimHash off use --color off or -c off    Example: ./PlainHash.py -H dfd5f9139a820075df69d7895015360b76d0360f3d4b77a845689614 -w wordlist -c off
* or you can use as file input ./PlainHash.py -r hash.txt -w wordlist
##  [ help menu overview ] 
 <img src = "images/5.png"><img src = "images/8.png"><img src = "images/9.png" >
  

### ScreenShot
 <img src = "images/2.gif" width=400> <img src = "images/7.gif" width=400>  <img src = "images/3.png" width=400> 
  
### [for Connect]
* administrator@jacstory.tech
* thank you 
