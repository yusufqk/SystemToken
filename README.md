# SystemToken

This code will iterate over all processes on a system until it reaches a process with
the following traits:

* The user for that process is SYSTEM
* The owner for that process is Administrators

Once a process is found with these two traits, the token for that process is duplicated and
a new process with that token is created. This will result in a SYSTEM shell. 

## System Requirements

This code was tested on a Windows 10 x64 machine using Visual Studio 2019.  
Must be run with UAC bypassed and Local Admin privileges.

## Usage

Compile and run SystemToken.exe

## References

This work is based on the research done by [Justin Bui from SpecterOps](https://posts.specterops.io/understanding-and-defending-against-access-token-theft-finding-alternatives-to-winlogon-exe-80696c8a73b)  
https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens<br/>
Windows API exploitation at PentesterAcademy (amazing course, learned alot). The EnablePriv.h file used to enable privileges (no longer provided and never used by this tool) is a modified version from the course.
