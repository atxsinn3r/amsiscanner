# AMSI Scanner

A C/C++ implementation of Microsoft's Antimalware Scan Interface.

# Requirements

Before you compile, there are a couple of things needed, such as the amsi.h header
file, and amsi.lib. This repository includes all that, but in case you are curious
where they can be found, go ahead and download the Windows 10 SDK:

https://developer.microsoft.com/en-us/windows/downloads/windows-10-sdk

And then you will be able to find the header file in this location:

C:\Program Files (x86)\Windows Kits\10\Include\10.0.16299.0\um\amsi.h

The amsi.lib file is shipped in two versions, x64 and x86:

* C:\Program Files (x86)\Windows Kits\10\Lib\10.0.16299.0\um\x86\amsi.lib
* C:\Program Files (x86)\Windows Kits\10\Lib\10.0.16299.0\um\x64\amsi.lib

# Compile

To compile, download Visual Studio (I used VS 2013, because Metasploit uses this
version to compile Meterpreter):

https://www.visualstudio.com/downloads/

Go ahead and open the Developer Command Prompt, and then do this to compile:

```
cl.exe /MT /EHa amsiscanner.cpp
```

And then you will have a amsiscanner.exe.

# Usage

To use this tool, simply provide the file name you wish you scan like this:
amsiscanner.exe C:\Users\bob\Desktop\example.exe

If you don't provide a file name, then amsiscanner.exe will scan an EICAR string
(a special string value that is used to test AV engines, but completely harmless).

# Demonstration

```
C:\Users\sinn3r\Desktop>amsiscanner.exe C:\Users\sinn3r\Desktop\AMSI_Detectables\Win32.VBS.APT34Dropper
Sample size: 9141 bytes
Malware detected: C:\Users\sinn3r\Desktop\AMSI_Detectables\Win32.VBS.APT34Dropper
Risk level = 32768 (File is considered malware)
```