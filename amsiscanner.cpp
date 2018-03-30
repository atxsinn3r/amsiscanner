/*

Author: sinn3r
Email: sinn3r[at]metasploit.com
Twitter: @_sinn3r

This program uses Microsoft's Antimalware Scan Interface to perform a malware scan.

Before you compile, there are a couple of things needed, such as the amsi.h header
file, and amsi.lib. This repository includes all that, but in case you are curious
where they can be found, go ahead and download the Windows 10 SDK:
https://developer.microsoft.com/en-us/windows/downloads/windows-10-sdk

And then you will be able to find the header file in this location:
C:\Program Files (x86)\Windows Kits\10\Include\10.0.16299.0\um\amsi.h

The amsi.lib file is shipped in two versions, x64 and x86:
C:\Program Files (x86)\Windows Kits\10\Lib\10.0.16299.0\um\x86\amsi.lib
C:\Program Files (x86)\Windows Kits\10\Lib\10.0.16299.0\um\x64\amsi.lib

To compile, download Visual Studio (I used VS 2013, because Metasploit uses this
version to compile Meterpreter):
https://www.visualstudio.com/downloads/

Go ahead and open the Developer Command Prompt, and then do this to compile:
cl.exe /MT /EHa amsiscanner.cpp

And then you will have a amsiscanner.exe.

To use this tool, simply provide the file name you wish you scan like this:
amsiscanner.exe C:\Users\bob\Desktop\example.exe

If you don't provide a file name, then amsiscanner.exe will scan an EICAR string
(a special string value that is used to test AV engines, but completely harmless).

DEMO

C:\Users\sinn3r\Desktop>amsiscanner.exe C:\Users\sinn3r\Desktop\AMSI_Detectables\Win32.VBS.APT34Dropper
Sample size: 9141 bytes
Malware detected: C:\Users\sinn3r\Desktop\AMSI_Detectables\Win32.VBS.APT34Dropper
Risk level = 32768 (File is considered malware)
*/

#include <iostream>
#include <Windows.h>
#include "amsi.h"
#pragma comment(lib, "amsi.lib")
#pragma comment(lib, "ole32.lib")
using namespace std;

#define EICAR "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
#define AMSIPROJECTNAME "MyAmsiScanner"
#define AMSIDLL "amsi.dll"

struct ScanResult {
  HRESULT RiskLevel;
  BOOL IsMalware;
};

struct Sample {
  BYTE* data;
  ULONG size;
};

class AmsiUtils {
public:
  LPSTR static GetErrorReason(DWORD errCode) {
    LPSTR reason = nullptr;
    FormatMessageA(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |FORMAT_MESSAGE_IGNORE_INSERTS,
      NULL,
      errCode,
      0,
      (LPSTR) &reason,
      0,
      NULL
    );
    return reason;
  }

  void static GetSampleFile(LPCTSTR fname, struct Sample* sample) {
    HANDLE hFile = CreateFileA(fname, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
      throw std::runtime_error("Invalid file handle");
    }

    DWORD dwFileSize = GetFileSize(hFile, NULL);
    if (dwFileSize == INVALID_FILE_SIZE || dwFileSize == 0) {
      throw std::runtime_error("Failed to get the file size");
    }

    BYTE* buffer = (BYTE*) VirtualAlloc(NULL, dwFileSize, MEM_COMMIT, PAGE_READWRITE);
    if (!buffer) {
      throw std::runtime_error("Failed to allocate memory for file");
    }

    DWORD dwBytesRead;
    if (!ReadFile(hFile, buffer, dwFileSize, &dwBytesRead, NULL)) {
      throw std::runtime_error("Failed to read file");
    }

    CloseHandle(hFile);

    sample->data = (BYTE*) buffer;
    sample->size = dwFileSize;
  }

  /*
  It looks like MSFT doesn't actually use the AMSI result as a risk score, even though it is
  documented to have that possible purpose. Instead, the Windows Defender provider only spits
  out one of these values as the result: clean, detected, blocked by admin, and not detected.
  */
  LPSTR static GetResultDescription(HRESULT score) {
    LPSTR description;
    switch (score) {
      case AMSI_RESULT_CLEAN:
        description = "File is clean";
        break;
      case AMSI_RESULT_NOT_DETECTED:
        description = "No threat detected";
        break;
      case AMSI_RESULT_BLOCKED_BY_ADMIN_START:
        description = "Threat is blocked by the administrator";
        break;
      case AMSI_RESULT_BLOCKED_BY_ADMIN_END:
        description = "Threat is blocked by the administrator";
        break;
      case AMSI_RESULT_DETECTED:
        description = "File is considered malware";
        break;
      default:
        description = "N/A";
        break;
    }

    return description;
  }
};

class AmsiScanner {
public:
  AmsiScanner() {
    HRESULT hResult = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (hResult != S_OK) {
      throw std::runtime_error("COM library failed to initialize");
    }
  }

  ~AmsiScanner() {
    CoUninitialize();
  }

  HRESULT Scan(LPCTSTR fname, BYTE* sample, ULONG sampleSize, struct ScanResult* scanResult) {
    HRESULT hResult = S_OK;
    HAMSICONTEXT amsiContext;
    AMSI_RESULT amsiRes = AMSI_RESULT_DETECTED;
    HAMSISESSION session = nullptr;

    ZeroMemory(&amsiContext, sizeof(amsiContext));
    
    hResult = AmsiInitialize((LPCWSTR) AMSIPROJECTNAME, &amsiContext);
    if (hResult != S_OK) {
      OutputDebugString("AmsiInitialize failed");
      return hResult;
    }

    hResult = AmsiOpenSession(amsiContext, &session);
    if (hResult != S_OK || session == nullptr) {
      OutputDebugString("AmsiOpenSession failed");
      return hResult;
    }

    // For this function to work, the following settings must be enabled:
    // * "Scan all downloaded files and attachments" in Local Group Policy Editor
    // * Real-time protection in Windows Defender Security Center
    //
    // If one of the above is turned off, you will get this error:
    // "Failed to scan with error code 0x80070015. Reason: The device is not ready."
    hResult = AmsiScanBuffer(amsiContext, sample, sampleSize, (LPCWSTR) fname, session, &amsiRes);
    if (hResult != S_OK) {
      OutputDebugString("AmsiScannerBuffer failed");
      cerr << "AmsiScanBuffer failed. Did you disable something for Windows Defender?" << endl;;
      return hResult;
    }

    // According to Microsoft's MSDN documentation:
    // The antimalware provider may return a result between 1 and 32767, inclusive, as an estimated
    // risk level. The larger the result, the riskier it is to continue with the content. These values
    // are provider specific, and may indicate a malware family or ID.
    //
    // Results within the range of AMSI_RESULT_BLOCKED_BY_ADMIN_START and AMSI_RESULT_BLOCKED_BY_ADMIN_END
    // values (inclusive) are officially blocked by the admin specified policy. In these cases, the script
    // in question will be blocked from executing. The range is large to accommodate future additions in
    // functionality.
    //
    // Any return result equal to or larger than 32768 is considered malware, and the content should be blocked.
    // An app should use AmsiResultIsMalware to determine if this is the case.
    scanResult->RiskLevel = amsiRes;
    scanResult->IsMalware = AmsiResultIsMalware(amsiRes);

    AmsiUninitialize(amsiContext);
    CoUninitialize();

    return S_OK;
  }

  static void Start(LPCTSTR fname=NULL) {
    AmsiScanner* scanner = new AmsiScanner();
    struct ScanResult scanResult;
    HRESULT hResult;
    struct Sample sample;

    if (fname) {
      AmsiUtils::GetSampleFile(fname, &sample);
    } else {
      fname = "EICAR";
      sample.data = (BYTE*) EICAR;
      sample.size = strlen(EICAR);
    }

    hResult = scanner->Scan(fname, sample.data, sample.size, &scanResult);
    cout << "Sample size: " << sample.size << " bytes" << endl;
    if (hResult == S_OK) {
      if (scanResult.IsMalware) {
        if (!fname) { fname = "EICAR Sample"; }
        cout << "Malware detected: " << fname << endl;
      }
      cout << "Risk level = " << scanResult.RiskLevel << " (" << AmsiUtils::GetResultDescription(scanResult.RiskLevel) << ")" << endl;
    } else {
      LPSTR errReason = AmsiUtils::GetErrorReason(hResult);
      printf("Failed to scan with error code 0x%x. Reason: %s", hResult, errReason);
    }

    delete(scanner);
  }
};

int main(int args, char** argv[]) {
  if (args != 2) {
    cout << "No sample provided, EICAR string will be used for testing" << endl;
  }

  try {
    AmsiScanner::Start((LPCTSTR) argv[1]);
  } catch(std::runtime_error& ex) {
    cerr << ex.what() << endl;
  }
  return 0;
} 