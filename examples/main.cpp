#include <iostream>
#include <NtExt.hpp>

using namespace NtExt;

int main() {
    DWORD64 ntdll64 = Resolver.GetNtdll64();
    if (ntdll64 == 0) {
        std::cout << "[!] Failed: Cannot find 64-bit ntdll." << std::endl;
        return -1;
    }

    DWORD64 pRtlGetVersion = Resolver.GetProcAddress64(ntdll64, "RtlGetVersion");
    if (pRtlGetVersion == 0) {
        std::cout << "[!] Failed: Cannot find 64-bit RtlGetVersion." << std::endl;
        return -1;
    }

    alignas(8) BYTE osvi[300] = { 0 };
    *(DWORD*)osvi = 284; 

    NTSTATUS status = Call(pRtlGetVersion)((DWORD64)&osvi);

    if (status == 0) {
        DWORD major = *(DWORD*)(osvi + 4);
        DWORD minor = *(DWORD*)(osvi + 8);
        DWORD build = *(DWORD*)(osvi + 12);
        
        std::cout << "[+] Heaven's Gate is open!" << std::endl;
        std::cout << "    OS Version: " << major << "." << minor << "." << build << std::endl;
    } else {
        std::cout << "[-] Call executed, but returned error status: 0x" << std::hex << status << std::endl;
    }

    return 0;
}