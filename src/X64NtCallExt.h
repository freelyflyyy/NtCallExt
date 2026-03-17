#pragma once
#include "NtCallExt.h"

namespace MemX {
    class X64NtCallExt : public NtCallExt {
        public:
        ~X64NtCallExt() override = default;

        DWORD64 NTAPI GetProcAddress64(DWORD64 hMod, const char* funcName) override;
        DWORD64 NTAPI GetSyscallNumber64(DWORD64 hMod, const char* funcName) override;
        DWORD64 NTAPI GetModuleLdrEntry64(const wchar_t* moduleName) override;
        DWORD64 NTAPI GetModuleBase64(const wchar_t* moduleName) override;
        DWORD64 NTAPI GetTeb64() override;
        DWORD64 NTAPI GetPeb64() override;
        DWORD64 NTAPI GetNtdll64() override;
        DWORD64 NTAPI GetKernel64() override;
        DWORD64 NTAPI LoadLibrary64(const wchar_t* moduleName) override;

        template<typename... Args>
        NTSTATUS X64Call(const DWORD64& funcAddr, Args&&... args) {
            if ( !funcAddr ) {
                return ERROR_INVALID_ADDRESS;
            }
            return ((NTSTATUS(NTAPI*)(Args...))funcAddr)(std::forward<Args>(args)...);
        }
    };
}