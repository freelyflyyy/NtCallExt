#pragma once
#include "NtCallExt.h"

namespace MemX {
    class Wow64NtCallExt : public NtCallExt {
        public:
        ~Wow64NtCallExt() override = default;
        DWORD64 NTAPI GetProcAddress64(DWORD64 hMod, const char* funcName) override;
        DWORD64 NTAPI GetSyscallNumber64(DWORD64 hMod, const char* funcName) override;
        DWORD64 NTAPI GetModuleLdrEntry64(const wchar_t* moduleName) override;
        DWORD64 NTAPI GetModuleBase64(const wchar_t* moduleName) override;
        DWORD64 NTAPI GetTeb64() override;
        DWORD64 NTAPI GetPeb64() override;
        DWORD64 NTAPI GetNtdll64() override;
        DWORD64 NTAPI GetKernel64() override;
        DWORD64 NTAPI LoadLibrary64(const wchar_t* moduleName) override;

        DWORD64 NTAPI GetLdrGetProcedureAddress();
        DWORD64 __cdecl X64CallVa(DWORD64 funcAddr, int argCount, ...);
		DWORD64 __cdecl X64SysCallVa(const WORD& ssn, int argCount, ...);
        VOID NTAPI memcpy64(VOID* dest, DWORD64 src, SIZE_T sz);
        VOID NTAPI memcpy64(DWORD64 dest, VOID* src, SIZE_T sz);

        template<typename... Args>
        NTSTATUS X64Call(const DWORD64& funcAddr, Args&&... args) {
            if ( !funcAddr ) return ERROR_INVALID_ADDRESS;
            return (NTSTATUS) X64CallVa((DWORD64) funcAddr, (int) sizeof...(Args), (DWORD64) std::forward<Args>(args)...);
        }

        template<typename... Args>
        NTSTATUS X64SysCall(const WORD& ssn, Args&&...args) {
            if ( !ssn ) return STATUS_INVALID_PARAMETER;
			return (NTSTATUS) X64SysCallVa(ssn, (int) sizeof...(Args), (DWORD64) std::forward<Args>(args)...);
        }

        // 32bit native functions
        DWORD NTAPI GetProcAddress32(DWORD hMod, const char* funcName);
        DWORD NTAPI GetModuleBase32(const wchar_t* moduleName);
        DWORD NTAPI GetTeb32();
        DWORD NTAPI GetPeb32();
        DWORD NTAPI GetNtdll32();
        DWORD NTAPI GetKernel32();
        DWORD NTAPI GetLdrGetProcedureAddress32();
        DWORD NTAPI LoadLibrary32(const wchar_t* moduleName);

        DWORD IsCached32(const std::string& funcName) {
            std::shared_lock<std::shared_mutex> lock(_mutex32);
            auto it = _cache32.find(funcName);
            if ( it != _cache32.end() ) {
                return it->second;
            }
            return 0;
        }

        DWORD GetFunc32(DWORD hMod, const std::string& funcName) {
            if ( auto addr = IsCached32(funcName) ) return addr;
            if ( hMod == 0 ) return 0;
            DWORD procAddr = GetProcAddress32(hMod, funcName.c_str());
            if ( procAddr ) {
                std::unique_lock<std::shared_mutex> lock(_mutex32);
                _cache32[ funcName ] = procAddr;
            }
            return procAddr;
        }

        DWORD GetFunc32(const std::wstring& moduleName, const std::string& funcName) {
            if ( auto addr = IsCached32(funcName) ) return addr;
            DWORD hMod = GetModuleBase32(moduleName.c_str());
            if ( hMod == 0 ) hMod = LoadLibrary32(moduleName.c_str());
            if ( hMod == 0 ) return 0;
            return GetFunc32(hMod, funcName);
        }

        DWORD GetFunc32(const std::string& funcName) {
            if ( auto addr = IsCached32(funcName) ) return addr;
            return GetFunc32(GetNtdll32(), funcName);
        }

        private:
        std::unordered_map<std::string, DWORD> _cache32;
        std::shared_mutex _mutex32;
    };
}