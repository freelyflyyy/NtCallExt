#pragma once
#include "../ResolverBase.hpp"

namespace NtExt {

    #ifdef _M_IX86
    class Wow64Resolver : public ResolverBase {
        public:
        static Wow64Resolver& GetInstance() {
            static Wow64Resolver instance;
            return instance;
        }
        
        ~Wow64Resolver() = default;

        DWORD64 NTAPI GetSyscallNumber64(DWORD64 hMod, const char* funcName);
        DWORD64 NTAPI GetModuleLdrEntry64(const wchar_t* moduleName);
        DWORD64 NTAPI GetModuleBase64(const wchar_t* moduleName);
        DWORD64 NTAPI GetTeb64();
        DWORD64 NTAPI GetPeb64();
        DWORD64 NTAPI GetNtdll64();
        DWORD64 NTAPI GetKernel64();
        DWORD64 NTAPI LoadLibrary64(const wchar_t* moduleName);

        DWORD64 NTAPI GetLdrGetProcedureAddress64();
        VOID NTAPI memcpy64(VOID* dest, DWORD64 src, SIZE_T sz);
        VOID NTAPI memcpy64(DWORD64 dest, VOID* src, SIZE_T sz);

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
            if ( it != _cache32.end() ) return it->second;
            return 0;
        }
        
        DWORD GetProcAddress32(DWORD hMod, const std::string& funcName) {
            if ( auto addr = IsCached32(funcName) ) return addr;
            if ( hMod == 0 ) return 0;
            DWORD procAddr = _GetProcAddress32(hMod, funcName.c_str());
            if ( procAddr ) {
                std::unique_lock<std::shared_mutex> lock(_mutex32);
                _cache32[ funcName ] = procAddr;
            }
            return procAddr;
        }

        DWORD GetProcAddress32(const std::wstring& moduleName, const std::string& funcName) {
            if ( auto addr = IsCached32(funcName) ) return addr;
            DWORD hMod = GetModuleBase32(moduleName.c_str());
            if ( hMod == 0 ) hMod = LoadLibrary32(moduleName.c_str());
            if ( hMod == 0 ) return 0;
            return GetProcAddress32(hMod, funcName);
        }

        DWORD GetProcAddress32(const std::string& funcName) {
            if ( auto addr = IsCached32(funcName) ) return addr;
            return GetProcAddress32(GetNtdll32(), funcName);
        }

        protected:
        DWORD64 NTAPI _GetProcAddress64(DWORD64 hMod, const char* funcName);
        DWORD NTAPI _GetProcAddress32(DWORD hMod, const char* funcName);

        private:
        Wow64Resolver() = default;

        std::unordered_map<std::string, DWORD> _cache32;
        std::shared_mutex _mutex32;
    };
    #endif
}