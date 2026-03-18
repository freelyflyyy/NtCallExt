#include <iostream>
#include <Wow64NtCallExt.h>

using namespace MemX;
int main() {
    printf("[+] 启动 Heavens Gate + Hells Gate 测试...\n");

    Wow64NtCallExt nt;
    DWORD64 ntdll64 = nt.GetNtdll64();
    if ( !ntdll64 ) {
        printf("[-] 无法定位 64 位 ntdll\n");
        return -1;
    }

    WORD ssnTerminate = nt.GetSyscallNumber64(ntdll64, "NtTerminateProcess");

    if ( ssnTerminate == 0 ) {
        printf("[-] 无法提取 SSN，可能函数被 Hook 或扫描失败\n");
        return -1;
    }

    printf("[+] 成功获取 SSN: 0x%X\n", ssnTerminate);
    printf("[!] 即将通过 Heavens Gate 执行 Direct Syscall 结束进程...\n");

    nt.X64SysCallVa(ssnTerminate, 2, (DWORD64) -1, (DWORD64) 123);

    printf("[-] 测试失败：程序未退出。\n");
}