#pragma once


#if defined(_WIN64) || defined(__x86_64__) || defined(__amd64__)
    #define _WIN64 1
#elif defined(_M_IX86) || defined(__i386__)
    #define _M_IX86 1
#else
    #error "Unsupported architecture! Only x86 and x64 are supported."
#endif