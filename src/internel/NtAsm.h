#pragma once
#include "stdafx.h"

namespace MemX {
	#define EMIT(a) __asm __emit (a)

	constexpr BYTE backup_env[] = {
		0x55,                                                        // push rbp
		0x48, 0x89, 0xE5,                                            // mov rbp, rsp
		0x53,                                                        // push rbx
		0x56,                                                        // push rsi
		0x57,                                                        // push rdi
		0x41, 0x54,                                                  // push r12
	};
	constexpr BYTE restore_env[] = {
		0x48, 0x8D, 0x65, 0xE0,                                      // lea rsp,[ rbp - 32 ]
		0x41, 0x5C,                                                  // pop r12
		0x5F,                                                        // pop rdi
		0x5E,                                                        // pop rsi
		0x5B,                                                        // pop rbx
		0x5D,                                                        // pop rbp
		0xC3                                                         // ret
	};

	constexpr BYTE backup_env_x86[] = {
		0x55,                                                        // push ebp
		0x53,                                                        // push ebx
		0x56,                                                        // push esi
		0x57                                                         // push edi
	};

	constexpr BYTE restore_env_x86[] = {
		0x5F,                                                        // pop edi
		0x5E,                                                        // pop esi
		0x5B,                                                        // pop ebx
		0x5D,                                                        // pop ebp
		0xC3                                                         // ret
	};

	BYTE prepare_env[] = {
		0x48, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rsi, _pParam
		0x49, 0xBC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov r12, _argC
		0x4C, 0x89, 0xE0,                                            // mov rax, r12
		0x49, 0x83, 0xFC, 0x04,                                      // cmp r12, 4
		0x7F, 0x07,                                                  // jg +7
		0x48, 0xC7, 0xC0, 0x04, 0x00, 0x00, 0x00,                    // mov rax, 4
		0x48, 0xC1, 0xE0, 0x03,                                      // shl rax, 3
		0x48, 0x29, 0xC4,                                            // sub rsp, rax
		0x48, 0x83, 0xE4, 0xF0,                                      // and rsp, 0xFFFFFFF0
		0x48, 0x8B, 0x0E,                                            // mov rcx, [rsi]
		0x48, 0x8B, 0x56, 0x08,                                      // mov rdx, [rsi + 8]
		0x4C, 0x8B, 0x46, 0x10,                                      // mov r8, [rsi + 16]
		0x4C, 0x8B, 0x4E, 0x18,                                      // mov r9, [rsi + 24]
		0x49, 0x83, 0xFC, 0x04,                                      // cmp r12, 4
		0x7E, 0x17,                                                  // jle _ready
		0x49, 0xC7, 0xC3, 0x04, 0x00, 0x00, 0x00,                    // mov r11, 4
		// _loop:
		0x4A, 0x8B, 0x04, 0xDE,                                      // mov rax, [rsi + r11 * 8]
		0x4A, 0x89, 0x04, 0xDC,                                      // mov [rsp + r11 * 8], rax
		0x49, 0xFF, 0xC3,                                            // inc r11
		0x4D, 0x39, 0xE3,                                            // cmp r11, r12
		0x7C, 0xF0                                                   // jl _loop
		// _ready:
	};


	constexpr BYTE jmp_x64[] = {
		0x6A, 0x33,                                                  // push 0x33
		0xE8, 0x00, 0x00, 0x00, 0x00,                                // call $+5
		0x83, 0x04, 0x24, 0x05,                                      // add dword ptr [esp], 5
		0xCB                                                         // retf
	};

	constexpr BYTE jmp_x86[] = {
		0x48, 0x89, 0xC2,                                            // mov rdx, rax
		0x48, 0xC1, 0xEA, 0x20,                                      // shr rdx, 32
		0xE8, 0x00, 0x00, 0x00, 0x00,                                // call $+5              
		0xC7, 0x44, 0x24, 0x04, 0x23, 0x00, 0x00, 0x00,              // mov dword [rsp+4], 0x2
		0x83, 0x04, 0x24, 0x0D,                                      // add dword [rsp], 0x0D 
		0xCB,                                                        // retf 
	};
	// Switch to 64 bit mode
	#define x64_start \
		EMIT(0x6A) EMIT(0x33)                         /* push 0x33             */ \
		EMIT(0xE8) EMIT(0) EMIT(0) EMIT(0) EMIT(0)    /* call $+5              */ \
		EMIT(0x83) EMIT(0x04) EMIT(0x24) EMIT(0x05)   /* add dword [esp], 5    */ \
		EMIT(0xCB)                                    /* retf                  */

	// back to 32 bit mode
	#define x64_end \
		EMIT(0xE8) EMIT(0) EMIT(0) EMIT(0) EMIT(0)                                     /* call $+5              */  \
		EMIT(0xC7) EMIT(0x44) EMIT(0x24) EMIT(0x04) EMIT(0x23) EMIT(0) EMIT(0) EMIT(0) /* mov dword [rsp+4], 0x23*/ \
		EMIT(0x83) EMIT(0x04) EMIT(0x24) EMIT(0x0D)                                    /* add dword [rsp], 0x0D */  \
		EMIT(0xCB)                                                                     /* retf                  */

	#define rex_w EMIT(0x48) __asm

	#define rax  0
	#define rcx  1
	#define rdx  2
	#define rbx  3
	#define rsp  4
	#define rbp  5
	#define rsi  6
	#define rdi  7
	#define r8   8
	#define r9   9
	#define r10  10
	#define r11  11
	#define r12  12
	#define r13  13
	#define r14  14
	#define r15  15

	// push 64 register
	#define x64_push(r) EMIT(0x48 | ((r) >> 3)) EMIT(0x50 | ((r) & 7))

	// pop 64 register
	#define x64_pop(r)  EMIT(0x48 | ((r) >> 3)) EMIT(0x58 | ((r) & 7))

	union Reg64 {
		DWORD64 v;
		DWORD dw[ 2 ];
	};
}