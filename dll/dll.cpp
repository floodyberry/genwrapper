#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>
#include "dll.h"

#pragma comment(linker, "/export:connect=ws2_32.connect,@3")

HINSTANCE mHinst, mHinstDLL;
FARPROC mProcs[3];

LPCSTR mImportNames[] = {
	"?func1@a@@AAEXH@Z", "?normal@@YAMM@Z", "_normal@4", 
};

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved ) {
	mHinst = hinstDLL;
	if ( fdwReason == DLL_PROCESS_ATTACH ) {
		char sysdir[255], path[255];
		GetSystemDirectory( sysdir, 254 );
		sprintf( path, "%s\\dll.dll", sysdir );
		mHinstDLL = LoadLibrary( path );
		if ( !mHinstDLL )
			return ( FALSE );

		for ( int i = 0; i < 3; i++ )
			mProcs[ i ] = GetProcAddress( mHinstDLL, mImportNames[ i ] );
	} else if ( fdwReason == DLL_PROCESS_DETACH ) {
		FreeLibrary( mHinstDLL );
	}
	return ( TRUE );
}

// private: void __thiscall a::func1(int)
int __stdcall __func1_a__AAEXH_Z() {
	return call__func1_a__AAEXH_Z();
}

// float __cdecl normal(float)
int __stdcall __normal__YAMM_Z() {
	return call__normal__YAMM_Z();
}

// _normal@4
int __stdcall __normal_4() {
	return call__normal_4();
}

naked void __stdcall decorated1() { __asm { jmp __func1_a__AAEXH_Z } }
naked void __stdcall decorated2() { __asm { jmp __normal__YAMM_Z } }
naked void __stdcall decorated4() { __asm { jmp __normal_4 } }
