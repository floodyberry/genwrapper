#ifndef __dll_h__
#define __dll_h__

	#define naked __declspec(naked)
	#define inline __forceinline


	extern FARPROC mProcs[];
	inline naked int call__func1_a__AAEXH_Z() { __asm { jmp dword ptr [ mProcs + 0 * 4 ] } }
	inline naked int call__normal__YAMM_Z() { __asm { jmp dword ptr [ mProcs + 1 * 4 ] } }
	inline naked int call__normal_4() { __asm { jmp dword ptr [ mProcs + 2 * 4 ] } }

#endif // __dll_h__
