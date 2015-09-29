
#ifndef _DEBUGGING_H_
#define _DEBUGGING_H_

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#undef WIN32_LEAN_AND_MEAN

class Debugging
{
public:
	typedef void (__stdcall *CleanupFunction)(void* params);

protected:
	static HANDLE ExitOrExceptionCaught;
	static char exeLocation[MAX_PATH];
	static char file[64];

	static CleanupFunction Clean;
	static void* CleanParams;

	static char* GetExceptionString(LPEXCEPTION_POINTERS ep);
	static void OutputStackTrace(LPEXCEPTION_POINTERS ep, char* callingFunction);

	static void CleanupDebugging();
public:
	static void InitialiseDebugging(
		char* filename = "Crash.log",
		bool HandleExceptions = false,
		bool HandleExit = false,
		bool HandleVector = false,
		bool HandleConsole = false,
		CleanupFunction Cleanup = nullptr,
		void* CleanupParams = nullptr
	);

	static void SetCrashFile(const char* filename);

	static LONG WINAPI VectorExceptionFilter(PEXCEPTION_POINTERS p);
	static LONG WINAPI closeOnException(LPEXCEPTION_POINTERS p);
	static BOOL WINAPI ConsoleHandler(DWORD Event);
	static void __cdecl ExitHandler();
};

#endif