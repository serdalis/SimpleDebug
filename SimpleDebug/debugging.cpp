#include "debugging.h"

#include <DbgHelp.h>
#include <Shlwapi.h>
#include <string>

#pragma comment(lib,"DbgHelp.lib")
#pragma comment(lib,"Shlwapi.lib")

#include <process.h>
#include <cstdlib> /* atexit */
#include <cstdio>

#define EXCEPTION_CASE(code) \
	case code: \
		exceptionString = #code; \
	break;

HANDLE Debugging::ExitOrExceptionCaught;

char Debugging::file[64];
char Debugging::exeLocation[MAX_PATH];

Debugging::CleanupFunction Debugging::Clean;
void* Debugging::CleanParams;

void
Debugging::InitialiseDebugging(
		char* filename,
		bool HandleExceptions,
		bool HandleExit,
		bool HandleVector,
		bool HandleConsole,
		CleanupFunction Cleanup,
		void* CleanupParams
	)
{
	char* PathEnd;

	if(HandleExit)
	{
		atexit(ExitHandler);
	}

	if(HandleExceptions)
	{
		SetUnhandledExceptionFilter(&closeOnException);
	}

	if(HandleVector)
	{
		AddVectoredExceptionHandler(1,VectorExceptionFilter);
	}

	if(HandleConsole)
	{
		SetConsoleCtrlHandler(ConsoleHandler, TRUE);
	}

	HMODULE hm = NULL;

	GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
						"InitialiseDebugging",
						&hm);

	GetModuleFileName(hm, exeLocation, MAX_PATH);
	PathEnd = PathFindFileName(exeLocation);
	*PathEnd = '\0';
	SetCrashFile(filename);

	ExitOrExceptionCaught = CreateEvent(NULL, TRUE, FALSE, NULL);

	Clean = Cleanup;
	CleanParams = CleanupParams;
}

void
Debugging::SetCrashFile(const char* filename)
{
	strncpy(file, filename, 64);
}


char*
Debugging::GetExceptionString(LPEXCEPTION_POINTERS ep)
{
	char* exceptionString;
	switch(ep->ExceptionRecord->ExceptionCode)
	{
		EXCEPTION_CASE(EXCEPTION_ACCESS_VIOLATION);
		EXCEPTION_CASE(EXCEPTION_DATATYPE_MISALIGNMENT);
		EXCEPTION_CASE(EXCEPTION_BREAKPOINT);
		EXCEPTION_CASE(EXCEPTION_SINGLE_STEP);
		EXCEPTION_CASE(EXCEPTION_ARRAY_BOUNDS_EXCEEDED);
		EXCEPTION_CASE(EXCEPTION_FLT_DENORMAL_OPERAND);
		EXCEPTION_CASE(EXCEPTION_FLT_DIVIDE_BY_ZERO);
		EXCEPTION_CASE(EXCEPTION_FLT_INEXACT_RESULT);
		EXCEPTION_CASE(EXCEPTION_FLT_INVALID_OPERATION);
		EXCEPTION_CASE(EXCEPTION_FLT_OVERFLOW);
		EXCEPTION_CASE(EXCEPTION_FLT_STACK_CHECK);
		EXCEPTION_CASE(EXCEPTION_FLT_UNDERFLOW);
		EXCEPTION_CASE(EXCEPTION_INT_DIVIDE_BY_ZERO);
		EXCEPTION_CASE(EXCEPTION_INT_OVERFLOW);
		EXCEPTION_CASE(EXCEPTION_PRIV_INSTRUCTION);
		EXCEPTION_CASE(EXCEPTION_IN_PAGE_ERROR);
		EXCEPTION_CASE(EXCEPTION_ILLEGAL_INSTRUCTION);
		EXCEPTION_CASE(EXCEPTION_NONCONTINUABLE_EXCEPTION);
		EXCEPTION_CASE(EXCEPTION_STACK_OVERFLOW);
		EXCEPTION_CASE(EXCEPTION_INVALID_DISPOSITION);
		EXCEPTION_CASE(EXCEPTION_GUARD_PAGE);
		EXCEPTION_CASE(EXCEPTION_INVALID_HANDLE);
		EXCEPTION_CASE(CONTROL_C_EXIT);

		case 0xE06D7363:
			exceptionString = "C++ exception (using throw)";
		break;

		default:
			exceptionString = "Unknown exception";
		break;
	}
	return exceptionString;
}


void
Debugging::OutputStackTrace(LPEXCEPTION_POINTERS ep, char* callingFunction)
{
	int i = 0;
	DWORD machine_type;

	HANDLE hProcess;
	HANDLE hThread;

	LPVOID ContextRecord = NULL;

	PREAD_PROCESS_MEMORY_ROUTINE ReadMemoryRoutine = NULL;
	PFUNCTION_TABLE_ACCESS_ROUTINE FunctionTableAccessRoutine = &SymFunctionTableAccess;
	PGET_MODULE_BASE_ROUTINE GetModuleBaseRoutine = &SymGetModuleBase;
	PTRANSLATE_ADDRESS_ROUTINE TranslateAddress = NULL;

	char* format_string;
	char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(CHAR)];
	PSYMBOL_INFO symbolInfo = (PSYMBOL_INFO)buffer;

	IMAGEHLP_LINE lineInfo;
	DWORD64 symDisplacement = 0;
	DWORD lineDisplacement = 0;

	BOOL symbols = FALSE;

	hProcess = GetCurrentProcess();
	hThread = GetCurrentThread();

#if defined(_WIN64)
	STACKFRAME64 frame = {0};
	machine_type = IMAGE_FILE_MACHINE_AMD64;
	format_string = "Stack=%016X Frame=%016X PC=%016X Return=%016X\n";
	frame.AddrStack.Offset  = ep->ContextRecord->Rsp;
	frame.AddrFrame.Offset  = ep->ContextRecord->Rbp;
	frame.AddrPC.Offset     = ep->ContextRecord->Rip;
	frame.AddrReturn.Offset = 0;
#elif defined(WIN32)
	STACKFRAME frame = {0};
	machine_type = IMAGE_FILE_MACHINE_I386;
	format_string = "Stack=%08X Frame=%08X PC=%08X Return=%08X\n";
	frame.AddrStack.Offset  = ep->ContextRecord->Esp;
	frame.AddrFrame.Offset  = ep->ContextRecord->Ebp;
	frame.AddrPC.Offset     = ep->ContextRecord->Eip;
	frame.AddrReturn.Offset = 0;
#endif
	frame.AddrPC.Mode = AddrModeFlat;
	frame.AddrStack.Mode = AddrModeFlat;
	frame.AddrFrame.Mode = AddrModeFlat;

	FILE* hFile;
	if(fopen_s(&hFile, file, "wb") != 0)
	{
		std::string new_loc(exeLocation);
		new_loc.append(file);
		fopen_s(&hFile, new_loc.c_str(), "wb");
		fprintf(hFile, "Original File Location Failed: %s\n", file);
	}
	fprintf(hFile, "%s\n", GetExceptionString(ep));
	fprintf(hFile, "exePath: %s\n", exeLocation);

	/*-- get the symbols from the pdb file --*/
	SymSetOptions(SYMOPT_UNDNAME | 
                    SYMOPT_DEFERRED_LOADS | 
                    SYMOPT_INCLUDE_32BIT_MODULES);
                    
	symbols = SymInitialize(hProcess, exeLocation, TRUE);
	while(StackWalk(
			machine_type,
			hProcess, 
			hThread,
			&frame,
			ContextRecord,
			ReadMemoryRoutine,
			FunctionTableAccessRoutine,
			GetModuleBaseRoutine,
			TranslateAddress
		))
	{
		if(frame.AddrFrame.Offset == 0) { break; }

		if(symbols)
		{
			memset(&buffer,0,sizeof(buffer));
			memset(&lineInfo, 0, sizeof(IMAGEHLP_LINE));

			symbolInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
			symbolInfo->MaxNameLen = MAX_SYM_NAME;

			symDisplacement = 0;
			lineDisplacement = 0;

			SymFromAddr(hProcess, frame.AddrPC.Offset, &symDisplacement, symbolInfo);
			SymGetLineFromAddr(hProcess, frame.AddrPC.Offset, &lineDisplacement, &lineInfo);

			fprintf(hFile, "-----------------------------------------\n");
			fprintf(
				hFile,
				"Stack=%08X Frame=%08X PC=%08X Return=%08X\n",
				frame.AddrStack.Offset,
				frame.AddrFrame.Offset,
				frame.AddrPC.Offset,
				frame.AddrReturn.Offset
			);
			fprintf(
				hFile, 
				"Trace %d\n::File: %s\n::Function: %s\n::Line: %d\n",
				++i,
				lineInfo.FileName,
				symbolInfo->Name,
				lineInfo.LineNumber
			);
		}
		else
		{
			fprintf(hFile, "-----------------------------------------\n");
			fprintf(
				hFile,
				"Stack=%08X Frame=%08X PC=%08X Return=%08X\n",
				frame.AddrStack.Offset,
				frame.AddrFrame.Offset,
				frame.AddrPC.Offset,
				frame.AddrReturn.Offset
			);
		}
	}

	fclose(hFile);
	SymCleanup(hProcess);
}


LONG WINAPI
Debugging::VectorExceptionFilter(PEXCEPTION_POINTERS p)
{
	if(WaitForSingleObject(ExitOrExceptionCaught, 0) == WAIT_TIMEOUT)
	{
		SetEvent(ExitOrExceptionCaught);
		if(Clean)
		{
			Clean(CleanParams);
		}
		OutputStackTrace(p, "VectorExceptionFilter");
		CleanupDebugging();
	}
	return EXCEPTION_CONTINUE_SEARCH;
}


LONG WINAPI
Debugging::closeOnException(LPEXCEPTION_POINTERS p)
{
	if(WaitForSingleObject(ExitOrExceptionCaught, 0) == WAIT_TIMEOUT)
	{
		SetEvent(ExitOrExceptionCaught);
		if(Clean)
		{
			Clean(CleanParams);
		}
		OutputStackTrace(p, "closeOnException");
		CleanupDebugging();
	}
	return EXCEPTION_EXECUTE_HANDLER;
}


BOOL WINAPI
Debugging::ConsoleHandler(DWORD Event)
{
	if(WaitForSingleObject(ExitOrExceptionCaught, 0) == WAIT_TIMEOUT)
	{
		SetEvent(ExitOrExceptionCaught);
		if(Clean)
		{
			Clean(CleanParams);
		}
		CleanupDebugging();
	}
	return 0;
}


void __cdecl
Debugging::ExitHandler()
{
	if(WaitForSingleObject(ExitOrExceptionCaught, 0) == WAIT_TIMEOUT)
	{
		SetEvent(ExitOrExceptionCaught);
		if(Clean)
		{
			Clean(CleanParams);
		}
		CleanupDebugging();
	}
}


void
Debugging::CleanupDebugging()
{
	CloseHandle(ExitOrExceptionCaught);
}