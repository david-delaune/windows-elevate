/*
MIT Software License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

/*
	Designed to compile under /W4 /WX (Warning level 4 with warnings as errors)
	with \"All Rules\" code analysis in all versions of Visual Studio >= VS2008
	This code has been tested with Windows 10.0.18362.0 SDK and backwards
	compatible all the way down to the Windows 7.1 SDK on Windows 7
*/

#include <windows.h>
#include <DbgHelp.h>
#include <initguid.h>
#include <tlhelp32.h>
#include <Psapi.h>
#include <userenv.h>
#include <lmcons.h>
#include <stdio.h>
#include <tchar.h>
#include <winerror.h>

#pragma comment(lib, "userenv.lib")

#define MODE_SYSTEM 2
#define MODE_TRUSTED_INSTALLER 4
#define MAX_ARGUMENTS 8

#if defined (_MSC_VER) && (_MSC_VER > 1600)
	#ifndef _DEBUG
		#define NOEXCEPT noexcept
	#else
		#define NOEXCEPT
	#endif
#else
	#define NOEXCEPT
#endif

#if defined (_SAL_VERSION) && (_SAL_VERSION < 20) || !defined(_SAL_VERSION)
	#define _Must_inspect_result_
	#define _Pre_satisfies_(x)
	#define NULL_POINTER 0
#else
	#define NULL_POINTER nullptr
#endif

_Ret_range_(FALSE, TRUE)
_Must_inspect_result_
BOOL AreWeLocalSystem() NOEXCEPT
{
	PTOKEN_USER pTokenUser = NULL_POINTER;
	BOOL bLocalSystem = FALSE;
	DWORD dwNeeded = 0;
	HANDLE hToken = NULL_POINTER;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		GetTokenInformation(hToken, TokenUser, NULL_POINTER, 0, &dwNeeded);
		if (dwNeeded && ERROR_INSUFFICIENT_BUFFER == GetLastError())
		{
			pTokenUser = static_cast<TOKEN_USER *>(LocalAlloc(LPTR, dwNeeded));
			if (pTokenUser && GetTokenInformation(hToken, TokenUser, pTokenUser, dwNeeded, &dwNeeded))
			{
				dwNeeded = SECURITY_MAX_SID_SIZE;
				PSID pLocalSID = LocalAlloc(LPTR, dwNeeded);

				if (pLocalSID)
				{
					if (TRUE == CreateWellKnownSid(WinLocalSystemSid, NULL_POINTER, pLocalSID, &dwNeeded))
					{
						bLocalSystem = EqualPrefixSid(pTokenUser->User.Sid, pLocalSID);
					}

					LocalFree(pLocalSID);
					pLocalSID = NULL_POINTER;
				}
			}

			LocalFree(pTokenUser);
			pTokenUser = NULL_POINTER;
		}

		CloseHandle(hToken);
	}
	return bLocalSystem;
}

_Must_inspect_result_
DWORD CreateProcessWithToken(_In_ HANDLE h, _In_z_ LPCWSTR lpCurrentdirectory, _In_z_ LPWSTR lpCommandline) NOEXCEPT
{
	STARTUPINFO si = {0};
	PROCESS_INFORMATION pi = { NULL_POINTER };
	LPVOID environment_block = NULL_POINTER;

	SecureZeroMemory(&si, sizeof(si));
	SecureZeroMemory(&pi, sizeof(pi));

	si.lpDesktop = L"winsta0\\default";
	si.cb = sizeof(si);

	DWORD id = WTSGetActiveConsoleSessionId();
	if (!SetTokenInformation(h, TokenSessionId, &id, sizeof(DWORD)))
	{
		wprintf(L"SetTokenInformation failed to set active session: %lx\n", GetLastError());
		return 0;
	}

	if (CreateEnvironmentBlock(&environment_block, h, TRUE))
	{
		if (!CreateProcessWithTokenW(h, 0, NULL_POINTER, lpCommandline, CREATE_NEW_CONSOLE | CREATE_DEFAULT_ERROR_MODE | CREATE_UNICODE_ENVIRONMENT | NORMAL_PRIORITY_CLASS, environment_block, lpCurrentdirectory, &si, &pi))
		{
			wprintf(L"CreateProcessWithTokenW failed to create process: %lx\n", GetLastError());
			if (!CreateProcessAsUserW(h, NULL_POINTER, lpCommandline, NULL_POINTER, NULL_POINTER, FALSE, CREATE_NEW_CONSOLE | CREATE_DEFAULT_ERROR_MODE | CREATE_UNICODE_ENVIRONMENT | NORMAL_PRIORITY_CLASS, environment_block, lpCurrentdirectory, &si, &pi))
			{
				wprintf(L"CreateProcessAsUserW failed to create process: %lx\n", GetLastError());
			}
		}
		else
		{
			::CloseHandle(pi.hThread);
			::CloseHandle(pi.hProcess);
		}

		DestroyEnvironmentBlock(environment_block);
	}
	else
	{
		wprintf(L"Failed to create environment block.\n");
	}

	return GetLastError();
}

_Success_(return  != FALSE)
_Pre_satisfies_(privilege_name != NULL)
_Ret_range_(FALSE,TRUE)
_Must_inspect_result_
BOOL GainPrivilege(_In_z_ LPCWSTR privilege_name) NOEXCEPT
{
	HANDLE h = INVALID_HANDLE_VALUE;
	BOOL bRet = FALSE;
	LUID luid = {0};
	TOKEN_PRIVILEGES tp = {0};

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &h))
	{
		if (LookupPrivilegeValueW(NULL_POINTER, privilege_name, &luid))
		{
			tp.PrivilegeCount = 1;
			tp.Privileges[0].Luid = luid;
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			if (AdjustTokenPrivileges(h, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), FALSE, FALSE))
			{
				bRet = TRUE;
			}
		}

		CloseHandle(h);
	}

	return bRet;
}

_Pre_satisfies_(name != NULL)
_Ret_range_(>= , 0)
_Must_inspect_result_
DWORD GetProcessPID(_In_z_ LPCWSTR name)
{
	DWORD dwProcessID = 0;
	PROCESSENTRY32W pe = {0};
	HANDLE h;

	h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (h)
	{
		pe.dwSize = sizeof(pe);
		if (Process32First(h, &pe))
		{
			do
			{
				if (wcsstr(&pe.szExeFile[0], name) != NULL_POINTER)
				{
					dwProcessID = pe.th32ProcessID;
					break;
				}
			} while (Process32Next(h, &pe) != FALSE);
		}

		CloseHandle(h);
	}

	return dwProcessID;
}

_Success_(return  != FALSE)
_Ret_range_(FALSE, TRUE)
_Must_inspect_result_
BOOL StartTrustedInstaller() NOEXCEPT
{
	BOOL bRet = FALSE;
	DWORD dwOriginalStartType = 0;
	QUERY_SERVICE_CONFIGW configuration = {0};
	static LPQUERY_SERVICE_CONFIGW lpBuffer = NULL_POINTER; //static works around broken C26486 code analysis warning on strict "Microsoft All Rules" on (_SAL_VERSION < 20)
	SC_HANDLE hManager = OpenSCManagerW(NULL_POINTER, NULL_POINTER, SC_MANAGER_CONNECT);

	if (hManager)
	{
		const SC_HANDLE hService = OpenServiceW(hManager, L"TrustedInstaller", SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG | SERVICE_START);
		if (hService)
		{
			DWORD dwBytesNeeded = 0;
			if (QueryServiceConfigW(hService, lpBuffer, 0, &dwBytesNeeded) == FALSE)
			{
				if (dwBytesNeeded && ERROR_INSUFFICIENT_BUFFER == GetLastError())
				{
					lpBuffer = static_cast <LPQUERY_SERVICE_CONFIGW> (LocalAlloc(LPTR, dwBytesNeeded));
					if (QueryServiceConfigW(hService, lpBuffer, dwBytesNeeded, &dwBytesNeeded))
					{
						dwOriginalStartType = configuration.dwStartType;

						ChangeServiceConfigW(hService, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_NO_CHANGE, NULL_POINTER, NULL_POINTER, NULL_POINTER, NULL_POINTER, NULL_POINTER, NULL_POINTER, NULL_POINTER);
						bRet = StartServiceW(hService, 0, NULL_POINTER);
						ChangeServiceConfigW(hService, SERVICE_NO_CHANGE, dwOriginalStartType, SERVICE_NO_CHANGE, NULL_POINTER, NULL_POINTER, NULL_POINTER, NULL_POINTER, NULL_POINTER, NULL_POINTER, NULL_POINTER);

						if (!bRet)
						{
							bRet = (ERROR_SERVICE_ALREADY_RUNNING == GetLastError());
						}

						LocalFree(lpBuffer);
						CloseServiceHandle(hService);
						CloseServiceHandle(hManager);
					}
				}
			}
		}
	}

	return bRet;
}

INT usage(void) NOEXCEPT
{
	fwprintf(stderr, L"usage: elevate [ options ]\n");
	fwprintf(stderr, L"\t -t (elevate to Trusted Installer)\n");
	fwprintf(stderr, L"\t -s (elevate to System)\n");
	return ERROR_BAD_ARGUMENTS;
}

_Pre_satisfies_(arg != NULL)
_Ret_range_(0, MODE_TRUSTED_INSTALLER)
_Must_inspect_result_
INT argument_to_flag(_In_z_ const LPCWSTR arg) NOEXCEPT
{
	INT flag = 0;
	if (!_wcsicmp(arg, L"-s"))
	{
		flag = MODE_SYSTEM;
	}
	else if (!_wcsicmp(arg, L"-t"))
	{
		flag = MODE_TRUSTED_INSTALLER;
	}
	return flag;
}

_Pre_satisfies_(argv != NULL)
_Ret_range_(0, MODE_TRUSTED_INSTALLER)
_Must_inspect_result_
INT process_commandline(_In_ INT argc, _In_ const LPCWSTR *argv) NOEXCEPT
{
	INT flag = 0;
	INT index = 0;
	LPCWSTR arguments[MAX_ARGUMENTS] = { NULL_POINTER,NULL_POINTER,NULL_POINTER,NULL_POINTER,NULL_POINTER,NULL_POINTER,NULL_POINTER,NULL_POINTER };

	if (argv && argc < MAX_ARGUMENTS)
	{
		memcpy(&arguments[0], argv, argc * sizeof(LPCWSTR));
		do
		{
			switch (index)
			{
				case 1:
				if (arguments[1] != NULL_POINTER)
				{
					flag += argument_to_flag(arguments[1]);
					break;
				}
				case 2:
				if (arguments[2] != NULL_POINTER)
				{
					flag += argument_to_flag(arguments[2]);
					break;
				}
			}
			index++;
		} while (index < argc);
	}
	return flag;
}

INT main()
{
	WCHAR process_name[MAX_PATH] = {0};
	WCHAR szPath[MAX_PATH] = {0};
	WCHAR szExe[MAX_PATH] = {0};
	HANDLE impersonation_token = NULL_POINTER;
	HANDLE elevated_token = NULL_POINTER;
	HANDLE process_handle = NULL_POINTER;
	HANDLE process_token = NULL_POINTER;
	DWORD process_pid = 0;
	DWORD error_code = 0;
	BOOL success = FALSE;
	INT flag = 0;
	INT argc = 0;

	const LPCWSTR *argv = CommandLineToArgvW(GetCommandLine(), &argc);

	flag = process_commandline(argc, argv);
	if (!flag)
	{
		return usage();
	}

	if (flag & MODE_TRUSTED_INSTALLER)
	{
		if (!AreWeLocalSystem())
		{
			wprintf(L"Elevate to system before attempting to elevate to Trusted Installer.\n");
			return ERROR_ACCESS_DENIED;
		}
		else
		{
			success = StartTrustedInstaller();
			if (!success)
			{
				error_code = GetLastError();
				wprintf(L"Failed to start the Trusted Installer service.\n");
				return error_code;
			}
		}
	}

	if (flag & MODE_SYSTEM)
		wcscpy_s(&process_name[0], MAX_PATH, L"winlogon.exe");
	else
		wcscpy_s(&process_name[0], MAX_PATH, L"TrustedInstaller.exe");

	process_pid = GetProcessPID(&process_name[0]);

	if (process_pid == 0)
	{
		error_code = GetLastError();
		wprintf(L"Failed to find the %s process: %lx\n", &process_name[0], GetLastError());
		return error_code;
	}

	if (GainPrivilege(SE_DEBUG_NAME) == 0)
	{
		error_code = GetLastError();
		wprintf(L"Failed to gain debug privilege: %lx\n", error_code);
		return error_code;
	}

	if (GainPrivilege(SE_IMPERSONATE_NAME) == 0)
	{
		error_code = GetLastError();
		wprintf(L"Failed to gain impersonate privilege: %lx\n", error_code);
		return error_code;
	}

	if (GainPrivilege(SE_ASSIGNPRIMARYTOKEN_NAME) == 0)
	{
		error_code = GetLastError();
		wprintf(L"Failed to gain token assignment privilege: %lx\n", error_code);
		return error_code;
	}

	if (GainPrivilege(SE_INCREASE_QUOTA_NAME) == 0)
	{
		error_code = GetLastError();
		wprintf(L"Failed to gain increase quota privilege: %lx\n", error_code);
		return error_code;
	}

	process_handle = OpenProcess(MAXIMUM_ALLOWED, FALSE, process_pid);
	if (process_handle == NULL_POINTER)
	{
		error_code = GetLastError();
		wprintf(L"Failed to open handle to %s process: %lx\n", &process_name[0], error_code);
		return error_code;
	}

	success = OpenProcessToken(process_handle, TOKEN_DUPLICATE | TOKEN_QUERY, &process_token);
	if (success == 0)
	{
		error_code = GetLastError();
		wprintf(L"Failed to open %s process token: %lx\n", &process_name[0], error_code);
		return error_code;
	}

	success = DuplicateToken(process_token, SecurityImpersonation, &impersonation_token);
	if (success == 0)
	{
		error_code = GetLastError();
		wprintf(L"DuplicateToken failed to duplicate %s process token: %lx\n", &process_name[0], error_code);
		return error_code;
	}

	success = SetThreadToken(NULL_POINTER, impersonation_token);
	if (success == 0)
	{
		error_code = GetLastError();
		wprintf(L"Failed to impersonate %s: %lx\n", &process_name[0], error_code);
		return error_code;
	}

	success = DuplicateTokenEx(process_token, TOKEN_ALL_ACCESS, NULL_POINTER, SecurityIdentification, TokenPrimary, &elevated_token);
	if (success == 0)
	{
		error_code = GetLastError();
		wprintf(L"DuplicateTokenEx failed to duplicate %s process token: %lx\n", &process_name[0], error_code);
		return error_code;
	}

	if (GetSystemDirectoryW(&szPath[0], MAX_PATH))
	{
		wcscat_s(&szExe[0], MAX_PATH, &szPath[0]);
		wcscat_s(&szExe[0], MAX_PATH, L"\\cmd.exe");

		success = CreateProcessWithToken(elevated_token, &szPath[0], &szExe[0]);
	}

	CloseHandle(process_token);
	CloseHandle(process_handle);
	CloseHandle(elevated_token);
	CloseHandle(impersonation_token);

	return success;
}
