#include "stdafx.h"
#include <stdio.h>
#include <mutex>
#include "../mhook/mhook-lib/mhook.h"
#include "../clogger/logger.h"
#include "../inc_cpdk/cardmod.h"


// Global Variables
#define				LOG_PATH		"C:\\Logs\\"
#if 0
#define				APP_HOOKING_W	L"C:\\Yubico\\open_src_my\\SCMiniDriverTest\\x64\\Debug\\SCMiniDriverTest.exe"
#else
#define				APP_HOOKING_W	L"C:\\Windows\\system32\\LogonUI.exe"
#endif
#if 0
#define				DLL_HOOKED_W	L"opensc-minidriver.dll"
#define				DLL_HOOKED		"opensc-minidriver.dll"
#else
#define				DLL_HOOKED_W	L"msclmd.dll"
#define				DLL_HOOKED		"msclmd.dll"
#endif
LOGGER::CLogger*	logger = NULL;
HMODULE				g_hDll = 0;


//initialization of MS Class Mini-driver API function pointers
PFN_CARD_ACQUIRE_CONTEXT	pOrigCardAcquireContext = NULL;


//CardAcquireContext
DWORD WINAPI
CardAcquireContext(
	IN		PCARD_DATA	pCardData,
	__in	DWORD		dwFlags
)
{
	if (logger) {
		logger->TraceInfo("CardAcquireContext");
		logger->TraceInfo("IN dwFlags: %x", dwFlags);
	}
	return pOrigCardAcquireContext(pCardData, dwFlags);
}


//////////////////////////////////////////////////////////////////////////////////////
//
//	Private Helper Functions
//
//////////////////////////////////////////////////////////////////////////////////////

//shouldHook
bool shouldHook() {
	wchar_t	wProcessName[MAX_PATH];
	GetModuleFileName(NULL, wProcessName, MAX_PATH);
	std::wstring wsPN(wProcessName);//convert wchar* to wstring
	std::string strProcessName(wsPN.begin(), wsPN.end());
	if (0 == wcscmp(APP_HOOKING_W, wProcessName)) {
		logger = LOGGER::CLogger::getInstance(LOGGER::LogLevel_Info, LOG_PATH, "");
		if (logger) { logger->TraceInfo("%s is calling %s", strProcessName.c_str(), DLL_HOOKED); }
		return true;
	}
	return false;
}


//hookInitialize
void hookInitialize() {
	g_hDll = LoadLibrary(DLL_HOOKED_W);

	//GetProcAddress
	pOrigCardAcquireContext = (PFN_CARD_ACQUIRE_CONTEXT)GetProcAddress(g_hDll, "CardAcquireContext");

	//Mhook_SetHook
	//Mhook_SetHook((PVOID*)&pOrigCardAcquireContext, pHookCardAcquireContext);
}


//hookFinalize
void hookFinalize() {
	//Mhook_Unhook
	//Mhook_Unhook((PVOID*)&pOrigCardAcquireContext);

	pOrigCardAcquireContext = NULL;
}


//DllMain
BOOL WINAPI DllMain(
	__in HINSTANCE  hInstance,
	__in DWORD      Reason,
	__in LPVOID     Reserved
)
{
	switch (Reason) {
	case DLL_PROCESS_ATTACH:
		if (shouldHook()) {
			hookInitialize();
		} else {
			return FALSE;
		}
		break;

	case DLL_PROCESS_DETACH:
		hookFinalize();
		break;
	}
	return TRUE;
}