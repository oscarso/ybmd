#include "stdafx.h"
#include <stdio.h>
#include <mutex>
#include "../clogger/logger.h"
#include "../inc_cpdk/cardmod.h"


// Global Variables
#define				LOG_PATH		"C:\\Logs\\"
LOGGER::CLogger*	logger = NULL;
HMODULE				g_hDll = 0;


//CardAcquireContext
DWORD WINAPI
CardAcquireContext(
	IN		PCARD_DATA	pCardData,
	__in	DWORD		dwFlags
)
{
	DWORD	dwRet = NO_ERROR;
	if (logger) {
		logger->TraceInfo("CardAcquireContext");
		logger->TraceInfo("IN dwFlags: %x", dwFlags);
		logger->TraceInfo("IN pCardData->dwVersion: %d", pCardData->dwVersion);
		logger->TraceInfo("IN pCardData->pbAtr:");
		logger->PrintBuffer(pCardData->pbAtr, pCardData->cbAtr);
		logger->TraceInfo("IN pCardData->pwszCardName:");
		logger->PrintBuffer(pCardData->pwszCardName, lstrlen(pCardData->pwszCardName));
		logger->TraceInfo("IN pCardData->pfnCspAlloc: %p", &(pCardData->pfnCspAlloc));
		logger->TraceInfo("IN pCardData->pfnCspReAlloc: %p", &(pCardData->pfnCspReAlloc));
		logger->TraceInfo("IN pCardData->pfnCspFree: %p", &(pCardData->pfnCspFree));
		logger->TraceInfo("IN pCardData->pfnCspCacheAddFile: %p", &(pCardData->pfnCspCacheAddFile));
		logger->TraceInfo("IN pCardData->pfnCspCacheLookupFile: %p", &(pCardData->pfnCspCacheLookupFile));
		logger->TraceInfo("IN pCardData->pfnCspCacheDeleteFile: %p", &(pCardData->pfnCspCacheDeleteFile));
		logger->TraceInfo("IN pCardData->pvCacheContext: %x", pCardData->pvCacheContext);
		logger->TraceInfo("IN pCardData->pfnCspPadData: %p", &(pCardData->pfnCspPadData));
		logger->TraceInfo("IN pCardData->hSCardCtx: %x", pCardData->hSCardCtx);
		logger->TraceInfo("IN pCardData->hScard: %x", pCardData->hScard);
	}

	//pCardData->pfnCardDeleteContext = CardDeleteContext;
	//pCardData->pfnCardAuthenticatePin = CardAuthenticatePin;
	//pCardData->pfnCardChangeAuthenticator = CardChangeAuthenticator;

	return dwRet;
}


#if 0
//CardDeleteContext
DWORD WINAPI
CardDeleteContext(
	__inout		PCARD_DATA	pCardData
)
{
	if (logger) {
		logger->TraceInfo("CardDeleteContext");
	}
	return pOrigCardDeleteContext(pCardData);
}


//CardAuthenticatePin
DWORD WINAPI
CardAuthenticatePin(
	__in					PCARD_DATA	pCardData,
	__in					LPWSTR		pwszUserId,
	__in_bcount(cbPin)		PBYTE		pbPin,
	__in					DWORD		cbPin,
	__out_opt				PDWORD		pcAttemptsRemaining
)
{
	if (logger) {
		logger->TraceInfo("CardAuthenticatePin");
	}
	return pOrigCardAuthenticatePin(
				pCardData,
				pwszUserId,
				pbPin,
				cbPin,
				pcAttemptsRemaining
				);
}


//CardChangeAuthenticator
DWORD WINAPI
CardChangeAuthenticator(
	__in									PCARD_DATA	pCardData,
	__in									LPWSTR		pwszUserId,
	__in_bcount(cbCurrentAuthenticator)		PBYTE		pbCurrentAuthenticator,
	__in									DWORD		cbCurrentAuthenticator,
	__in_bcount(cbNewAuthenticator)			PBYTE		pbNewAuthenticator,
	__in									DWORD		cbNewAuthenticator,
	__in									DWORD		cRetryCount,
	__in									DWORD		dwFlags,
	__out_opt								PDWORD		pcAttemptsRemaining
)
{
	if (logger) {
		logger->TraceInfo("CardChangeAuthenticator");
	}
	return pOrigCardChangeAuthenticator(
				pCardData,
				pwszUserId,
				pbCurrentAuthenticator,
				cbCurrentAuthenticator,
				pbNewAuthenticator,
				cbNewAuthenticator,
				cRetryCount,
				dwFlags,
				pcAttemptsRemaining
				);
}
#endif


//////////////////////////////////////////////////////////////////////////////////////
//
//	Private Helper Functions
//
//////////////////////////////////////////////////////////////////////////////////////

//DllMain
BOOL WINAPI DllMain(
	__in HINSTANCE  hInstance,
	__in DWORD      Reason,
	__in LPVOID     Reserved
)
{
	switch (Reason) {
	case DLL_PROCESS_ATTACH:
		break;

	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}