#include "stdafx.h"
#include <stdio.h>
#include <mutex>
#include "../clogger/logger.h"
#include "../inc_cpdk/cardmod.h"


// Global Variables
#define	LOG_PATH			"C:\\Logs\\"
LOGGER::CLogger*			logger = NULL;
HMODULE						g_hDll = 0;
PFN_CARD_ACQUIRE_CONTEXT	pOrigCardAcquireContext;


//Initialize
void Initialize() {
	g_hDll = LoadLibrary(L"msclmd.dll");

	//GetProcAddress
	pOrigCardAcquireContext = (PFN_CARD_ACQUIRE_CONTEXT)GetProcAddress(g_hDll, "CardAcquireContext");
}


//Finalize
void Finalize() {
	g_hDll = NULL;
}


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

#if 0
	dwRet = pOrigCardAcquireContext(pCardData, dwFlags);
#else
	pCardData->pfnCardAuthenticateChallenge = NULL;//pOrigCardData->pfnCardAuthenticateChallenge;
	pCardData->pfnCardAuthenticateEx = NULL;//pOrigCardData->pfnCardAuthenticateEx;
	pCardData->pfnCardAuthenticatePin = NULL;//CardAuthenticatePin;
	pCardData->pfnCardChangeAuthenticator = NULL;//CardChangeAuthenticator;
	pCardData->pfnCardChangeAuthenticatorEx = NULL;//pOrigCardData->pfnCardChangeAuthenticatorEx;
	pCardData->pfnCardConstructDHAgreement = NULL;//pOrigCardData->pfnCardConstructDHAgreement;
	pCardData->pfnCardCreateContainer = NULL;//pOrigCardData->pfnCardCreateContainer;
	pCardData->pfnCardCreateDirectory = NULL;//pOrigCardData->pfnCardCreateDirectory;
	pCardData->pfnCardCreateFile = NULL;//pOrigCardData->pfnCardCreateFile;
	pCardData->pfnCardDeauthenticate = NULL;//pOrigCardData->pfnCardDeauthenticate;
	pCardData->pfnCardDeauthenticateEx = NULL;//pOrigCardData->pfnCardDeauthenticateEx;
	pCardData->pfnCardDeleteContainer = NULL;//pOrigCardData->pfnCardDeleteContainer;
	pCardData->pfnCardDeleteContext = NULL;//CardDeleteContext;
	pCardData->pfnCardDeleteDirectory = NULL;//pOrigCardData->pfnCardDeleteDirectory;
	pCardData->pfnCardDeleteFile = NULL;//pOrigCardData->pfnCardDeleteFile;
	pCardData->pfnCardDeriveKey = NULL;//pOrigCardData->pfnCardDeriveKey;
	pCardData->pfnCardDestroyDHAgreement = NULL;//pOrigCardData->pfnCardDestroyDHAgreement;
	pCardData->pfnCardEnumFiles = NULL;//pOrigCardData->pfnCardEnumFiles;
	pCardData->pfnCardGetChallenge = NULL;//pOrigCardData->pfnCardGetChallenge;
	pCardData->pfnCardGetChallengeEx = NULL;//pOrigCardData->pfnCardGetChallengeEx;
	pCardData->pfnCardGetContainerInfo = NULL;//pOrigCardData->pfnCardGetContainerInfo;
	pCardData->pfnCardGetContainerProperty = NULL;//pOrigCardData->pfnCardGetContainerProperty;
	pCardData->pfnCardGetFileInfo = NULL;//pOrigCardData->pfnCardGetFileInfo;
	pCardData->pfnCardGetProperty = NULL;//pOrigCardData->pfnCardGetProperty;
	pCardData->pfnCardQueryCapabilities = CardQueryCapabilities;
	pCardData->pfnCardQueryFreeSpace = NULL;//pOrigCardData->pfnCardQueryFreeSpace;
	pCardData->pfnCardQueryKeySizes = NULL;//pOrigCardData->pfnCardQueryKeySizes;
	pCardData->pfnCardReadFile = NULL;//pOrigCardData->pfnCardReadFile;
	pCardData->pfnCardRSADecrypt = NULL;//pOrigCardData->pfnCardRSADecrypt;
	pCardData->pfnCardSetContainerProperty = NULL;//pOrigCardData->pfnCardSetContainerProperty;
	pCardData->pfnCardSetProperty = NULL;//pOrigCardData->pfnCardSetProperty;
	pCardData->pfnCardSignData = NULL;//pOrigCardData->pfnCardSignData;
	pCardData->pfnCardUnblockPin = NULL;//pOrigCardData->pfnCardUnblockPin;
	pCardData->pfnCardWriteFile = NULL;//pOrigCardData->pfnCardWriteFile;
	pCardData->pvUnused3 = NULL;
	pCardData->pvUnused4 = NULL;
	pCardData->pvVendorSpecific = NULL;
#endif

	return dwRet;
}


//CardQueryCapabilities
DWORD WINAPI
CardQueryCapabilities(
	__in      PCARD_DATA          pCardData,
	__in      PCARD_CAPABILITIES  pCardCapabilities
)
{
	DWORD	dwRet = NO_ERROR;
	if (logger) {
		logger->TraceInfo("CardQueryCapabilities");
	}

	return dwRet;
}


//CardDeleteContext
DWORD WINAPI
CardDeleteContext(
	__inout		PCARD_DATA	pCardData
)
{
	DWORD	dwRet = NO_ERROR;
	if (logger) {
		logger->TraceInfo("CardDeleteContext");
	}

	return dwRet;
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
	DWORD	dwRet = NO_ERROR;
	if (logger) {
		logger->TraceInfo("CardAuthenticatePin");
	}

	return dwRet;
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
	DWORD	dwRet = NO_ERROR;
	if (logger) {
		logger->TraceInfo("CardChangeAuthenticator");
	}

	return dwRet;
}


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
			logger = LOGGER::CLogger::getInstance(LOGGER::LogLevel_Info, LOG_PATH, "");
			if (logger) {
				logger->TraceInfo("DllMain");
			}
			Initialize();
		break;

		case DLL_PROCESS_DETACH:
			Finalize();
		break;
	}
	return TRUE;
}