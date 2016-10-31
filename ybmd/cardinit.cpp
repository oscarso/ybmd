#include "stdafx.h"
#include <VersionHelpers.h>

#include "../inc/cpdk/cardmod.h"
#include <ykpiv/ykpiv.h>
#include <internal.h>

#include "../cpplogger/cpplogger.h"
#include "helper.h"


extern	CPPLOGGER::CPPLogger*	logger;

const unsigned int		MAX_SPEC_VERSION_SUPPORTED = 7;
OSVERSIONINFO			g_osver;


//CardAcquireContext
DWORD WINAPI
CardAcquireContext(
	IN		PCARD_DATA	pCardData,
	__in	DWORD		dwFlags
)
{
	ykpiv_state	ykState;
	DWORD		dwRet = SCARD_S_SUCCESS;

	if (logger) {
		logger->TraceInfo("\n");
		logger->TraceInfo("#####   CardAcquireContext   #####");
		logger->TraceInfo("##################################");
		logger->TraceInfo("IN dwFlags: %x", dwFlags);
		logger->TraceInfo("IN pCardData->dwVersion: %d", pCardData->dwVersion);
		logger->TraceInfo("IN pCardData->pbAtr:");
		logger->PrintBuffer(pCardData->pbAtr, pCardData->cbAtr);
		char cardName[MAX_PATH] = { 0 };
		wcstombs(cardName, pCardData->pwszCardName, wcslen(pCardData->pwszCardName));
		logger->TraceInfo("IN pCardData->pwszCardName: %s", cardName);
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

	pCardData->pfnCardDeleteContext = CardDeleteContext;//
	pCardData->pfnCardQueryCapabilities = CardQueryCapabilities;//
	pCardData->pfnCardDeleteContainer = CardDeleteContainer;//
	pCardData->pfnCardCreateContainer = CardCreateContainer;//
	pCardData->pfnCardGetContainerInfo = CardGetContainerInfo;//
	pCardData->pfnCardAuthenticatePin = CardAuthenticatePin;//
	pCardData->pfnCardGetChallenge = CardGetChallenge;//
	pCardData->pfnCardAuthenticateChallenge = CardAuthenticateChallenge;//
	pCardData->pfnCardUnblockPin = CardUnblockPin;//
	pCardData->pfnCardChangeAuthenticator = CardChangeAuthenticator;//
	pCardData->pfnCardDeauthenticate = NULL;
	pCardData->pfnCardCreateDirectory = CardCreateDirectory;//
	pCardData->pfnCardDeleteDirectory = CardDeleteDirectory;//
	pCardData->pvUnused3 = NULL;//
	pCardData->pvUnused4 = NULL;//
	pCardData->pfnCardCreateFile = CardCreateFile;//
	pCardData->pfnCardReadFile = CardReadFile;//
	pCardData->pfnCardWriteFile = CardWriteFile;//
	pCardData->pfnCardDeleteFile = CardDeleteFile;//
	pCardData->pfnCardEnumFiles = CardEnumFiles;//
	pCardData->pfnCardGetFileInfo = CardGetFileInfo;//
	pCardData->pfnCardQueryFreeSpace = CardQueryFreeSpace;//
	pCardData->pfnCardQueryKeySizes = CardQueryKeySizes;//
	pCardData->pfnCardSignData = CardSignData;//
	pCardData->pfnCardRSADecrypt = CardRSADecrypt;//
	pCardData->pfnCardConstructDHAgreement = NULL;//CardConstructDHAgreement;

	if (pCardData->dwVersion != 0) {
		if (NULL == pCardData->pbAtr)
			return SCARD_E_INVALID_PARAMETER;

		if (NULL == pCardData->pwszCardName) {
			if (logger) { logger->TraceInfo("[%s:%d][MD] Invalid pCardData->pwszCardName", __FUNCTION__, __LINE__); }
			return SCARD_E_INVALID_PARAMETER;
		}
		if (NULL == pCardData->pfnCspAlloc) {
			if (logger) { logger->TraceInfo("[%s:%d][MD] Invalid pCardData->pfnCspAlloc", __FUNCTION__, __LINE__); }
			return SCARD_E_INVALID_PARAMETER;
		}
		if (NULL == pCardData->pfnCspReAlloc) {
			if (logger) { logger->TraceInfo("[%s:%d][MD] Invalid pCardData->pfnCspReAlloc", __FUNCTION__, __LINE__); }
			return SCARD_E_INVALID_PARAMETER;
		}
		if (NULL == pCardData->pfnCspFree) {
			if (logger) { logger->TraceInfo("[%s:%d][MD] Invalid pCardData->pfnCspFree", __FUNCTION__, __LINE__); }
			return SCARD_E_INVALID_PARAMETER;
		}
		if (SCARD_S_SUCCESS != SCardIsValidContext(pCardData->hSCardCtx)) {
			if (logger) { logger->TraceInfo("CardAcquireContext failed - SCardIsValidContext(%x) fails", pCardData->hSCardCtx); }
			return SCARD_E_INVALID_PARAMETER;
		}
		if (0 == pCardData->hScard) {
			if (logger) { logger->TraceInfo("CardAcquireContext failed - pCardData->hScard = NULL"); }
			return SCARD_E_INVALID_PARAMETER;
		}

		memset(&ykState, 0, sizeof(ykpiv_state));
		ykState.verbose = TRUE;
		ykState.context = pCardData->hSCardCtx;
		ykState.card = pCardData->hScard;

		if (logger) {
			logger->TraceInfo("CardAcquireContext:             ykState.context = %x", ykState.context);
			logger->TraceInfo("CardAcquireContext:                ykState.card = %x", ykState.card);
			logger->TraceInfo("CardAcquireContext: pCardData->pvVendorSpecific = %p", pCardData->pvVendorSpecific);
		}

		if (shouldSelectApplet(&ykState)) {
			ykpiv_rc ykrc = selectApplet(&ykState);
			if (ykrc != YKPIV_OK) { logger->TraceInfo("CardAcquireContext: selectApplet failed. ykrc=%d", ykrc); }
		}
	}

	if (MAX_SPEC_VERSION_SUPPORTED < pCardData->dwVersion)
		pCardData->dwVersion = MAX_SPEC_VERSION_SUPPORTED;

	if (pCardData->dwVersion > 4) {
		pCardData->pfnCardDeriveKey = NULL;
		pCardData->pfnCardDestroyDHAgreement = NULL;
		pCardData->pfnCspGetDHAgreement = NULL;

		if (pCardData->dwVersion > 5 && IsWindowsVistaOrGreater() && MAX_SPEC_VERSION_SUPPORTED >= 6) {
			logger->TraceInfo("[%s:%d][MD] Reporting version 6 on Windows version %i.%i build %i. Max supported spec version is set to %i", __FUNCTION__, __LINE__, g_osver.dwMajorVersion, g_osver.dwMinorVersion, g_osver.dwBuildNumber, MAX_SPEC_VERSION_SUPPORTED);
#if 0
			pCardData->pfnCardGetChallengeEx = CardGetChallengeEx;
			pCardData->pfnCardAuthenticateEx = CardAuthenticateEx;
			pCardData->pfnCardChangeAuthenticatorEx = CardChangeAuthenticatorEx;
			pCardData->pfnCardDeauthenticateEx = CardDeauthenticateEx;
			pCardData->pfnCardGetContainerProperty = CardGetContainerProperty;
			pCardData->pfnCardSetContainerProperty = CardSetContainerProperty;
			pCardData->pfnCardGetProperty = CardGetProperty;
			pCardData->pfnCardSetProperty = CardSetProperty;
#endif
		}
		else {
			logger->TraceInfo("[%s:%d][MD] Version 6 is not supported on Windows version %i.%i build %i. Max supported spec version is set to %i", __FUNCTION__, __LINE__, g_osver.dwMajorVersion, g_osver.dwMinorVersion, g_osver.dwBuildNumber, MAX_SPEC_VERSION_SUPPORTED);
		}

		if (pCardData->dwVersion > 6 && IsWindowsVistaOrGreater() && MAX_SPEC_VERSION_SUPPORTED >= 7) {
			logger->TraceInfo("[%s:%d][MD] Reporting version 7 on Windows version %i.%i build %i. Max supported spec version is set to %i", __FUNCTION__, __LINE__, g_osver.dwMajorVersion, g_osver.dwMinorVersion, g_osver.dwBuildNumber, MAX_SPEC_VERSION_SUPPORTED);
#if 0
			pCardData->pfnCardDestroyKey = CardDestroyKey;
			pCardData->pfnCardGetAlgorithmProperty = CardGetAlgorithmProperty;
			pCardData->pfnCardGetKeyProperty = CardGetKeyProperty;
			pCardData->pfnCardGetSharedKeyHandle = CardGetSharedKeyHandle;
			//pCardData->pfnCardProcessEncryptedData = CardProcessEncryptedData;
			pCardData->pfnCardSetKeyProperty = CardSetKeyProperty;
			pCardData->pfnCardCreateContainerEx = CardCreateContainerEx;
			//pCardData->pfnMDImportSessionKey = MDImportSessionKey;
			//pCardData->pfnMDEncryptData = MDEncryptData;
			//pCardData->pfnCardImportSessionKey = CardImportSessionKey;
#endif
		}
		else {
			logger->TraceInfo("[%s:%d][MD] Version 7 is not supported on Windows version %i.%i build %i. Max supported spec version is set to %i", __FUNCTION__, __LINE__, g_osver.dwMajorVersion, g_osver.dwMinorVersion, g_osver.dwBuildNumber, MAX_SPEC_VERSION_SUPPORTED);
		}
	}

	logger->TraceInfo("CardAcquireContext returns SCARD_S_SUCCESS");
	return SCARD_S_SUCCESS;
}


//CardDeleteContext
DWORD WINAPI
CardDeleteContext(
	__inout		PCARD_DATA	pCardData
)
{
	ykpiv_state	ykState;

	if (logger) {
		logger->TraceInfo("\n");
		logger->TraceInfo("#####    CardDeleteContext    #####");
		logger->TraceInfo("###################################");
	}

	if (SCARD_S_SUCCESS != SCardIsValidContext(pCardData->hSCardCtx)) {
		if (logger) { logger->TraceInfo("CardDeleteContext failed - SCardIsValidContext(%x) fails", pCardData->hSCardCtx); }
		return SCARD_E_INVALID_PARAMETER;
	}

	ykState.context = pCardData->hSCardCtx;
	ykState.card = pCardData->hScard;

	if (logger) {
		logger->TraceInfo("CardDeleteContext: ykState.context = %x", ykState.context);
		logger->TraceInfo("CardDeleteContext:    ykState.card = %x", ykState.card);
	}

	pCardData->pfnCardDeleteContext = NULL;
	pCardData->pfnCardQueryCapabilities = NULL;
	pCardData->pfnCardDeleteContainer = NULL;
	pCardData->pfnCardCreateContainer = NULL;
	pCardData->pfnCardGetContainerInfo = NULL;
	pCardData->pfnCardAuthenticatePin = NULL;
	pCardData->pfnCardGetChallenge = NULL;
	pCardData->pfnCardAuthenticateChallenge = NULL;
	pCardData->pfnCardUnblockPin = NULL;
	pCardData->pfnCardChangeAuthenticator = NULL;
	pCardData->pfnCardDeauthenticate = NULL;
	pCardData->pfnCardCreateDirectory = NULL;
	pCardData->pfnCardDeleteDirectory = NULL;
	pCardData->pvUnused3 = NULL;
	pCardData->pvUnused4 = NULL;
	pCardData->pfnCardCreateFile = NULL;
	pCardData->pfnCardReadFile = NULL;
	pCardData->pfnCardWriteFile = NULL;
	pCardData->pfnCardDeleteFile = NULL;
	pCardData->pfnCardEnumFiles = NULL;
	pCardData->pfnCardGetFileInfo = NULL;
	pCardData->pfnCardQueryFreeSpace = NULL;
	pCardData->pfnCardQueryKeySizes = NULL;
	pCardData->pfnCardSignData = NULL;
	pCardData->pfnCardRSADecrypt = NULL;
	pCardData->pfnCardConstructDHAgreement = NULL;

	return SCARD_S_SUCCESS;
} // of CardDeleteContext
