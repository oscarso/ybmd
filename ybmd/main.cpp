#include "stdafx.h"
#include <stdio.h>
#include <mutex>
#include <VersionHelpers.h>

#include "../cpplogger/cpplogger.h"
#include "../inc/cpdk/cardmod.h"
#include <ykpiv/ykpiv.h>
#include <internal.h>


// Global Variables
#define	LOG_PATH			"C:\\Logs\\"
CPPLOGGER::CPPLogger*		logger = NULL;
HMODULE						g_hDll = 0;
OSVERSIONINFO				g_osver;
unsigned int				g_maxSpecVersion = 7;


DWORD	ykrc2mdrc(const ykpiv_rc ykrc) {
	DWORD	dwRet;
	switch (ykrc) {
	case YKPIV_OK:						dwRet = SCARD_S_SUCCESS; break;
	case YKPIV_MEMORY_ERROR:			dwRet = SCARD_E_NO_MEMORY; break;
	case YKPIV_PCSC_ERROR:				dwRet = SCARD_F_INTERNAL_ERROR; break;
	case YKPIV_SIZE_ERROR:				dwRet = SCARD_E_INVALID_PARAMETER; break;
	case YKPIV_APPLET_ERROR:			dwRet = SCARD_F_INTERNAL_ERROR; break;
	case YKPIV_AUTHENTICATION_ERROR:	dwRet = SCARD_W_CARD_NOT_AUTHENTICATED; break;
	case YKPIV_RANDOMNESS_ERROR:		dwRet = SCARD_F_INTERNAL_ERROR; break;
	case YKPIV_GENERIC_ERROR:			dwRet = SCARD_F_INTERNAL_ERROR; break;
	case YKPIV_KEY_ERROR:				dwRet = SCARD_F_INTERNAL_ERROR; break;
	case YKPIV_PARSE_ERROR:				dwRet = SCARD_E_INVALID_PARAMETER; break;
	case YKPIV_WRONG_PIN:				dwRet = SCARD_E_INVALID_CHV; break;
	case YKPIV_INVALID_OBJECT:			dwRet = SCARD_F_INTERNAL_ERROR; break;
	case YKPIV_ALGORITHM_ERROR:			dwRet = SCARD_F_INTERNAL_ERROR; break;
	case YKPIV_PIN_LOCKED:				dwRet = SCARD_W_CHV_BLOCKED; break;
	default:							dwRet = SCARD_F_UNKNOWN_ERROR;
	}
	return dwRet;
}


//CardAcquireContext
DWORD WINAPI
CardAcquireContext(
	IN		PCARD_DATA	pCardData,
	__in	DWORD		dwFlags
)
{
	DWORD	dwRet = SCARD_S_SUCCESS;

	char cardName[MAX_PATH] = { 0 };
	wcstombs(cardName, pCardData->pwszCardName, wcslen(pCardData->pwszCardName));
	if (logger) {
		logger->TraceInfo("CardAcquireContext");
		logger->TraceInfo("IN dwFlags: %x", dwFlags);
		logger->TraceInfo("IN pCardData->dwVersion: %d", pCardData->dwVersion);
		logger->TraceInfo("IN pCardData->pbAtr:");
		logger->PrintBuffer(pCardData->pbAtr, pCardData->cbAtr);
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
		if (0 == pCardData->hScard) {
			if (logger) { logger->TraceInfo("CardAcquireContext failed - pCardData->hScard = NULL"); }
			return SCARD_E_INVALID_HANDLE;
		}

		// call ykpiv library
		ykpiv_state*	ykState;
		ykpiv_rc		ykrc;
		LONG			scrc;
		ykrc = ykpiv_init(&ykState, FALSE);
		scrc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &ykState->context);
		if (SCARD_S_SUCCESS != scrc) {
			if (logger) { logger->TraceInfo("CardAcquireContext: SCardEstablishContext failed - ErrCode=%x", scrc); }
			return SCARD_F_INTERNAL_ERROR;
		}
		// WARNING: NEVER call SCardConnect/SCardReconnect, it will hung up
		ykState->card = pCardData->hScard;
		if (logger) {
			logger->TraceInfo("CardAcquireContext:     ykState->context = %x", ykState->context);
			logger->TraceInfo("CardAcquireContext:        ykState->card = %x", ykState->card);
			logger->TraceInfo("CardAcquireContext: pCardData->hSCardCtx = %x", pCardData->hSCardCtx);
		}
		pCardData->pvVendorSpecific = ykState;
	}

	if (g_maxSpecVersion < pCardData->dwVersion)
		pCardData->dwVersion = g_maxSpecVersion;

	if (pCardData->dwVersion > 4) {
		pCardData->pfnCardDeriveKey = NULL;
		pCardData->pfnCardDestroyDHAgreement = NULL;
		pCardData->pfnCspGetDHAgreement = NULL;

		if (pCardData->dwVersion > 5 && IsWindowsVistaOrGreater() && g_maxSpecVersion >= 6) {
			logger->TraceInfo("[%s:%d][MD] Reporting version 6 on Windows version %i.%i build %i. Max supported spec version is set to %i", __FUNCTION__, __LINE__, g_osver.dwMajorVersion, g_osver.dwMinorVersion, g_osver.dwBuildNumber, g_maxSpecVersion);

			/*pCardData->pfnCardGetChallengeEx = CardGetChallengeEx;
			pCardData->pfnCardAuthenticateEx = CardAuthenticateEx;
			pCardData->pfnCardChangeAuthenticatorEx = CardChangeAuthenticatorEx;
			pCardData->pfnCardDeauthenticateEx = CardDeauthenticateEx;
			pCardData->pfnCardGetContainerProperty = CardGetContainerProperty;
			pCardData->pfnCardSetContainerProperty = CardSetContainerProperty;
			pCardData->pfnCardGetProperty = CardGetProperty;
			pCardData->pfnCardSetProperty = CardSetProperty;*/
		} else {
			logger->TraceInfo("[%s:%d][MD] Version 6 is not supported on Windows version %i.%i build %i. Max supported spec version is set to %i", __FUNCTION__, __LINE__, g_osver.dwMajorVersion, g_osver.dwMinorVersion, g_osver.dwBuildNumber, g_maxSpecVersion);
		}

		if (pCardData->dwVersion > 6 && IsWindowsVistaOrGreater() && g_maxSpecVersion >= 7) {
			logger->TraceInfo("[%s:%d][MD] Reporting version 7 on Windows version %i.%i build %i. Max supported spec version is set to %i", __FUNCTION__, __LINE__, g_osver.dwMajorVersion, g_osver.dwMinorVersion, g_osver.dwBuildNumber, g_maxSpecVersion);
			/*pCardData->pfnCardDestroyKey = CardDestroyKey;
			pCardData->pfnCardGetAlgorithmProperty = CardGetAlgorithmProperty;
			pCardData->pfnCardGetKeyProperty = CardGetKeyProperty;
			pCardData->pfnCardGetSharedKeyHandle = CardGetSharedKeyHandle;
			pCardData->pfnCardProcessEncryptedData = CardProcessEncryptedData;
			pCardData->pfnCardSetKeyProperty = CardSetKeyProperty;
			pCardData->pfnCardCreateContainerEx = CardCreateContainerEx;
			pCardData->pfnMDImportSessionKey = MDImportSessionKey;
			pCardData->pfnMDEncryptData = MDEncryptData;
			pCardData->pfnCardImportSessionKey = CardImportSessionKey;*/
		} else {
			logger->TraceInfo("[%s:%d][MD] Version 7 is not supported on Windows version %i.%i build %i. Max supported spec version is set to %i", __FUNCTION__, __LINE__, g_osver.dwMajorVersion, g_osver.dwMinorVersion, g_osver.dwBuildNumber, g_maxSpecVersion);
		}
	}

	return SCARD_S_SUCCESS;
}


//CardDeleteContext
DWORD WINAPI
CardDeleteContext(
	__inout		PCARD_DATA	pCardData
)
{
	DWORD	dwRet = SCARD_S_SUCCESS;
	if (logger) {
		logger->TraceInfo("CardDeleteContext");
	}

	ykpiv_state*	ykState = (ykpiv_state *)pCardData->pvVendorSpecific;
	if (logger) { logger->TraceInfo("CardDeleteContext: ykState->context = %x", ykState->context);}
	LONG	scrc = SCardReleaseContext(ykState->context);
	if (logger) { logger->TraceInfo("CardDeleteContext: SCardReleaseContext - scrc=%x", scrc); }

	return dwRet;
} // of CardDeleteContext


//CardQueryCapabilities
DWORD WINAPI
CardQueryCapabilities(
	__in      PCARD_DATA          pCardData,
	__in      PCARD_CAPABILITIES  pCardCapabilities
)
{
	DWORD	dwRet = SCARD_S_SUCCESS;
	if (logger) {
		logger->TraceInfo("CardQueryCapabilities");
	}

	return dwRet;
} // of CardQueryCapabilities


//CardDeleteContainer
DWORD WINAPI
CardDeleteContainer(
	__in PCARD_DATA pCardData,
	__in BYTE bContainerIndex,
	__in DWORD dwReserved
)
{
	if (logger) {
		logger->TraceInfo("CardDeleteContainer");
	}
	return SCARD_E_UNSUPPORTED_FEATURE;
} // of CardDeleteContainer


//CardCreateContainer
DWORD WINAPI
CardCreateContainer(
	__in PCARD_DATA pCardData,
	__in BYTE bContainerIndex,
	__in DWORD dwFlags,
	__in DWORD dwKeySpec,
	__in DWORD dwKeySize,
	__in PBYTE pbKeyData
)
{
	if (logger) {
		logger->TraceInfo("CardCreateContainer");
	}
	return SCARD_E_UNSUPPORTED_FEATURE;
} // of CardCreateContainer


//CardGetContainerInfo
DWORD WINAPI
CardGetContainerInfo(
	__in PCARD_DATA	pCardData,
	__in BYTE bContainerIndex,
	__in DWORD dwFlags,
	__in PCONTAINER_INFO pContainerInfo
)
{
	if (logger) {
		logger->TraceInfo("CardGetContainerInfo");
	}
	if (!pCardData) return SCARD_E_INVALID_PARAMETER;
	if (!pContainerInfo) return SCARD_E_INVALID_PARAMETER;
	if (dwFlags) return SCARD_E_INVALID_PARAMETER;
	if (pContainerInfo->dwVersion < 0 || pContainerInfo->dwVersion >  CONTAINER_INFO_CURRENT_VERSION)
		return ERROR_REVISION_MISMATCH;

	return SCARD_S_SUCCESS;
} // of CardGetContainerInfo


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
	DWORD	dwRet = SCARD_S_SUCCESS;
	if (logger) {
		logger->TraceInfo("CardAuthenticatePin");
	}

	return dwRet;
}


//CardGetChallenge
DWORD WINAPI
CardGetChallenge(
	__in PCARD_DATA pCardData,
	__deref_out_bcount(*pcbChallengeData) PBYTE *ppbChallengeData,
	__out PDWORD pcbChallengeData
)
{
	if (logger) {
		logger->TraceInfo("CardGetChallenge");
	}
	if (NULL == pCardData)
		return SCARD_E_INVALID_PARAMETER;
	if (NULL == ppbChallengeData)
		return SCARD_E_INVALID_PARAMETER;
	if (NULL == pcbChallengeData)
		return SCARD_E_INVALID_PARAMETER;

	return SCARD_S_SUCCESS;
} // of CardGetChallenge


//CardAuthenticateChallenge
DWORD WINAPI
CardAuthenticateChallenge(
	__in PCARD_DATA  pCardData,
	__in_bcount(cbResponseData) PBYTE pbResponseData,
	__in DWORD cbResponseData,
	__out_opt PDWORD pcAttemptsRemaining
)
{
	if (logger) {
		logger->TraceInfo("CardAuthenticateChallenge");
	}
	return SCARD_E_UNSUPPORTED_FEATURE;
} // of CardAuthenticateChallenge


//CardUnblockPin
DWORD WINAPI
CardUnblockPin(
	__in PCARD_DATA  pCardData,
	__in LPWSTR pwszUserId,
	__in_bcount(cbAuthenticationData) PBYTE pbAuthenticationData,
	__in DWORD cbAuthenticationData,
	__in_bcount(cbNewPinData) PBYTE pbNewPinData,
	__in DWORD cbNewPinData,
	__in DWORD cRetryCount,
	__in DWORD dwFlags
)
{
	if (logger) {
		logger->TraceInfo("CardUnblockPin");
	}

	return SCARD_S_SUCCESS;
} // of CardUnblockPin


//CardChangeAuthenticator
DWORD WINAPI
CardChangeAuthenticator(
	__in PCARD_DATA	pCardData,
	__in LPWSTR pwszUserId,
	__in_bcount(cbCurrentAuthenticator) PBYTE pbCurrentAuthenticator,
	__in DWORD cbCurrentAuthenticator,
	__in_bcount(cbNewAuthenticator) PBYTE pbNewAuthenticator,
	__in DWORD cbNewAuthenticator,
	__in DWORD cRetryCount,
	__in DWORD dwFlags,
	__out_opt PDWORD pcAttemptsRemaining
)
{
	ykpiv_rc	ykrc;
	int			tries = 0;

	if (logger) {
		logger->TraceInfo("CardChangeAuthenticator");
		char szUserId[MAX_PATH] = { 0 };
		wcstombs(szUserId, pwszUserId, wcslen(pwszUserId));
		logger->PrintBuffer(pbCurrentAuthenticator, cbCurrentAuthenticator);
		logger->PrintBuffer(pbNewAuthenticator, cbNewAuthenticator);
		logger->TraceInfo("szUserId=%s  cRetryCount=%d  dwFlags=0x%x  pcAttemptsRemaining=%d", szUserId, cRetryCount, dwFlags, *pcAttemptsRemaining);
	}

	ykpiv_state*	ykState = (ykpiv_state *)pCardData->pvVendorSpecific;
	if (logger) {
		logger->TraceInfo("CardChangeAuthenticator: state->context=0x%x", ykState->context);
	}
	ykrc = ykpiv_change_pin(
				ykState,
				(const char *)pbCurrentAuthenticator, (size_t)cbCurrentAuthenticator,
				(const char *)pbNewAuthenticator, (size_t)cbNewAuthenticator,
				&tries);
	if (logger) {
		logger->TraceInfo("CardChangeAuthenticator: ykpiv_change_pin: ykrc=%d; tries=%d", ykrc, tries);
	}
	return ykrc2mdrc(ykrc);
} // of CardChangeAuthenticator


//CardCreateDirectory
DWORD WINAPI CardCreateDirectory(
	__in PCARD_DATA pCardData,
	__in LPSTR pszDirectoryName,
	__in CARD_DIRECTORY_ACCESS_CONDITION AccessCondition
)
{
	if (logger) {
		logger->TraceInfo("CardCreateDirectory");
	}
	return SCARD_E_UNSUPPORTED_FEATURE;
} // of CardCreateDirectory


//CardDeleteDirectory
DWORD WINAPI
CardDeleteDirectory(
	__in PCARD_DATA pCardData,
	__in LPSTR pszDirectoryName
)
{
	if (logger) {
		logger->TraceInfo("CardDeleteDirectory");
	}
	return SCARD_E_UNSUPPORTED_FEATURE;
} // of CardDeleteDirectory


//CardCreateFile
DWORD WINAPI
CardCreateFile(
	__in PCARD_DATA pCardData,
	__in LPSTR pszDirectoryName,
	__in LPSTR pszFileName,
	__in DWORD cbInitialCreationSize,
	__in CARD_FILE_ACCESS_CONDITION AccessCondition
)
{
	if (logger) {
		logger->TraceInfo("CardCreateFile");
	}
	return SCARD_E_UNSUPPORTED_FEATURE;
} // of CardCreateFile


//CardReadFile
DWORD WINAPI
CardReadFile(
	__in PCARD_DATA pCardData,
	__in LPSTR pszDirectoryName,
	__in LPSTR pszFileName,
	__in DWORD dwFlags,
	__deref_out_bcount(*pcbData) PBYTE *ppbData,
	__out PDWORD pcbData
)
{
	if (logger) {
		logger->TraceInfo("CardReadFile");
	}
	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	if (!pszFileName)
		return SCARD_E_INVALID_PARAMETER;
	if (!strlen(pszFileName))
		return SCARD_E_INVALID_PARAMETER;
	if (!ppbData)
		return SCARD_E_INVALID_PARAMETER;
	if (!pcbData)
		return SCARD_E_INVALID_PARAMETER;
	if (dwFlags)
		return SCARD_E_INVALID_PARAMETER;
	
	return SCARD_S_SUCCESS;
}


//CardWriteFile
DWORD WINAPI CardWriteFile(
	__in PCARD_DATA pCardData,
	__in LPSTR pszDirectoryName,
	__in LPSTR pszFileName,
	__in DWORD dwFlags,
	__in_bcount(cbData) PBYTE pbData,
	__in DWORD cbData
)
{
	if (logger) {
		logger->TraceInfo("CardWriteFile");
	}
	if (!pCardData) return SCARD_E_INVALID_PARAMETER;
	return SCARD_E_UNSUPPORTED_FEATURE;
}


//CardDeleteFile
DWORD WINAPI CardDeleteFile(
	__in PCARD_DATA pCardData,
	__in LPSTR pszDirectoryName,
	__in LPSTR pszFileName,
	__in DWORD dwFlags
)
{
	if (logger) {
		logger->TraceInfo("CardDeleteFile");
	}
	return SCARD_E_UNSUPPORTED_FEATURE;
} // of CardDeleteFile


//CardEnumFiles
DWORD WINAPI CardEnumFiles(
	__in PCARD_DATA  pCardData,
	__in LPSTR pszDirectoryName,
	__out_ecount(*pdwcbFileName) LPSTR *pmszFileNames,
	__out LPDWORD pdwcbFileName,
	__in DWORD dwFlags
)
{
	if (logger) {
		logger->TraceInfo("CardEnumFiles");
	}
	if (!pCardData) return SCARD_E_INVALID_PARAMETER;
	if (!pmszFileNames) return SCARD_E_INVALID_PARAMETER;
	if (!pdwcbFileName) return SCARD_E_INVALID_PARAMETER;
	if (dwFlags) return SCARD_E_INVALID_PARAMETER;

	return SCARD_S_SUCCESS;
} // of CardEnumFiles


//CardGetFileInfo
DWORD WINAPI
CardGetFileInfo(
	__in PCARD_DATA pCardData,
	__in LPSTR pszDirectoryName,
	__in LPSTR pszFileName,
	__in PCARD_FILE_INFO pCardFileInfo
)
{
	if (logger) {
		logger->TraceInfo("CardGetFileInfo");
	}
	if (!pCardData) return SCARD_E_INVALID_PARAMETER;
	if (!pszFileName) return SCARD_E_INVALID_PARAMETER;
	if (!strlen(pszFileName)) return SCARD_E_INVALID_PARAMETER;
	if (!pCardFileInfo) return SCARD_E_INVALID_PARAMETER;

	if (pCardFileInfo->dwVersion != CARD_FILE_INFO_CURRENT_VERSION &&
		pCardFileInfo->dwVersion != 0)
		return ERROR_REVISION_MISMATCH;

	return SCARD_S_SUCCESS;
}


//CardQueryFreeSpace
DWORD WINAPI
CardQueryFreeSpace(
	__in PCARD_DATA pCardData,
	__in DWORD dwFlags,
	__in PCARD_FREE_SPACE_INFO pCardFreeSpaceInfo
)
{
	if (logger) {
		logger->TraceInfo("CardQueryFreeSpace");
	}
	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;
	if (!pCardFreeSpaceInfo)
		return SCARD_E_INVALID_PARAMETER;
	if (dwFlags)
		return SCARD_E_INVALID_PARAMETER;

	if (pCardFreeSpaceInfo->dwVersion != CARD_FREE_SPACE_INFO_CURRENT_VERSION && pCardFreeSpaceInfo->dwVersion != 0)
		return ERROR_REVISION_MISMATCH;

	pCardFreeSpaceInfo->dwVersion = CARD_FREE_SPACE_INFO_CURRENT_VERSION;
	pCardFreeSpaceInfo->dwBytesAvailable = 0;
	pCardFreeSpaceInfo->dwKeyContainersAvailable = 0;
	pCardFreeSpaceInfo->dwMaxKeyContainers = 2;

	return SCARD_S_SUCCESS;
} // of CardQueryFreeSpace


//CardQueryKeySizes
DWORD WINAPI
CardQueryKeySizes(
	__in PCARD_DATA pCardData,
	__in DWORD dwKeySpec,
	__in DWORD dwFlags,
	__in PCARD_KEY_SIZES pKeySizes
)
{
	if (logger) {
		logger->TraceInfo("CardQueryKeySizes");
	}
	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	if (!pKeySizes) {
		return SCARD_E_INVALID_PARAMETER;
	}

	if (dwFlags)
		return  SCARD_E_INVALID_PARAMETER;

	if (dwKeySpec > 8 || dwKeySpec == 0)
		return SCARD_E_INVALID_PARAMETER;

	if (dwKeySpec != AT_SIGNATURE && dwKeySpec != AT_KEYEXCHANGE)
		return SCARD_E_UNSUPPORTED_FEATURE;

	if (pKeySizes->dwVersion > CARD_KEY_SIZES_CURRENT_VERSION)
		return ERROR_REVISION_MISMATCH;

	return SCARD_S_SUCCESS;
} // of CardQueryKeySizes


//CardSignData
DWORD WINAPI
CardSignData(
	__in PCARD_DATA pCardData,
	__in PCARD_SIGNING_INFO pInfo
)
{
	if (logger) {
		logger->TraceInfo("CardSignData");
	}
	if (!pCardData) return SCARD_E_INVALID_PARAMETER;
	if (!pInfo) return SCARD_E_INVALID_PARAMETER;

	return SCARD_S_SUCCESS;
} // of CardSignData


//CardRSADecrypt
DWORD WINAPI
CardRSADecrypt(
	__in PCARD_DATA pCardData,
	__inout PCARD_RSA_DECRYPT_INFO  pInfo
)
{
	if (logger) {
		logger->TraceInfo("CardRSADecrypt");
	}
	if (!pCardData) return SCARD_E_INVALID_PARAMETER;
	if (!pInfo) return SCARD_E_INVALID_PARAMETER;
	if (pInfo->dwKeySpec > AT_SIGNATURE)
		return SCARD_E_INVALID_PARAMETER;

	if (pInfo->dwKeySpec != AT_KEYEXCHANGE)
	{
		if (pInfo->dwKeySpec <= AT_SIGNATURE)
			return SCARD_E_INVALID_PARAMETER;
	}
	if (pInfo->cbData <= 1)
		return SCARD_E_INSUFFICIENT_BUFFER;

	if (!pInfo->cbData)
		return SCARD_E_INSUFFICIENT_BUFFER;

	if (!pInfo->pbData) {
		return SCARD_E_INVALID_PARAMETER;
	}
	if (pInfo->dwKeySpec > 8 || pInfo->dwKeySpec == 0) {
		return SCARD_E_INVALID_PARAMETER;
	}
	if (pInfo->dwKeySpec != AT_SIGNATURE && pInfo->dwKeySpec != AT_KEYEXCHANGE) {
		return SCARD_E_INVALID_PARAMETER;
	}

	return SCARD_S_SUCCESS;
} // of CardRSADecrypt


//CardCreateContainerEx
DWORD WINAPI
CardCreateContainerEx(
	__in PCARD_DATA  pCardData,
	__in BYTE  bContainerIndex,
	__in DWORD  dwFlags,
	__in DWORD  dwKeySpec,
	__in DWORD  dwKeySize,
	__in PBYTE  pbKeyData,
	__in PIN_ID  PinId)
{
	if (logger) {
		logger->TraceInfo("CardCreateContainerEx");
	}
	return SCARD_E_UNSUPPORTED_FEATURE;
} // of CardCreateContainerEx


//////////////////////////////////////////////////////////////////////////////////////
//
//	Private Helper Functions
//
//////////////////////////////////////////////////////////////////////////////////////


//getProcessName
const char*	getProcessName() {
	//wchar_t	wProcessName[MAX_PATH];
	char	ProcessName[MAX_PATH];
	GetModuleFileName(NULL, ProcessName, MAX_PATH);
	std::string PN(ProcessName);//convert wchar* to wstring
	std::string strProcessNameFullPath(PN.begin(), PN.end());
	size_t lastIndexPath = strProcessNameFullPath.find_last_of("\\");
	size_t lastIndexDot = strProcessNameFullPath.find_last_of(".");
	std::string strProcessName = strProcessNameFullPath.substr(lastIndexPath + 1, lastIndexDot - lastIndexPath - 1);
	return strProcessName.c_str();
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
			logger = CPPLOGGER::CPPLogger::getInstance(CPPLOGGER::LogLevel_Info, LOG_PATH, "");
			if (logger) {
				logger->TraceInfo("DllMain");
			}
		break;

		case DLL_PROCESS_DETACH:
			if (logger) {
				delete logger;
			}
		break;
	}
	return TRUE;
}