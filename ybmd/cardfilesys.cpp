#include "stdafx.h"
#include <VersionHelpers.h>

#include "../inc/cpdk/cardmod.h"
#include <ykpiv/ykpiv.h>
#include <internal.h>

#include "../cpplogger/cpplogger.h"
#include "helper.h"


extern	CPPLOGGER::CPPLogger*	logger;

#define	SZ_MAX_PAGE			2048 //max size in bytes per flash page
#define	SZ_MAX_LEN			sizeof(DWORD) //max size in bytes to store the length of write data

// Move into ykpiv.h later
#define	szCARD_APPS				"cardapps"
#define	YKPIV_OBJ_MSMD			0x5fd000
#define YKPIV_OBJ_MSMDMSROOTS	(YKPIV_OBJ_MSMD + 1)
#define	YKPIV_OBJ_MSMDCARDID	(YKPIV_OBJ_MSMD + 2) // Fixed Size: 16 bytes
#define	YKPIV_OBJ_MSMDCARDCF	(YKPIV_OBJ_MSMD + 3) // Variable Size:  6 bytes - 8KB or more
#define	YKPIV_OBJ_MSMDCARDAPPS	(YKPIV_OBJ_MSMD + 4) // Fixed Size:  8 bytes
#define	YKPIV_OBJ_MSMDCMAPFILE	(YKPIV_OBJ_MSMD + 5) // Variable Size:  6 bytes - 8KB or more


const char* cardDirAccessCond2String(const CARD_DIRECTORY_ACCESS_CONDITION cond) {
	switch (cond) {
	case 0: return "InvalidDirAc";
	case 1: return "UserCreateDeleteDirAc";
	case 2: return "AdminCreateDeleteDirAc";
	default: return "UNDEFINED";
	}
}


const char* cardFileAccessCond2String(const CARD_FILE_ACCESS_CONDITION cond) {
	switch (cond) {
	case 0: return "InvalidAc";
	case 1: return "EveryoneReadUserWriteAc";
	case 2: return "UserWriteExecuteAc";
	case 3: return "EveryoneReadAdminWriteAc";
	case 4: return "UnknownAc";
	case 5: return "UserReadWriteAc";
	case 6: return "AdminReadWriteAc";
	default: return "UNDEFINED";
	}
}


//CardCreateDirectory
DWORD WINAPI CardCreateDirectory(
	__in PCARD_DATA pCardData,
	__in LPSTR pszDirectoryName,
	__in CARD_DIRECTORY_ACCESS_CONDITION AccessCondition
)
{
	if (logger) {
		logger->TraceInfo("\n");
		logger->TraceInfo("#####    CardCreateDirectory    #####");
		logger->TraceInfo("#####################################");
		logger->TraceInfo("IN pszDirectoryName: %s", pszDirectoryName);
		logger->TraceInfo("IN AccessCondition: %s", cardDirAccessCond2String(AccessCondition));
	}

	logger->TraceInfo("CardCreateDirectory returns SCARD_E_UNSUPPORTED_FEATURE");
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
		logger->TraceInfo("\n");
		logger->TraceInfo("#####    CardDeleteDirectory    #####");
		logger->TraceInfo("#####################################");
		logger->TraceInfo("IN pszDirectoryName: %s", pszDirectoryName);
	}

	logger->TraceInfo("CardDeleteDirectory returns SCARD_E_UNSUPPORTED_FEATURE");
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
		logger->TraceInfo("\n");
		logger->TraceInfo("#####    CardCreateFile    #####");
		logger->TraceInfo("################################");
		logger->TraceInfo("IN pszDirectoryName: %s", pszDirectoryName);
		logger->TraceInfo("IN pszFileName: %s", pszFileName);
		logger->TraceInfo("IN cbInitialCreationSize: %d", cbInitialCreationSize);
		logger->TraceInfo("IN AccessCondition: %s", cardFileAccessCond2String(AccessCondition));
	}

	logger->TraceInfo("CardCreateFile returns SCARD_E_UNSUPPORTED_FEATURE");
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
	ykpiv_state		ykState;
	ykpiv_rc		ykrc = YKPIV_OK;
	DWORD			objID;
	unsigned char	buf[SZ_MAX_PAGE + SZ_MAX_LEN + 1];
	DWORD			buflen = sizeof(buf) - 1;
	DWORD			dwRet = SCARD_S_SUCCESS;

	if (logger) {
		logger->TraceInfo("\n");
		logger->TraceInfo("#####    CardReadFile    #####");
		logger->TraceInfo("##############################");
		logger->TraceInfo("IN pszDirectoryName: %s", pszDirectoryName);
		logger->TraceInfo("IN pszFileName: %s", pszFileName);
		logger->TraceInfo("IN dwFlags: %x", dwFlags);
	}
	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;
	if (!pszFileName)
		return SCARD_E_INVALID_PARAMETER;
	if (!strlen(pszFileName))
		return SCARD_E_INVALID_PARAMETER;
	if (!ppbData)
		return SCARD_E_INVALID_PARAMETER;
	if (NULL == pcbData) {
		if (logger) { logger->TraceInfo("pcbData is NULL, read the entire file"); }
	}
	if (0 == *pcbData) {
		if (logger) { logger->TraceInfo("pcbData is 0, read the entire file"); }
	}
	if (dwFlags)
		return SCARD_E_INVALID_PARAMETER;
	if (SCARD_S_SUCCESS != SCardIsValidContext(pCardData->hSCardCtx)) {
		if (logger) { logger->TraceInfo("CardReadFile failed - SCardIsValidContext(%x) fails", pCardData->hSCardCtx); }
		return SCARD_E_INVALID_PARAMETER;
	}

	ykState.context = pCardData->hSCardCtx;
	ykState.card = pCardData->hScard;
	if (logger) {
		logger->TraceInfo("CardReadFile: ykState.context=0x%x", ykState.context);
	}

	memset(buf, 0, sizeof(buf));

	//cardcf - YKPIV_OBJ_MSMDCARDCF
	if (0 == strcmp(pszFileName, szCACHE_FILE)) {
		objID = YKPIV_OBJ_MSMDCARDCF;
		ykrc = ykpiv_fetch_object(&ykState, objID, buf, &buflen);
		buflen = *((DWORD *)&buf[0]);
		if (ykrc != YKPIV_OK || 0 == buflen) {
			logger->TraceInfo("CardReadFile: ykpiv_fetch_object failed. ykrc=%d  buflen=%d", ykrc, buflen);
			buflen = 6;
			memset(buf, 0, buflen);
			dwRet = SCARD_E_FILE_NOT_FOUND;
		}
	}
	//cardid - YKPIV_OBJ_MSMDCARDID
	else if (0 == strcmp(pszFileName, szCARD_IDENTIFIER_FILE)) {
		objID = YKPIV_OBJ_MSMDCARDID;
		DWORD	dwDataLen = 0;
		buflen = 16;
		dwRet = CardGetProperty(pCardData, CP_CARD_GUID, (PBYTE)&buf[SZ_MAX_LEN], buflen, &dwDataLen, 0);
		if (SCARD_S_SUCCESS != dwRet) goto EXIT;
	}
	//cardapps - YKPIV_OBJ_MSMDCARDAPPS
	else if (0 == strcmp(pszFileName, szCARD_APPS)) {
		objID = YKPIV_OBJ_MSMDCARDAPPS;
		ykrc = ykpiv_fetch_object(&ykState, objID, buf, &buflen);
		buflen = *((DWORD *)&buf[0]);
		if (ykrc != YKPIV_OK || 0 == buflen) {
			logger->TraceInfo("CardReadFile: ykpiv_fetch_object failed. ykrc=%d  buflen=%d", ykrc, buflen);
			buflen = 8;
			memcpy(buf, "mscp", 4);
			buf[buflen] = 0;
			dwRet = SCARD_E_FILE_NOT_FOUND;
		}
	}
	//cmapfile - YKPIV_OBJ_MSMDCMAPFILE
	else if (strcmp(pszFileName, szCONTAINER_MAP_FILE) == 0) {
		objID = YKPIV_OBJ_MSMDCMAPFILE;
		ykrc = ykpiv_fetch_object(&ykState, objID, buf, &buflen);
		buflen = *((DWORD *)&buf[0]);
		if (ykrc != YKPIV_OK || 0 == buflen) {
			logger->TraceInfo("CardReadFile: ykpiv_fetch_object failed. ykrc=%d  buflen=%d", ykrc, buflen);
			buflen = 0;
			dwRet = SCARD_E_FILE_NOT_FOUND;
		}
	}
	//msroots - YKPIV_OBJ_MSMDMSROOTS
	else if (strcmp(pszFileName, szROOT_STORE_FILE) == 0) {
		objID = YKPIV_OBJ_MSMDMSROOTS;
		ykrc = ykpiv_fetch_object(&ykState, objID, buf, &buflen);
		buflen = *((DWORD *)&buf[0]);
		if (ykrc != YKPIV_OK || 0 == buflen) {
			logger->TraceInfo("CardReadFile: ykpiv_fetch_object failed. ykrc=%d  buflen=%d", ykrc, buflen);
			buflen = 0;
			dwRet = SCARD_E_FILE_NOT_FOUND;
		}
	}
	else {
		logger->TraceInfo("CardReadFile: SCARD_E_INVALID_PARAMETER");
		dwRet = SCARD_E_INVALID_PARAMETER;
	}

	*pcbData = buflen;
	*ppbData = (PBYTE)pCardData->pfnCspAlloc(1 + *pcbData);
	if (!*ppbData) {
		logger->TraceInfo("CardReadFile: SCARD_E_NO_MEMORY");
		return SCARD_E_NO_MEMORY;
	}
	memset(*ppbData, 0, *pcbData);
	memcpy(*ppbData, &buf[SZ_MAX_LEN], *pcbData);

EXIT:
	if (logger) {
		logger->TraceInfo("OUT: *pcbData = %d", *pcbData);
		logger->TraceInfo("OUT: *ppbData");
		logger->PrintBuffer(*ppbData, *pcbData);
		logger->TraceInfo("CardReadFile returns %x", dwRet);
	}
	return dwRet;
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
	ykpiv_state	ykState;
	ykpiv_rc	ykrc;
	DWORD		objID;
	DWORD		dwRet = SCARD_S_SUCCESS;

	if (logger) {
		logger->TraceInfo("\n");
		logger->TraceInfo("#####    CardWriteFile    #####");
		logger->TraceInfo("###############################");
		logger->TraceInfo("IN pszDirectoryName: %s", pszDirectoryName);
		logger->TraceInfo("IN pszFileName: %s", pszFileName);
		logger->TraceInfo("IN dwFlags: %x", dwFlags);
		logger->TraceInfo("IN pbData:");
		logger->PrintBuffer(pbData, cbData);
	}
	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;
	if (!pszFileName)
		return SCARD_E_INVALID_PARAMETER;
	if (!strlen(pszFileName))
		return SCARD_E_INVALID_PARAMETER;
	if (!pbData)
		return SCARD_E_INVALID_PARAMETER;
	if (0 == cbData)
		return SCARD_E_INVALID_PARAMETER;
	if (cbData > SZ_MAX_PAGE)
		return SCARD_E_WRITE_TOO_MANY;
	if (dwFlags)
		return SCARD_E_INVALID_PARAMETER;
	if (SCARD_S_SUCCESS != SCardIsValidContext(pCardData->hSCardCtx)) {
		if (logger) { logger->TraceInfo("CardWriteFile failed - SCardIsValidContext(%x) fails", pCardData->hSCardCtx); }
		return SCARD_E_INVALID_PARAMETER;
	}

	ykState.context = pCardData->hSCardCtx;
	ykState.card = pCardData->hScard;
	if (logger) {
		logger->TraceInfo("CardWriteFile: ykState.context=0x%x", ykState.context);
	}

	//cardcf - YKPIV_OBJ_MSMDCARDCF
	if (0 == strcmp(pszFileName, szCACHE_FILE)) {
		objID = YKPIV_OBJ_MSMDCARDCF;
	}
	//cardid - YKPIV_OBJ_MSMDCARDID
	else if (0 == strcmp(pszFileName, szCARD_IDENTIFIER_FILE)) {
		objID = YKPIV_OBJ_MSMDCARDID;
	}
	//cmapfile - YKPIV_OBJ_MSMDCMAPFILE
	else if (strcmp(pszFileName, szCONTAINER_MAP_FILE) == 0) {
		objID = YKPIV_OBJ_MSMDCMAPFILE;
	}
	//msroots - YKPIV_OBJ_MSMDMSROOTS
	else if (strcmp(pszFileName, szROOT_STORE_FILE) == 0) {
		objID = YKPIV_OBJ_MSMDMSROOTS;
	}
	else {
		logger->TraceInfo("CardWriteFile: SCARD_E_INVALID_PARAMETER");
		dwRet = SCARD_E_INVALID_PARAMETER;
	}
	unsigned char* pBufWrite = (unsigned char *)pCardData->pfnCspAlloc(1 + cbData + SZ_MAX_LEN);
	memcpy(pBufWrite, (DWORD *)&cbData, SZ_MAX_LEN);
	memcpy(&pBufWrite[SZ_MAX_LEN], (unsigned char *)pbData, cbData);
	ykrc = ykpiv_save_object(&ykState, objID, pBufWrite, cbData + SZ_MAX_LEN);
	if (ykrc != YKPIV_OK) {
		if (logger) { logger->TraceInfo("CardWriteFile failed - ykpiv_save_object - Bytes to be written: %d", cbData + SZ_MAX_LEN); }
		return ykrc2mdrc(ykrc);
	}
#if 0 //verify write
	unsigned char	buf[SZ_MAX_PAGE + SZ_MAX_LEN + 1];
	DWORD			buflen = sizeof(buf) - 1;
	memset(buf, 0, sizeof(buf));
	ykrc = ykpiv_fetch_object(&ykState, objID, buf, &buflen);
	if (ykrc != YKPIV_OK) {
		if (logger) { logger->TraceInfo("CardWriteFile failed because ykpiv_fetch_object failed with error: %d", ykrc); }
	}
	else {
		buflen = *((DWORD *)&buf[0]);
		if (logger) { logger->PrintBuffer(buf, buflen + SZ_MAX_LEN); }
	}
#endif

	if (logger) { logger->TraceInfo("CardWriteFile returns SCARD_S_SUCCESS"); }
	return SCARD_S_SUCCESS;
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
		logger->TraceInfo("\n");
		logger->TraceInfo("#####    CardDeleteFile    #####");
		logger->TraceInfo("################################");
		logger->TraceInfo("IN pszDirectoryName: %s", pszDirectoryName);
		logger->TraceInfo("IN pszFileName: %s", pszFileName);
		logger->TraceInfo("IN dwFlags: %x", dwFlags);
	}
	logger->TraceInfo("CardDeleteFile returns SCARD_E_UNSUPPORTED_FEATURE");
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
		logger->TraceInfo("\n");
		logger->TraceInfo("#####    CardEnumFiles    #####");
		logger->TraceInfo("###############################");
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
		logger->TraceInfo("\n");
		logger->TraceInfo("#####    CardGetFileInfo    #####");
		logger->TraceInfo("#################################");
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
		logger->TraceInfo("\n");
		logger->TraceInfo("#####    CardQueryFreeSpace    #####");
		logger->TraceInfo("####################################");
		logger->TraceInfo("IN dwFlags: %x", dwFlags);
	}
	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;
	if (!pCardFreeSpaceInfo)
		return SCARD_E_INVALID_PARAMETER;
	if (dwFlags)
		return SCARD_E_INVALID_PARAMETER;//must be zero
	if (pCardFreeSpaceInfo->dwVersion != CARD_FREE_SPACE_INFO_CURRENT_VERSION
		&&
		pCardFreeSpaceInfo->dwVersion != 0) {
		return ERROR_REVISION_MISMATCH;
	}
	if (SCARD_S_SUCCESS != SCardIsValidContext(pCardData->hSCardCtx)) {
		if (logger) { logger->TraceInfo("CardQueryFreeSpace failed - SCardIsValidContext(%x) fails", pCardData->hSCardCtx); }
		return SCARD_E_INVALID_PARAMETER;
	}

	pCardFreeSpaceInfo->dwVersion = CARD_FREE_SPACE_INFO_CURRENT_VERSION;
	pCardFreeSpaceInfo->dwBytesAvailable = 8096;
	pCardFreeSpaceInfo->dwKeyContainersAvailable = 1;
	pCardFreeSpaceInfo->dwMaxKeyContainers = 1;

	if (logger) {
		logger->TraceInfo("OUT dwVersion: %x", pCardFreeSpaceInfo->dwVersion);
		logger->TraceInfo("OUT dwBytesAvailable: %x", pCardFreeSpaceInfo->dwBytesAvailable);
		logger->TraceInfo("OUT dwKeyContainersAvailable: %x", pCardFreeSpaceInfo->dwKeyContainersAvailable);
		logger->TraceInfo("OUT dwMaxKeyContainers: %x", pCardFreeSpaceInfo->dwMaxKeyContainers);
	}

	return SCARD_S_SUCCESS;
} // of CardQueryFreeSpace
