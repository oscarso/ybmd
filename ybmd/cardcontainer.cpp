#include "stdafx.h"
#include <VersionHelpers.h>

#include "../inc/cpdk/cardmod.h"
#include <ykpiv/ykpiv.h>
#include <internal.h>

#include "../cpplogger/cpplogger.h"
#include "helper.h"


extern	CPPLOGGER::CPPLogger*	logger;


//CardGetContainerProperty
DWORD WINAPI
CardGetContainerProperty(
	__in										PCARD_DATA	pCardData,
	__in										BYTE		bContainerIndex,
	__in										LPCWSTR		wszProperty,
	__out_bcount_part_opt(cbData, *pdwDataLen)	PBYTE		pbData,
	__in										DWORD		cbData,
	__out										PDWORD		pdwDataLen,
	__in										DWORD		dwFlags
)
{
	if (logger) {
		logger->TraceInfo("\n");
		logger->TraceInfo("#####   CardGetContainerProperty   #####");
		logger->TraceInfo("########################################");
	}

	logger->TraceInfo("CardGetContainerProperty returns SCARD_E_UNSUPPORTED_FEATURE");
	return SCARD_E_UNSUPPORTED_FEATURE;
}


//CardSetContainerProperty
DWORD WINAPI
CardSetContainerProperty(
	__in					PCARD_DATA	pCardData,
	__in					BYTE		bContainerIndex,
	__in					LPCWSTR		wszProperty,
	__in_bcount(cbDataLen)	PBYTE		pbData,
	__in					DWORD		cbDataLen,
	__in					DWORD		dwFlags
)
{
	if (logger) {
		logger->TraceInfo("\n");
		logger->TraceInfo("#####   CardSetContainerProperty   #####");
		logger->TraceInfo("########################################");
	}

	logger->TraceInfo("CardSetContainerProperty returns SCARD_E_UNSUPPORTED_FEATURE");
	return SCARD_E_UNSUPPORTED_FEATURE;
}


//CardGetProperty
DWORD WINAPI
CardGetProperty(
	__in										PCARD_DATA	pCardData,
	__in										LPCWSTR		wszProperty,
	__out_bcount_part_opt(cbData, *pdwDataLen)	PBYTE		pbData,
	__in										DWORD		cbData,
	__out										PDWORD		pdwDataLen,
	__in										DWORD		dwFlags
)
{
	ykpiv_rc		ykrc = YKPIV_OK;
	ykpiv_state		ykState;
	char			buf[MAX_PATH];
	DWORD			dwRet = SCARD_S_SUCCESS;

	if (logger) {
		logger->TraceInfo("\n");
		logger->TraceInfo("#####   CardGetProperty   #####");
		logger->TraceInfo("###############################");
		char prop[MAX_PATH] = { 0 };
		wcstombs(prop, wszProperty, wcslen(wszProperty));
		logger->TraceInfo("IN wszProperty: %s", prop);
		logger->TraceInfo("IN cbData: %d", cbData);
		logger->TraceInfo("IN dwFlags: %x", dwFlags);
	}

	if (SCARD_S_SUCCESS != SCardIsValidContext(pCardData->hSCardCtx)) {
		if (logger) { logger->TraceInfo("CardGetProperty failed - SCardIsValidContext(%x) fails", pCardData->hSCardCtx); }
		return SCARD_E_INVALID_PARAMETER;
	}

	ykState.context = pCardData->hSCardCtx;
	ykState.card = pCardData->hScard;

	//CP_CARD_SERIAL_NO
	if (0 == wcscmp(CP_CARD_SERIAL_NO, wszProperty)) {
		memset(buf, 0, sizeof(buf));
		ykrc = selectAppletYubiKey(&ykState);
		ykrc = getSerialNumber(&ykState, &buf[0]);
		memcpy(pbData, buf, 16);
		if (pdwDataLen) {
			*pdwDataLen = 16;
		}
	}
	//CP_CARD_GUID
	else if (0 == wcscmp(CP_CARD_GUID, wszProperty)) {
		// Refer to: https://github.com/OpenSC/OpenSC/blob/master/src/minidriver/opensc-minidriver.inf.in
#if 1
		const unsigned char class_guid[] = {
			0x99, 0x0a, 0x2b, 0xd7, 0xe7, 0x38, 0x46, 0xc7,
			0xb2, 0x6f, 0x1c, 0xf8, 0xfb, 0x9f, 0x13, 0x91 };
#endif
		memcpy(pbData, class_guid, sizeof(class_guid));
		if (pdwDataLen) {
			*pdwDataLen = sizeof(class_guid);
		}
	}

	if (logger) {
		logger->TraceInfo("OUT: pbData:");
		logger->PrintBuffer(pbData, cbData);
		logger->TraceInfo("OUT: *pdwDataLen: %d", *pdwDataLen);
		logger->TraceInfo("CardGetProperty returns %x", dwRet);
	}
	return dwRet;
}


//CardSetProperty
DWORD WINAPI
CardSetProperty(
	__in					PCARD_DATA	pCardData,
	__in					LPCWSTR		wszProperty,
	__in_bcount(cbDataLen)	PBYTE		pbData,
	__in					DWORD		cbDataLen,
	__in					DWORD		dwFlags
)
{
	if (logger) {
		logger->TraceInfo("\n");
		logger->TraceInfo("#####   CardSetProperty   #####");
		logger->TraceInfo("###############################");
		char prop[MAX_PATH] = { 0 };
		wcstombs(prop, wszProperty, wcslen(wszProperty));
		logger->TraceInfo("IN wszProperty: %s", prop);
		logger->TraceInfo("IN cbDataLen: %d", cbDataLen);
		logger->TraceInfo("IN dwFlags: %x", dwFlags);
	}

	logger->TraceInfo("CardSetProperty returns SCARD_E_UNSUPPORTED_FEATURE");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

