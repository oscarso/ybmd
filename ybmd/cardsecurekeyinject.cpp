#include "stdafx.h"
#include <VersionHelpers.h>

#include "../inc/cpdk/cardmod.h"
#include <ykpiv/ykpiv.h>
#include <internal.h>

#include "../cpplogger/cpplogger.h"
#include "helper.h"


extern	CPPLOGGER::CPPLogger*	logger;


//CardDestroyKey
DWORD WINAPI
CardDestroyKey(
	__in	PCARD_DATA		pCardData,
	__in	CARD_KEY_HANDLE	hKey
)
{
	if (logger) {
		logger->TraceInfo("\n");
		logger->TraceInfo("#####     CardDestroyKey     #####");
		logger->TraceInfo("###################################");
	}

	logger->TraceInfo("CardDestroyKey returns SCARD_E_UNSUPPORTED_FEATURE");
	return SCARD_E_UNSUPPORTED_FEATURE;
}


//CardGetAlgorithmProperty
DWORD WINAPI
CardGetAlgorithmProperty(
	__in										PCARD_DATA	pCardData,
	__in										LPCWSTR		pwszAlgId,
	__in										LPCWSTR		pwszProperty,
	__out_bcount_part_opt(cbData, *pdwDataLen)	PBYTE		pbData,
	__in										DWORD		cbData,
	__out										PDWORD		pdwDataLen,
	__in										DWORD		dwFlags
)
{
	if (logger) {
		logger->TraceInfo("\n");
		logger->TraceInfo("#####   CardGetAlgorithmProperty   #####");
		logger->TraceInfo("########################################");
	}

	logger->TraceInfo("CardGetAlgorithmProperty returns SCARD_E_UNSUPPORTED_FEATURE");
	return SCARD_E_UNSUPPORTED_FEATURE;
}


//CardGetKeyProperty
DWORD WINAPI
CardGetKeyProperty(
	__in										PCARD_DATA		pCardData,
	__in										CARD_KEY_HANDLE	hKey,
	__in										LPCWSTR			pwszProperty,
	__out_bcount_part_opt(cbData, *pdwDataLen)	PBYTE			pbData,
	__in										DWORD			cbData,
	__out										PDWORD			pdwDataLen,
	__in										DWORD			dwFlags
)
{
	if (logger) {
		logger->TraceInfo("\n");
		logger->TraceInfo("#####      CardGetKeyProperty      #####");
		logger->TraceInfo("########################################");
	}

	logger->TraceInfo("CardGetKeyProperty returns SCARD_E_UNSUPPORTED_FEATURE");
	return SCARD_E_UNSUPPORTED_FEATURE;
}


//CardGetSharedKeyHandle
DWORD WINAPI
CardGetSharedKeyHandle(
	__in								PCARD_DATA			pCardData,
	__in_bcount(cbInput)				PBYTE				pbInput,
	__in								DWORD				cbInput,
	__deref_opt_out_bcount(*pcbOutput)	PBYTE				*ppbOutput,
	__out_opt							PDWORD				pcbOutput,
	__out								PCARD_KEY_HANDLE	phKey
)
{
	if (logger) {
		logger->TraceInfo("\n");
		logger->TraceInfo("#####    CardGetSharedKeyHandle    #####");
		logger->TraceInfo("########################################");
	}

	logger->TraceInfo("CardGetSharedKeyHandle returns SCARD_E_UNSUPPORTED_FEATURE");
	return SCARD_E_UNSUPPORTED_FEATURE;
}


//CardSetKeyProperty
DWORD WINAPI
CardSetKeyProperty(
	__in					PCARD_DATA		pCardData,
	__in					CARD_KEY_HANDLE	hKey,
	__in					LPCWSTR			pwszProperty,
	__in_bcount(cbInput)	PBYTE			pbInput,
	__in					DWORD			cbInput,
	__in					DWORD			dwFlags
)
{
	if (logger) {
		logger->TraceInfo("\n");
		logger->TraceInfo("#####    CardSetKeyProperty    #####");
		logger->TraceInfo("####################################");
	}

	logger->TraceInfo("CardSetKeyProperty returns SCARD_E_UNSUPPORTED_FEATURE");
	return SCARD_E_UNSUPPORTED_FEATURE;
}
