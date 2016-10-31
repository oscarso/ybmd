#include "stdafx.h"
#include <VersionHelpers.h>

#include "../inc/cpdk/cardmod.h"
#include <ykpiv/ykpiv.h>
#include <internal.h>

#include "../cpplogger/cpplogger.h"
#include "helper.h"


extern	CPPLOGGER::CPPLogger*	logger;


//CardQueryCapabilities
DWORD WINAPI
CardQueryCapabilities(
	__in      PCARD_DATA          pCardData,
	__in      PCARD_CAPABILITIES  pCardCapabilities
)
{
	if (logger) {
		logger->TraceInfo("\n");
		logger->TraceInfo("#####    CardQueryCapabilities    #####");
		logger->TraceInfo("#######################################");
	}

	if (SCARD_S_SUCCESS != SCardIsValidContext(pCardData->hSCardCtx)) {
		if (logger) { logger->TraceInfo("CardQueryCapabilities failed - SCardIsValidContext(%x) fails", pCardData->hSCardCtx); }
		return SCARD_E_INVALID_PARAMETER;
	}

	pCardCapabilities->dwVersion = CONTAINER_INFO_CURRENT_VERSION;
	pCardCapabilities->fCertificateCompression = FALSE;
	pCardCapabilities->fKeyGen = TRUE;

	if (logger) { logger->TraceInfo("CardQueryCapabilities returns SCARD_S_SUCCESS"); }
	return SCARD_S_SUCCESS;
} // of CardQueryCapabilities