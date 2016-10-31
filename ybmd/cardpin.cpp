#include "stdafx.h"
#include <VersionHelpers.h>

#include "../inc/cpdk/cardmod.h"
#include <ykpiv/ykpiv.h>
#include <internal.h>

#include "../cpplogger/cpplogger.h"
#include "helper.h"


extern	CPPLOGGER::CPPLogger*	logger;


int getRetryCount(ykpiv_state *state) {
	int tries = 0;
	ykpiv_rc ykrc = ykpiv_verify(state, NULL, &tries);
	if (YKPIV_OK == ykrc) {
		return tries;
	}
	return -1;
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
	ykpiv_state	ykState;
	ykpiv_rc	ykrc;
	char		key[24] = { 0 };
	char		pin[9] = { 0 };
	int			tries = 0;

	if (logger) {
		logger->TraceInfo("\n");
		logger->TraceInfo("#####    CardAuthenticatePin    #####");
		logger->TraceInfo("#####################################");
		char userID[MAX_PATH] = { 0 };
		wcstombs(userID, pwszUserId, wcslen(pwszUserId));
		logger->TraceInfo("IN pwszUserId: %s", userID);
		logger->TraceInfo("IN pbPin");
		logger->PrintBuffer(pbPin, cbPin);
		logger->TraceInfo("IN pcAttemptsRemaining: %p", pcAttemptsRemaining);
	}

	if (!pCardData) return SCARD_E_INVALID_PARAMETER;
	if (!pbPin || 0 == cbPin) return SCARD_E_INVALID_PARAMETER;
	if (SCARD_S_SUCCESS != SCardIsValidContext(pCardData->hSCardCtx)) {
		if (logger) { logger->TraceInfo("CardAuthenticatePin failed - SCardIsValidContext(%x) fails", pCardData->hSCardCtx); }
		return SCARD_E_INVALID_PARAMETER;
	}

	ykState.context = pCardData->hSCardCtx;
	ykState.card = pCardData->hScard;
	if (logger) { logger->TraceInfo("CardAuthenticatePin: ykState.context=0x%x", ykState.context); }
	if (shouldSelectApplet(&ykState)) {
		ykrc = selectApplet(&ykState);
		if (ykrc != YKPIV_OK) { logger->TraceInfo("CardAuthenticatePin: selectApplet failed. ykrc=%d", ykrc); }
	}

	memcpy(pin, (const char *)pbPin, (cbPin > 8) ? 8 : cbPin);
	memcpy(key, pin, 8);
	memcpy(&key[8], pin, 8);
	memcpy(&key[16], pin, 8);

	if (logger) {
		logger->PrintBuffer(pin, sizeof(pin));
	}

	ykrc = ykpiv_verify(&ykState, (const char *)pin, &tries);
	if (YKPIV_OK != ykrc) {
		if (logger) { logger->TraceInfo("CardAuthenticatePin: _verify: ykrc=%d", ykrc); }
		return ykrc2mdrc(ykrc);
	}

	ykrc = ykpiv_authenticate(&ykState, (const unsigned char *)key);
	if (ykrc != YKPIV_OK) {
		if (logger) { logger->TraceInfo("CardAuthenticatePin: ykpiv_authenticate: ykrc=%d", ykrc); }
		return ykrc2mdrc(ykrc);
	}

	if (pcAttemptsRemaining) {
		*pcAttemptsRemaining = (DWORD)getRetryCount(&ykState);
		if (logger) { logger->TraceInfo("OUT pcAttemptsRemaining: %d", *pcAttemptsRemaining); }
	}

	if (ykrc != YKPIV_OK && NULL == pcAttemptsRemaining) {
		// Function fail and no more attempts in retry
		if (logger) { logger->TraceInfo("CardAuthenticatePin returns SCARD_W_CHV_BLOCKED"); }
		return SCARD_W_CHV_BLOCKED;
	}
	else {
		return ykrc2mdrc(ykrc);
	}
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
		logger->TraceInfo("\n");
		logger->TraceInfo("#####    CardGetChallenge    #####");
		logger->TraceInfo("##################################");
	}
	if (NULL == pCardData)
		return SCARD_E_INVALID_PARAMETER;
	if (NULL == ppbChallengeData)
		return SCARD_E_INVALID_PARAMETER;
	if (NULL == pcbChallengeData)
		return SCARD_E_INVALID_PARAMETER;
	if (SCARD_S_SUCCESS != SCardIsValidContext(pCardData->hSCardCtx)) {
		if (logger) { logger->TraceInfo("CardGetChallenge failed - SCardIsValidContext(%x) fails", pCardData->hSCardCtx); }
		return SCARD_E_INVALID_PARAMETER;
	}

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
		logger->TraceInfo("\n");
		logger->TraceInfo("#####    CardAuthenticateChallenge    #####");
		logger->TraceInfo("###########################################");
	}
	if (SCARD_S_SUCCESS != SCardIsValidContext(pCardData->hSCardCtx)) {
		if (logger) { logger->TraceInfo("CardAuthenticateChallenge failed - SCardIsValidContext(%x) fails", pCardData->hSCardCtx); }
		return SCARD_E_INVALID_PARAMETER;
	}

	logger->TraceInfo("CardAuthenticateChallenge returns SCARD_E_UNSUPPORTED_FEATURE");
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
		logger->TraceInfo("\n");
		logger->TraceInfo("#####    CardUnblockPin    #####");
		logger->TraceInfo("################################");
	}
	if (SCARD_S_SUCCESS != SCardIsValidContext(pCardData->hSCardCtx)) {
		if (logger) { logger->TraceInfo("CardUnblockPin failed - SCardIsValidContext(%x) fails", pCardData->hSCardCtx); }
		return SCARD_E_INVALID_PARAMETER;
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
	ykpiv_state	ykState;
	ykpiv_rc	ykrc;
	int			tries = 0;
	char		oldpin[9] = { 0 };
	char		newpin[9] = { 0 };

	if (logger) {
		logger->TraceInfo("\n");
		logger->TraceInfo("#####    CardChangeAuthenticator    #####");
		logger->TraceInfo("#########################################");
		char szUserId[MAX_PATH] = { 0 };
		wcstombs(szUserId, pwszUserId, wcslen(pwszUserId));
		logger->PrintBuffer(pbCurrentAuthenticator, cbCurrentAuthenticator);
		logger->PrintBuffer(pbNewAuthenticator, cbNewAuthenticator);
		logger->TraceInfo("szUserId=%s  cRetryCount=%d  dwFlags=0x%x  pcAttemptsRemaining=%d", szUserId, cRetryCount, dwFlags, *pcAttemptsRemaining);
	}
	if (SCARD_S_SUCCESS != SCardIsValidContext(pCardData->hSCardCtx)) {
		if (logger) { logger->TraceInfo("CardChangeAuthenticator failed - SCardIsValidContext(%x) fails", pCardData->hSCardCtx); }
		return SCARD_E_INVALID_PARAMETER;
	}

	ykState.context = pCardData->hSCardCtx;
	ykState.card = pCardData->hScard;
	if (logger) {
		logger->TraceInfo("CardChangeAuthenticator: ykState.context=0x%x", ykState.context);
	}

	memcpy(oldpin, (const char *)pbCurrentAuthenticator, 8);
	memcpy(newpin, (const char *)pbNewAuthenticator, 8);
	logger->TraceInfo("CardChangeAuthenticator: oldpin=%s  newpin=%s", oldpin, newpin);
	ykrc = ykpiv_change_pin(
		&ykState,
		(const char *)oldpin, 8,
		(const char *)newpin, 8,
		&tries);
	if (logger) {
		logger->TraceInfo("CardChangeAuthenticator: ykpiv_change_pin: ykrc=%d; tries=%d", ykrc, tries);
	}
	return ykrc2mdrc(ykrc);
} // of CardChangeAuthenticator


//CardGetChallengeEx
DWORD WINAPI
CardGetChallengeEx(
	__in									PCARD_DATA	pCardData,
	__in									PIN_ID		PinId,
	__deref_out_bcount(*pcbChallengeData)	PBYTE		*ppbChallengeData,
	__out									PDWORD		pcbChallengeData,
	__in									DWORD		dwFlags)
{
	if (logger) {
		logger->TraceInfo("\n");
		logger->TraceInfo("#####   CardGetChallengeEx   #####");
		logger->TraceInfo("##################################");
	}

	logger->TraceInfo("CardGetChallengeEx returns SCARD_E_UNSUPPORTED_FEATURE");
	return SCARD_E_UNSUPPORTED_FEATURE;
}


//CardAuthenticateEx
DWORD WINAPI
CardAuthenticateEx(
	__in									PCARD_DATA	pCardData,
	__in									PIN_ID		PinId,
	__in									DWORD		dwFlags,
	__in_bcount(cbPinData)					PBYTE		pbPinData,
	__in									DWORD		cbPinData,
	__deref_opt_out_bcount(*pcbSessionPin)	PBYTE		*ppbSessionPin,
	__out_opt								PDWORD		pcbSessionPin,
	__out_opt								PDWORD		pcAttemptsRemaining
)
{
	if (logger) {
		logger->TraceInfo("\n");
		logger->TraceInfo("#####     CardAuthenticateEx     #####");
		logger->TraceInfo("######################################");
	}

	logger->TraceInfo("CardAuthenticateEx returns SCARD_E_UNSUPPORTED_FEATURE");
	return SCARD_E_UNSUPPORTED_FEATURE;
}


//CardChangeAuthenticatorEx
DWORD WINAPI
CardChangeAuthenticatorEx(
	__in									PCARD_DATA	pCardData,
	__in									DWORD		dwFlags,
	__in									PIN_ID		dwAuthenticatingPinId,
	__in_bcount(cbAuthenticatingPinData)	PBYTE		pbAuthenticatingPinData,
	__in									DWORD		cbAuthenticatingPinData,
	__in									PIN_ID		dwTargetPinId,
	__in_bcount(cbTargetData)				PBYTE		pbTargetData,
	__in									DWORD		cbTargetData,
	__in									DWORD		cRetryCount,
	__out_opt								PDWORD		pcAttemptsRemaining
)
{
	if (logger) {
		logger->TraceInfo("\n");
		logger->TraceInfo("#####   CardChangeAuthenticatorEx   #####");
		logger->TraceInfo("#########################################");
	}

	logger->TraceInfo("CardChangeAuthenticatorEx returns SCARD_E_UNSUPPORTED_FEATURE");
	return SCARD_E_UNSUPPORTED_FEATURE;
}


//CardDeauthenticateEx
DWORD WINAPI
CardDeauthenticateEx(
	__in	PCARD_DATA	pCardData,
	__in	PIN_SET		PinId,
	__in	DWORD		dwFlags
)
{
	if (logger) {
		logger->TraceInfo("\n");
		logger->TraceInfo("#####     CardDeauthenticateEx     #####");
		logger->TraceInfo("########################################");
	}

	logger->TraceInfo("CardDeauthenticateEx returns SCARD_E_UNSUPPORTED_FEATURE");
	return SCARD_E_UNSUPPORTED_FEATURE;
}
