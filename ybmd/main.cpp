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
	case YKPIV_OK:						dwRet = SCARD_S_SUCCESS;
		if (logger) { logger->TraceInfo("ykrc2mdrc: YKPIV_OK -> SCARD_S_SUCCESS"); }
		break;
	case YKPIV_MEMORY_ERROR:			dwRet = SCARD_E_NO_MEMORY;
		if (logger) { logger->TraceInfo("ykrc2mdrc: YKPIV_MEMORY_ERROR -> SCARD_E_NO_MEMORY"); }
		break;
	case YKPIV_PCSC_ERROR:				dwRet = SCARD_F_INTERNAL_ERROR;
		if (logger) { logger->TraceInfo("ykrc2mdrc: YKPIV_PCSC_ERROR -> SCARD_F_INTERNAL_ERROR"); }
		break;
	case YKPIV_SIZE_ERROR:				dwRet = SCARD_E_INVALID_PARAMETER;
		if (logger) { logger->TraceInfo("ykrc2mdrc: YKPIV_SIZE_ERROR -> SCARD_E_INVALID_PARAMETER"); }
		break;
	case YKPIV_APPLET_ERROR:			dwRet = SCARD_F_INTERNAL_ERROR;
		if (logger) { logger->TraceInfo("ykrc2mdrc: YKPIV_APPLET_ERROR -> SCARD_F_INTERNAL_ERROR"); }
		break;
	case YKPIV_AUTHENTICATION_ERROR:	dwRet = SCARD_W_CARD_NOT_AUTHENTICATED;
		if (logger) { logger->TraceInfo("ykrc2mdrc: YKPIV_AUTHENTICATION_ERROR -> SCARD_W_CARD_NOT_AUTHENTICATED"); }
		break;
	case YKPIV_RANDOMNESS_ERROR:		dwRet = SCARD_F_INTERNAL_ERROR;
		if (logger) { logger->TraceInfo("ykrc2mdrc: YKPIV_RANDOMNESS_ERROR -> SCARD_F_INTERNAL_ERROR"); }
		break;
	case YKPIV_GENERIC_ERROR:			dwRet = SCARD_F_INTERNAL_ERROR;
		if (logger) { logger->TraceInfo("ykrc2mdrc: YKPIV_GENERIC_ERROR -> SCARD_F_INTERNAL_ERROR"); }
		break;
	case YKPIV_KEY_ERROR:				dwRet = SCARD_F_INTERNAL_ERROR;
		if (logger) { logger->TraceInfo("ykrc2mdrc: YKPIV_KEY_ERROR -> SCARD_F_INTERNAL_ERROR"); }
		break;
	case YKPIV_PARSE_ERROR:				dwRet = SCARD_E_INVALID_PARAMETER;
		if (logger) { logger->TraceInfo("ykrc2mdrc: YKPIV_PARSE_ERROR -> SCARD_E_INVALID_PARAMETER"); }
		break;
	case YKPIV_WRONG_PIN:				dwRet = SCARD_E_INVALID_CHV;
		if (logger) { logger->TraceInfo("ykrc2mdrc: YKPIV_WRONG_PIN -> SCARD_E_INVALID_CHV"); }
		break;
	case YKPIV_INVALID_OBJECT:			dwRet = SCARD_F_INTERNAL_ERROR;
		if (logger) { logger->TraceInfo("ykrc2mdrc: YKPIV_INVALID_OBJECT -> SCARD_F_INTERNAL_ERROR"); }
		break;
	case YKPIV_ALGORITHM_ERROR:			dwRet = SCARD_F_INTERNAL_ERROR;
		if (logger) { logger->TraceInfo("ykrc2mdrc: YKPIV_ALGORITHM_ERROR -> SCARD_F_INTERNAL_ERROR"); }
		break;
	case YKPIV_PIN_LOCKED:				dwRet = SCARD_W_CHV_BLOCKED;
		if (logger) { logger->TraceInfo("ykrc2mdrc: YKPIV_PIN_LOCKED -> SCARD_W_CHV_BLOCKED"); }
		break;
	default:							dwRet = SCARD_F_UNKNOWN_ERROR;
		if (logger) { logger->TraceInfo("ykrc2mdrc: %d -> SCARD_F_UNKNOWN_ERROR", ykrc); }
	}
	return dwRet;
}


#define CHREF_ACT_CHANGE_PIN 0
#define CHREF_ACT_UNBLOCK_PIN 1
#define CHREF_ACT_CHANGE_PUK 2

static ykpiv_rc _send_data(ykpiv_state *state, APDU *apdu,
	unsigned char *data, unsigned long *recv_len, int *sw) {
	long rc;
	unsigned int send_len = (unsigned int)apdu->st.lc + 5;

	logger->TraceInfo("_send_data");
	if (1) {
		logger->TraceInfo("Data Sent:");
		logger->PrintBuffer(apdu->raw, send_len);
	}
	rc = SCardTransmit(state->card, SCARD_PCI_T1, apdu->raw, send_len, NULL, data, recv_len);
	if (rc != SCARD_S_SUCCESS) {
		if (1) {
			logger->TraceInfo("error: SCardTransmit failed, rc=%08lx\n", rc);
		}
		return YKPIV_PCSC_ERROR;
	}

	if (1) {
		logger->TraceInfo("Data Received:");
		logger->PrintBuffer(data, *recv_len);
	}
	if (*recv_len >= 2) {
		*sw = (data[*recv_len - 2] << 8) | data[*recv_len - 1];
	} else {
		*sw = 0;
	}
	return YKPIV_OK;
}

ykpiv_rc _transfer_data(ykpiv_state *state, const unsigned char *templ,
	const unsigned char *in_data, long in_len,
	unsigned char *out_data, unsigned long *out_len, int *sw) {
	const unsigned char *in_ptr = in_data;
	unsigned long max_out = *out_len;
	ykpiv_rc res;
	//long rc;
	*out_len = 0;

	logger->TraceInfo("_transfer_data");

	/*rc = SCardBeginTransaction(state->card);
	if (rc != SCARD_S_SUCCESS) {
	if (state->verbose) {
	fprintf(stderr, "error: Failed to begin pcsc transaction, rc=%08lx\n", rc);
	}
	return YKPIV_PCSC_ERROR;
	}*/

	do {
		size_t this_size = 0xff;
		unsigned char data[261];
		unsigned long recv_len = sizeof(data);
		APDU apdu;

		memset(apdu.raw, 0, sizeof(apdu.raw));
		memcpy(apdu.raw, templ, 4);
		if (in_ptr + 0xff < in_data + in_len) {
			apdu.st.cla = 0x10;
		} else {
			this_size = (size_t)((in_data + in_len) - in_ptr);
		}
		if (1) {
			logger->TraceInfo("Going to send %lu bytes in this go.\n", (unsigned long)this_size);
		}
		apdu.st.lc = (unsigned char)this_size;
		memcpy(apdu.st.data, in_ptr, this_size);
		res = _send_data(state, &apdu, data, &recv_len, sw);
		logger->TraceInfo("1st _send_data: res=%d", res);
		if (res != YKPIV_OK) {
			return res;
		}
		else if (*sw != SW_SUCCESS && *sw >> 8 != 0x61) {
			return YKPIV_OK;
		}
		if (*out_len + recv_len - 2 > max_out) {
			if (1) {
				logger->TraceInfo("Output buffer to small, wanted to write %lu, max was %lu.\n", *out_len + recv_len - 2, max_out);
			}
			return YKPIV_SIZE_ERROR;
		}
		if (out_data) {
			memcpy(out_data, data, recv_len - 2);
			out_data += recv_len - 2;
			*out_len += recv_len - 2;
		}
		in_ptr += this_size;
	} while (in_ptr < in_data + in_len);
	while (*sw >> 8 == 0x61) {
		APDU apdu;
		unsigned char data[261];
		unsigned long recv_len = sizeof(data);

		if (1) { 
			logger->TraceInfo("The card indicates there is %d bytes more data for us.\n", *sw & 0xff);
		}

		memset(apdu.raw, 0, sizeof(apdu.raw));
		apdu.st.ins = 0xc0;
		res = _send_data(state, &apdu, data, &recv_len, sw);
		logger->TraceInfo("2nd _send_data: res=%d", res);
		if (res != YKPIV_OK) {
			return res;
		}
		else if (*sw != SW_SUCCESS && *sw >> 8 != 0x61) {
			return YKPIV_OK;
		}
		if (*out_len + recv_len - 2 > max_out) {
			logger->TraceInfo("Output buffer to small, wanted to write %lu, max was %lu.", *out_len + recv_len - 2, max_out);
		}
		if (out_data) {
			memcpy(out_data, data, recv_len - 2);
			out_data += recv_len - 2;
			*out_len += recv_len - 2;
		}
	}

	/*rc = SCardEndTransaction(state->card, SCARD_LEAVE_CARD);
	if (rc != SCARD_S_SUCCESS) {
	if (state->verbose) {
	fprintf(stderr, "error: Failed to end pcsc transaction, rc=%08lx\n", rc);
	}
	return YKPIV_PCSC_ERROR;
	}*/
	return YKPIV_OK;
}

static ykpiv_rc _change_pin_internal(ykpiv_state *state, int action, const char * current_pin, size_t current_pin_len, const char * new_pin, size_t new_pin_len, int *tries) {
	int sw;
	unsigned char templ[] = { 0, YKPIV_INS_CHANGE_REFERENCE, 0, 0x80 };
	unsigned char indata[0x10];
	unsigned char data[0xff];
	unsigned long recv_len = sizeof(data);
	ykpiv_rc res;

	logger->TraceInfo("_change_pin_internal");

	if (current_pin_len > 8) {
		return YKPIV_SIZE_ERROR;
	}
	if (new_pin_len > 8) {
		return YKPIV_SIZE_ERROR;
	}
	if (action == CHREF_ACT_UNBLOCK_PIN) {
		templ[1] = YKPIV_INS_RESET_RETRY;
	} else if (action == CHREF_ACT_CHANGE_PUK) {
		templ[3] = 0x81;
	}
	memcpy(indata, current_pin, current_pin_len);
	if (current_pin_len < 8) {
		memset(indata + current_pin_len, 0xff, 8 - current_pin_len);
	}
	memcpy(indata + 8, new_pin, new_pin_len);
	if (new_pin_len < 8) {
		memset(indata + 8 + new_pin_len, 0xff, 8 - new_pin_len);
	}
	res = _transfer_data(state, templ, indata, sizeof(indata), data, &recv_len, &sw);
	if (res != YKPIV_OK) {
		return res;
	} else if (sw != SW_SUCCESS) {
		if ((sw >> 8) == 0x63) {
			*tries = sw & 0xf;
			return YKPIV_WRONG_PIN;
		}
		else if (sw == SW_ERR_AUTH_BLOCKED) {
			return YKPIV_PIN_LOCKED;
		} else {
			if (1) {
				logger->TraceInfo("Failed changing pin, token response code: %x.\n", sw);
			}
			return YKPIV_GENERIC_ERROR;
		}
	}
	return YKPIV_OK;
}

ykpiv_rc _change_pin(ykpiv_state *state, const char * current_pin, size_t current_pin_len, const char * new_pin, size_t new_pin_len, int *tries) {
	return _change_pin_internal(state, CHREF_ACT_CHANGE_PIN, current_pin, current_pin_len, new_pin, new_pin_len, tries);
}


//CardAcquireContext
DWORD WINAPI
CardAcquireContext(
	IN		PCARD_DATA	pCardData,
	__in	DWORD		dwFlags
)
{
	ykpiv_state*	ykState;
	SCARDCONTEXT	sCtx = SCARD_E_INVALID_HANDLE;
	DWORD			dwRet = SCARD_S_SUCCESS;

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
		LONG			scrc;

		ykState = (ykpiv_state *)pCardData->pfnCspAlloc(sizeof(ykpiv_state));
		if (NULL == ykState) {
			return YKPIV_MEMORY_ERROR;
		}
		memset(ykState, 0, sizeof(ykpiv_state));
		ykState->verbose = TRUE;

		scrc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &sCtx);
		if (SCARD_S_SUCCESS != scrc) {
			if (logger) { logger->TraceInfo("CardAcquireContext: SCardEstablishContext failed - ErrCode=%x", scrc); }
			return SCARD_F_INTERNAL_ERROR;
		}

		// WARNING: NEVER call SCardConnect/SCardReconnect, it will hung up
		ykState->context = sCtx;
		ykState->card = pCardData->hScard;

		if (logger) {
			logger->TraceInfo("CardAcquireContext:     ykState->context = %x", ykState->context);
			logger->TraceInfo("CardAcquireContext:        ykState->card = %x", ykState->card);
			logger->TraceInfo("CardAcquireContext: pCardData->pvVendorSpecific=%p", pCardData->pvVendorSpecific);
		}

		{
			if (logger) { logger->TraceInfo("CardAcquireContext: _send_data with ins=0xa4"); }

			APDU apdu;
			unsigned char data[0xff];
			unsigned long recv_len = sizeof(data);
			int sw;
			ykpiv_rc res;

			memset(apdu.raw, 0, sizeof(apdu));
			apdu.st.ins = 0xa4;
			apdu.st.p1 = 0x04;
			apdu.st.lc = sizeof(aid);
			memcpy(apdu.st.data, aid, sizeof(aid));

			if ((res = _send_data(ykState, &apdu, data, &recv_len, &sw)) != YKPIV_OK) {
				if (logger) { logger->TraceInfo("CardAcquireContext: Failed communicating with card: %d", res); }
			}
			else if (sw == SW_SUCCESS) {
				return YKPIV_OK;
			}
			else {
				if (logger) { logger->TraceInfo("CardAcquireContext: Failed selecting application: %04x\n", sw); }
			}
		}
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
	ykpiv_state	ykState;

	if (logger) { logger->TraceInfo("CardDeleteContext"); }

	ykState.card = pCardData->hScard;
	ykState.context = pCardData->hSCardCtx;

	if (logger) { logger->TraceInfo("CardDeleteContext: SCardReleaseContext(ykState.context=%x)", ykState.context); }
	LONG	scrc = SCardReleaseContext(ykState.context);
	if (logger) {
		logger->TraceInfo("CardDeleteContext: SCardReleaseContext returns %x", scrc);
	}
	return SCARD_S_SUCCESS;
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
	ykpiv_state	ykState;
	ykpiv_rc	ykrc;
	int			tries = 0;
	char		oldpin[9] = { 0 };
	char		newpin[9] = { 0 };

	if (logger) {
		logger->TraceInfo("CardChangeAuthenticator");
		char szUserId[MAX_PATH] = { 0 };
		wcstombs(szUserId, pwszUserId, wcslen(pwszUserId));
		logger->PrintBuffer(pbCurrentAuthenticator, cbCurrentAuthenticator);
		logger->PrintBuffer(pbNewAuthenticator, cbNewAuthenticator);
		logger->TraceInfo("szUserId=%s  cRetryCount=%d  dwFlags=0x%x  pcAttemptsRemaining=%d", szUserId, cRetryCount, dwFlags, *pcAttemptsRemaining);
	}

	ykState.context = pCardData->hSCardCtx;
	ykState.card = pCardData->hScard;
	if (logger) {
		logger->TraceInfo("CardChangeAuthenticator: ykState.context=0x%x", ykState.context);
	}

	memcpy(oldpin, (const char *)pbCurrentAuthenticator, 8);
	memcpy(newpin, (const char *)pbNewAuthenticator, 8);
	logger->TraceInfo("CardChangeAuthenticator: oldpin=%s  newpin=%s", oldpin, newpin);
	ykrc = _change_pin(
				&ykState,
				(const char *)oldpin, 8,
				(const char *)newpin, 8,
				&tries);
	if (logger) {
		logger->TraceInfo("CardChangeAuthenticator: _change_pin: ykrc=%d; tries=%d", ykrc, tries);
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
	DWORD	dwRet = SCARD_S_SUCCESS;
	if (logger) {
		logger->TraceInfo("CardReadFile");
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
	if (!pcbData)
		return SCARD_E_INVALID_PARAMETER;
	if (dwFlags)
		return SCARD_E_INVALID_PARAMETER;

	//cardid
	if (strcmp(pszFileName, szCARD_IDENTIFIER_FILE) == 0) {
		const char buf[] = {
					0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
					0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
					};//dummy szCARD_IDENTIFIER_FILE value
		*ppbData = (PBYTE)pCardData->pfnCspAlloc(sizeof(buf));
		if (!*ppbData) {
			logger->TraceInfo("CardReadFile(szCARD_IDENTIFIER_FILE): SCARD_E_NO_MEMORY");
			return SCARD_E_NO_MEMORY;
		}
		*pcbData = (DWORD)sizeof(buf);
		memcpy(*ppbData, buf, sizeof(buf));
	}
	//cardcf
	else if (strcmp(pszFileName, szCACHE_FILE) == 0) {
		const char buf[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };//dummy szCACHE_FILE value
		*ppbData = (PBYTE)pCardData->pfnCspAlloc(sizeof(buf));
		if (!*ppbData) {
			logger->TraceInfo("CardReadFile(szCACHE_FILE): SCARD_E_NO_MEMORY");
			return SCARD_E_NO_MEMORY;
		}
		*pcbData = (DWORD)sizeof(buf);
		memcpy(*ppbData, buf, sizeof(buf));
	}
	//cmapfile
	else if (strcmp(pszFileName, szCONTAINER_MAP_FILE) == 0) {
		typedef struct _CONTAINERMAPRECORD {
			BYTE GuidInfo[80];	// 40 x UNICODE char
			BYTE Flags;		// Bit 1 set for default container
			BYTE RFUPadding;
			WORD ui16SigKeySize;
			WORD ui16KeyExchangeKeySize;
		} CONTAINERMAPRECORD;
		CONTAINERMAPRECORD	cmaprec;//dummy szCONTAINER_MAP_FILE value
		memset(&cmaprec, 0, sizeof(CONTAINERMAPRECORD));
		cmaprec.Flags = 0x3;

		*ppbData = (PBYTE)pCardData->pfnCspAlloc(sizeof(CONTAINERMAPRECORD));
		if (!*ppbData) {
			logger->TraceInfo("CardReadFile(szCONTAINER_MAP_FILE): SCARD_E_NO_MEMORY");
			return SCARD_E_NO_MEMORY;
		}
		*pcbData = (DWORD)sizeof(CONTAINERMAPRECORD);
		memcpy(*ppbData, &cmaprec, sizeof(CONTAINERMAPRECORD));
	}
	else {
		logger->TraceInfo("CardReadFile: SCARD_E_FILE_NOT_FOUND");
		dwRet = SCARD_E_FILE_NOT_FOUND;
	}
	
	logger->TraceInfo("CardReadFile returns %x", dwRet);
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