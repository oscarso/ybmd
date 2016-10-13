#include "stdafx.h"
#include <stdio.h>
#include <mutex>
#include <VersionHelpers.h>

#include "../cpplogger/cpplogger.h"
#include "../inc/cpdk/cardmod.h"
#include <ykpiv/ykpiv.h>
#include <internal.h>


// Global Variables
#define	SZ_MAX_PAGE			2048 //max size in bytes per flash page
#define	SZ_MAX_LEN			sizeof(DWORD) //max size in bytes to store the length of write data
#define	LOG_PATH			"C:\\Logs\\"
CPPLOGGER::CPPLogger*		logger = NULL;
HMODULE						g_hDll = 0;
OSVERSIONINFO				g_osver;
unsigned int				g_maxSpecVersion = 7;


// Move into ykpiv.h later
#define	szCARD_APPS				"cardapps"
#define	YKPIV_OBJ_MSMD			0x5fd000
#define YKPIV_OBJ_MSMDMSROOTS	(YKPIV_OBJ_MSMD + 1)
#define	YKPIV_OBJ_MSMDCARDID	(YKPIV_OBJ_MSMD + 2) // Fixed Size: 16 bytes
#define	YKPIV_OBJ_MSMDCARDCF	(YKPIV_OBJ_MSMD + 3) // Variable Size:  6 bytes - 8KB or more
#define	YKPIV_OBJ_MSMDCARDAPPS	(YKPIV_OBJ_MSMD + 4) // Fixed Size:  8 bytes
#define	YKPIV_OBJ_MSMDCMAPFILE	(YKPIV_OBJ_MSMD + 5) // Variable Size:  6 bytes - 8KB or more


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
	case YKPIV_WRONG_PIN:				dwRet = SCARD_W_WRONG_CHV;
		if (logger) { logger->TraceInfo("ykrc2mdrc: YKPIV_WRONG_PIN -> SCARD_W_WRONG_CHV"); }
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

#if 1
static int set_length(unsigned char *buffer, size_t length) {
	if (length < 0x80) {
		*buffer++ = length;
		return 1;
	}
	else if (length < 0xff) {
		*buffer++ = 0x81;
		*buffer++ = length;
		return 2;
	}
	else {
		*buffer++ = 0x82;
		*buffer++ = (length >> 8) & 0xff;
		*buffer++ = length & 0xff;
		return 3;
	}
}
ykpiv_rc _import_private_key(
			ykpiv_state *state,
			const unsigned char key,
			unsigned char algorithm,
			const unsigned char *p, size_t p_len,
			const unsigned char *q, size_t q_len,
			const unsigned char *dp, size_t dp_len,
			const unsigned char *dq, size_t dq_len,
			const unsigned char *qinv, size_t qinv_len,
			const unsigned char *ec_data, unsigned char ec_data_len,
			const unsigned char pin_policy,
			const unsigned char touch_policy)
{
	unsigned char key_data[1024];
	unsigned char *in_ptr = key_data;
	unsigned char templ[] = { 0, YKPIV_INS_IMPORT_KEY, algorithm, key };
	unsigned char data[256];
	unsigned long recv_len = sizeof(data);
	unsigned elem_len;
	int sw;
	const unsigned char *params[5];
	size_t lens[5];
	size_t padding;
	unsigned char n_params;
	int i;
	int param_tag;

	if (state == NULL)
		return YKPIV_GENERIC_ERROR;

	if (key == YKPIV_KEY_CARDMGM ||
		key < YKPIV_KEY_RETIRED1 ||
		(key > YKPIV_KEY_RETIRED20 && key < YKPIV_KEY_AUTHENTICATION) ||
		(key > YKPIV_KEY_CARDAUTH && key != YKPIV_KEY_ATTESTATION)) {
		return YKPIV_KEY_ERROR;
	}

	if (pin_policy != YKPIV_PINPOLICY_DEFAULT &&
		pin_policy != YKPIV_PINPOLICY_NEVER &&
		pin_policy != YKPIV_PINPOLICY_ONCE &&
		pin_policy != YKPIV_PINPOLICY_ALWAYS)
		return YKPIV_GENERIC_ERROR;

	if (touch_policy != YKPIV_TOUCHPOLICY_DEFAULT &&
		touch_policy != YKPIV_TOUCHPOLICY_NEVER &&
		touch_policy != YKPIV_TOUCHPOLICY_ALWAYS &&
		touch_policy != YKPIV_TOUCHPOLICY_CACHED)
		return YKPIV_GENERIC_ERROR;

	if (algorithm == YKPIV_ALGO_RSA1024 || algorithm == YKPIV_ALGO_RSA2048) {

		if (algorithm == YKPIV_ALGO_RSA1024)
			elem_len = 64;
		if (algorithm == YKPIV_ALGO_RSA2048)
			elem_len = 128;

		if (p == NULL || q == NULL || dp == NULL ||
			dq == NULL || qinv == NULL)
			return YKPIV_GENERIC_ERROR;

		params[0] = p;
		lens[0] = p_len;
		params[1] = q;
		lens[1] = q_len;
		params[2] = dp;
		lens[2] = dp_len;
		params[3] = dq;
		lens[3] = dq_len;
		params[4] = qinv;
		lens[4] = qinv_len;
		param_tag = 0x01;

		n_params = 5;
	}
	else if (algorithm == YKPIV_ALGO_ECCP256 || algorithm == YKPIV_ALGO_ECCP384) {
		if (algorithm == YKPIV_ALGO_ECCP256)
			elem_len = 32;
		if (algorithm == YKPIV_ALGO_ECCP384)
			elem_len = 48;

		if (ec_data == NULL)
			return YKPIV_GENERIC_ERROR;

		params[0] = ec_data;
		lens[0] = ec_data_len;
		param_tag = 0x06;
		n_params = 1;
	}
	else
		return YKPIV_ALGORITHM_ERROR;

	for (i = 0; i < n_params; i++) {
		*in_ptr++ = param_tag + i;
		in_ptr += set_length(in_ptr, elem_len);
		padding = elem_len - lens[i];
		memset(in_ptr, 0, padding);
		in_ptr += padding;
		memcpy(in_ptr, params[i], lens[i]);
		in_ptr += lens[i];
	}

	if (pin_policy != YKPIV_PINPOLICY_DEFAULT) {
		*in_ptr++ = YKPIV_PINPOLICY_TAG;
		*in_ptr++ = 0x01;
		*in_ptr++ = pin_policy;
	}

	if (touch_policy != YKPIV_TOUCHPOLICY_DEFAULT) {
		*in_ptr++ = YKPIV_TOUCHPOLICY_TAG;
		*in_ptr++ = 0x01;
		*in_ptr++ = touch_policy;
	}

	if (ykpiv_transfer_data(state, templ, key_data, in_ptr - key_data, data, &recv_len, &sw) != YKPIV_OK)
		return YKPIV_GENERIC_ERROR;

	if (sw == SW_ERR_SECURITY_STATUS)
		return YKPIV_AUTHENTICATION_ERROR;

	if (sw != SW_SUCCESS)
		return YKPIV_GENERIC_ERROR;

	return YKPIV_OK;
}
#endif

#if 1
static ykpiv_rc _send_data(ykpiv_state *state, APDU *apdu,
	unsigned char *data, unsigned long *recv_len, int *sw) {
	long rc;
	unsigned int send_len = (unsigned int)apdu->st.lc + 5;

	if (logger) {
		logger->TraceInfo("_send_data");
		logger->TraceInfo("Data Sent:");
		logger->PrintBuffer(apdu->raw, send_len);
	}

	rc = SCardTransmit(state->card, SCARD_PCI_T1, apdu->raw, send_len, NULL, data, recv_len);
	if (rc != SCARD_S_SUCCESS) {
		if (logger) { logger->TraceInfo("error: SCardTransmit failed, rc=%08lx\n", rc); }
		return YKPIV_PCSC_ERROR;
	}

	if (logger) {
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
#endif

#if 0
ykpiv_rc _verify(ykpiv_state *state, const char *pin, int *tries) {
	APDU apdu;
	unsigned char data[261];
	unsigned long recv_len = sizeof(data);
	int sw;
	size_t len = 0;
	ykpiv_rc res;
	if (pin) {
		len = strlen(pin);
	}

	if (len > 8) {
		return YKPIV_SIZE_ERROR;
	}

	memset(apdu.raw, 0, sizeof(apdu.raw));
	apdu.st.ins = YKPIV_INS_VERIFY;
	apdu.st.p1 = 0x00;
	apdu.st.p2 = 0x80;
	apdu.st.lc = pin ? 0x08 : 0;
	if (pin) {
		memcpy(apdu.st.data, pin, len);
		if (len < 8) {
			memset(apdu.st.data + len, 0xff, 8 - len);
		}
	}
	if ((res = _send_data(state, &apdu, data, &recv_len, &sw)) != YKPIV_OK) {
		return res;
	}
	else if (sw == SW_SUCCESS) {
		*tries = (sw & 0xf);
		return YKPIV_OK;
	}
	else if ((sw >> 8) == 0x63) {
		*tries = (sw & 0xf);
		return YKPIV_WRONG_PIN;
	}
	else if (sw == SW_ERR_AUTH_BLOCKED) {
		*tries = 0;
		return YKPIV_WRONG_PIN;
	}
	else {
		return YKPIV_GENERIC_ERROR;
	}
}
#endif


ykpiv_rc selectApplet(ykpiv_state *state) {
		APDU apdu;
		unsigned char data[0xff];
		unsigned long recv_len = sizeof(data);
		int sw;
		ykpiv_rc res = YKPIV_OK;

		if (logger) { logger->TraceInfo("selectApplet: _send_data"); }

		memset(apdu.raw, 0, sizeof(apdu));
		apdu.st.ins = 0xa4;
		apdu.st.p1 = 0x04;
		apdu.st.lc = sizeof(aid);
		memcpy(apdu.st.data, aid, sizeof(aid));

		if ((res = _send_data(state, &apdu, data, &recv_len, &sw)) != YKPIV_OK) {
			if (logger) { logger->TraceInfo("selectApplet: Failed communicating with card: %d", res); }
		}
		else if (sw == SW_SUCCESS) {
			res = YKPIV_OK;
		}
		else {
			if (logger) { logger->TraceInfo("selectApplet: Failed selecting application: %04x\n", sw); }
		}
		if (logger) { logger->TraceInfo("selectApplet returns %x\n", res); }
		return res;
}


ykpiv_rc selectAppletYubiKey(ykpiv_state *state) {
	APDU apdu;
	unsigned char data[0xff];
	unsigned long recv_len = sizeof(data);
	int sw;
	unsigned const char yk_applet[] = { 0xa0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01, 0x01 };
	ykpiv_rc res = YKPIV_OK;

	if (logger) { logger->TraceInfo("selectAppletYubiKey: _send_data"); }

	memset(apdu.raw, 0, sizeof(apdu));
	apdu.st.ins = 0xa4;
	apdu.st.p1 = 0x04;
	apdu.st.lc = sizeof(yk_applet);
	memcpy(apdu.st.data, yk_applet, sizeof(yk_applet));

	if ((res = _send_data(state, &apdu, data, &recv_len, &sw)) != YKPIV_OK) {
		if (logger) { logger->TraceInfo("selectAppletYubiKey: Failed communicating with card: %d", res); }
	}
	else if (sw == SW_SUCCESS) {
		res = YKPIV_OK;
	}
	else {
		if (logger) { logger->TraceInfo("selectAppletYubiKey: Failed selecting application: %04x\n", sw); }
	}
	if (logger) { logger->TraceInfo("selectAppletYubiKey returns %x\n", res); }
	return res;
}


ykpiv_rc getSerialNumber(ykpiv_state *state, char* pSerial) {
	ykpiv_rc		res = YKPIV_OK;
	APDU			apdu;
	int				sw;
	unsigned char	data[0xff];
	unsigned long	recv_len = sizeof(data);
	unsigned const char	get_serial[] = { 0x00, 0x01, 0x10, 0x00 };
	union {
		unsigned int ui;
		unsigned char uc[4];
	} uSerial;

	if (logger) { logger->TraceInfo("getSerialNumber"); }

	memset(apdu.raw, 0, sizeof(apdu.raw));
	memcpy(apdu.raw, get_serial, sizeof(get_serial));

	if ((res = _send_data(state, &apdu, data, &recv_len, &sw)) != YKPIV_OK) {
		if (logger) { logger->TraceInfo("getSerialNumber: Failed communicating with card: %d", res); }
	} else if (sw == SW_SUCCESS) {
		res = YKPIV_OK;
		uSerial.uc[0] = data[3];
		uSerial.uc[1] = data[2];
		uSerial.uc[2] = data[1];
		uSerial.uc[3] = data[0];
		if (logger) { logger->TraceInfo("getSerialNumber: uSerial.ui = %u", uSerial.ui); }
		memset(data, 0, sizeof(data));
		sprintf((char *)data, "%u", uSerial.ui);
		size_t len = strlen((const char *)data);
		memcpy(pSerial, data, len);
		memset(&pSerial[len], ' ', 16-len);
		return YKPIV_OK;
	} else {
		if (logger) { logger->TraceInfo("getSerialNumber: Failed selecting application: %04x\n", sw); }
	}

	return YKPIV_GENERIC_ERROR;
}


BOOL shouldSelectApplet(ykpiv_state *state) {
	int tries = 0;
	ykpiv_rc ykrc = ykpiv_verify(state, NULL, &tries);
	if (logger) { logger->TraceInfo("shouldSelectApplet returns ykrc=%d\n", ykrc); }
	return (ykrc != YKPIV_OK);
}


int getRetryCount(ykpiv_state *state) {
	int tries = 0;
	ykpiv_rc ykrc = ykpiv_verify(state, NULL, &tries);
	if (YKPIV_OK == ykrc) {
		return tries;
	}
	return -1;
}


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


//CardQueryCapabilities
DWORD WINAPI
CardQueryCapabilities(
	__in      PCARD_DATA          pCardData,
	__in      PCARD_CAPABILITIES  pCardCapabilities
)
{
	DWORD	dwRet = SCARD_S_SUCCESS;
	if (logger) {
		logger->TraceInfo("\n");
		logger->TraceInfo("#####    CardQueryCapabilities    #####");
		logger->TraceInfo("#######################################");
	}

	if (SCARD_S_SUCCESS != SCardIsValidContext(pCardData->hSCardCtx)) {
		if (logger) { logger->TraceInfo("CardQueryCapabilities failed - SCardIsValidContext(%x) fails", pCardData->hSCardCtx); }
		return SCARD_E_INVALID_PARAMETER;
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
		logger->TraceInfo("\n");
		logger->TraceInfo("#####    CardDeleteContainer    #####");
		logger->TraceInfo("#####################################");
	}

	if (SCARD_S_SUCCESS != SCardIsValidContext(pCardData->hSCardCtx)) {
		if (logger) { logger->TraceInfo("CardDeleteContainer failed - SCardIsValidContext(%x) fails", pCardData->hSCardCtx); }
		return SCARD_E_INVALID_PARAMETER;
	}

	return SCARD_E_UNSUPPORTED_FEATURE;
} // of CardDeleteContainer



const char* keySpec2String(DWORD dwKeySpec) {
	switch (dwKeySpec) {
	case AT_KEYEXCHANGE: return "AT_KEYEXCHANGE";
	case AT_SIGNATURE: return "AT_SIGNATURE";
	case AT_ECDSA_P256: return "AT_ECDSA_P256";
	case AT_ECDSA_P384: return "AT_ECDSA_P384";
	case AT_ECDSA_P521: return "AT_ECDSA_P521";
	case AT_ECDHE_P256: return "AT_ECDHE_P256";
	case AT_ECDHE_P384: return "AT_ECDHE_P384";
	case AT_ECDHE_P521: return "AT_ECDHE_P521";
	default:
		return NULL;
	}
}
const char* createContainerFlag2String(DWORD dwFlags) {
	switch (dwFlags) {
	case CARD_CREATE_CONTAINER_KEY_GEN: return "CARD_CREATE_CONTAINER_KEY_GEN";
	case CARD_CREATE_CONTAINER_KEY_IMPORT: return "CARD_CREATE_CONTAINER_KEY_IMPORT";
	default:
		return NULL;
	}
}
BOOL isValidKeySize(DWORD dwKeySize) {
	switch (dwKeySize) {
	case 128: return TRUE;
	case 256: return TRUE;
	case 512: return TRUE;
	case 1024: return TRUE;
	case 2048: return TRUE;
	case 4096: return TRUE;
	default:
		return FALSE;
	}
}

void ReverseBuffer(LPBYTE pbData, DWORD cbData)
{
	DWORD i;
	for (i = 0; i<(cbData / 2); i++)
	{
		BYTE t = pbData[i];
		pbData[i] = pbData[cbData - 1 - i];
		pbData[cbData - 1 - i] = t;
	}
}
void logPrivateKeyBlob(LPBYTE pbBlob)
{
	//Reference: https://www.idrix.fr/Root/Samples/pfx_parse.cpp
	LPBYTE pbModulus, pbPrime1, pbPrime2, pbExp1, pbExp2, pbCoeff, pbPriExp;
	DWORD cbModulus, cbPrime1, cbPrime2, cbExp1, cbExp2, cbCoeff, cbPriExp;
	RSAPUBKEY* pRsa = (RSAPUBKEY *)(pbBlob + sizeof(BLOBHEADER));
	LPBYTE pbKeyData = pbBlob + sizeof(BLOBHEADER) + sizeof(RSAPUBKEY);

	cbModulus = (pRsa->bitlen + 7) / 8;
	cbPriExp = cbModulus;
	cbPrime1 = cbPrime2 = cbExp1 = cbExp2 = cbCoeff = cbModulus / 2;
	pbModulus = pbKeyData;
	pbPrime1 = pbModulus + cbModulus;
	pbPrime2 = pbPrime1 + cbPrime1;
	pbExp1 = pbPrime2 + cbPrime2;
	pbExp2 = pbExp1 + cbExp1;
	pbCoeff = pbExp2 + cbExp2;
	pbPriExp = pbCoeff + cbCoeff;

	ReverseBuffer(pbModulus, cbModulus);
	ReverseBuffer(pbPrime1, cbPrime1);
	ReverseBuffer(pbPrime2, cbPrime2);
	ReverseBuffer(pbExp1, cbExp1);
	ReverseBuffer(pbExp2, cbExp2);
	ReverseBuffer(pbCoeff, cbCoeff);
	ReverseBuffer(pbPriExp, cbPriExp);

	if (logger) {
		logger->TraceInfo("\n");
		logger->TraceInfo("Private Key Details:\n");
		logger->TraceInfo("=> RSA Bit Length = %d\n", pRsa->bitlen);
		logger->TraceInfo("=> Public Exponent = 0x%.8X\n", pRsa->pubexp);
		logger->TraceInfo("=> Modulus = ");
		logger->PrintBuffer(pbModulus, cbModulus);
		logger->TraceInfo("=> Private Exponent = ");
		logger->PrintBuffer(pbPriExp, cbPriExp);
		logger->TraceInfo("=> P:");
		logger->PrintBuffer(pbPrime1, cbPrime1);
		logger->TraceInfo("=> Q:");
		logger->PrintBuffer(pbPrime2, cbPrime2);
		logger->TraceInfo("=> DP:");
		logger->PrintBuffer(pbExp1, cbExp1);
		logger->TraceInfo("=> DQ:");
		logger->PrintBuffer(pbExp2, cbExp2);
		logger->TraceInfo("=> Coefficient:");
		logger->PrintBuffer(pbCoeff, cbCoeff);
	}
}
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
		logger->TraceInfo("\n");
		logger->TraceInfo("#####    CardCreateContainer    #####");
		logger->TraceInfo("#####################################");
		logger->TraceInfo("IN bContainerIndex: %d", bContainerIndex);
		logger->TraceInfo("IN dwFlags: %d , %s", dwFlags, createContainerFlag2String(dwFlags));
		logger->TraceInfo("IN dwKeySpec: %s", keySpec2String(dwKeySpec));
		logger->TraceInfo("IN dwKeySize: %d", dwKeySize);
		logger->TraceInfo("IN pbKeyData");
		logPrivateKeyBlob(pbKeyData);
	}
	if (!createContainerFlag2String(dwFlags)) {
		return SCARD_E_INVALID_PARAMETER;
	}
	if (!keySpec2String(dwKeySpec)) {
		return SCARD_E_INVALID_PARAMETER;
	}
	if (!isValidKeySize(dwKeySize)) {
		return SCARD_E_INVALID_PARAMETER;
	}
	if (SCARD_S_SUCCESS != SCardIsValidContext(pCardData->hSCardCtx)) {
		if (logger) { logger->TraceInfo("CardCreateContainer failed - SCardIsValidContext(%x) fails", pCardData->hSCardCtx); }
		return SCARD_E_INVALID_PARAMETER;
	}

	switch (dwFlags) {
	case CARD_CREATE_CONTAINER_KEY_IMPORT:
		break;
	case CARD_CREATE_CONTAINER_KEY_GEN:
		break;
	}
	//YKPIV_KEY_RETIRED1

	return SCARD_S_SUCCESS;
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
		logger->TraceInfo("\n");
		logger->TraceInfo("#####    CardGetContainerInfo    #####");
		logger->TraceInfo("######################################");
	}
	if (!pCardData) return SCARD_E_INVALID_PARAMETER;
	if (!pContainerInfo) return SCARD_E_INVALID_PARAMETER;
	if (dwFlags) return SCARD_E_INVALID_PARAMETER;
	if (pContainerInfo->dwVersion < 0 || pContainerInfo->dwVersion >  CONTAINER_INFO_CURRENT_VERSION)
		return ERROR_REVISION_MISMATCH;
	if (SCARD_S_SUCCESS != SCardIsValidContext(pCardData->hSCardCtx)) {
		if (logger) { logger->TraceInfo("CardGetContainerInfo failed - SCardIsValidContext(%x) fails", pCardData->hSCardCtx); }
		return SCARD_E_INVALID_PARAMETER;
	}

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
	} else {
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
		logger->TraceInfo("\n");
		logger->TraceInfo("#####    CardDeleteDirectory    #####");
		logger->TraceInfo("#####################################");
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
		logger->TraceInfo("\n");
		logger->TraceInfo("#####    CardCreateFile    #####");
		logger->TraceInfo("################################");
	}
	return SCARD_E_UNSUPPORTED_FEATURE;
} // of CardCreateFile


#if 0
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

	//cardid
	if (strcmp(pszFileName, szCARD_IDENTIFIER_FILE) == 0) {
		// Refer to: https://github.com/OpenSC/OpenSC/blob/master/src/minidriver/opensc-minidriver.inf.in
		const char class_guid[] = {
						0x99, 0x0a, 0x2b, 0xd7, 0xe7, 0x38, 0x46, 0xc7,
						0xb2, 0x6f, 0x1c, 0xf8, 0xfb, 0x9f, 0x13, 0x91 };
		*pcbData = (DWORD)sizeof(class_guid);
		*ppbData = (PBYTE)pCardData->pfnCspAlloc(1 + *pcbData);
		if (!*ppbData) {
			logger->TraceInfo("CardReadFile(szCARD_IDENTIFIER_FILE): SCARD_E_NO_MEMORY");
			return SCARD_E_NO_MEMORY;
		}
		memset(*ppbData, 0, 1 + *pcbData);
		memcpy(*ppbData, class_guid, *pcbData);
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
		memcpy(*ppbData, buf, *pcbData);
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
		memcpy(*ppbData, &cmaprec, *pcbData);
	}
	else {
		logger->TraceInfo("CardReadFile: SCARD_E_FILE_NOT_FOUND");
		dwRet = SCARD_E_FILE_NOT_FOUND;
	}

	if (logger) {
		logger->TraceInfo("*ppbData:");
		logger->PrintBuffer(*ppbData, *pcbData);
		logger->TraceInfo("CardReadFile returns %x", dwRet);
	}
	return dwRet;
}
#else
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
	DWORD			buflen = sizeof(buf)-1;
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
			ykrc = YKPIV_OK;
		}
	}
	//cardid - YKPIV_OBJ_MSMDCARDID
	else if (0 == strcmp(pszFileName, szCARD_IDENTIFIER_FILE)) {
		objID = YKPIV_OBJ_MSMDCARDID;
		// Refer to: https://github.com/OpenSC/OpenSC/blob/master/src/minidriver/opensc-minidriver.inf.in
		const unsigned char class_guid[] = {
			0x99, 0x0a, 0x2b, 0xd7, 0xe7, 0x38, 0x46, 0xc7,
			0xb2, 0x6f, 0x1c, 0xf8, 0xfb, 0x9f, 0x13, 0x91 };
		buflen = sizeof(class_guid);
		memcpy(buf, (DWORD *)&buflen, SZ_MAX_LEN);
		memcpy(&buf[SZ_MAX_LEN], class_guid, buflen);
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
			ykrc = YKPIV_OK;
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
			ykrc = YKPIV_OK;
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
			ykrc = YKPIV_OK;
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
 
	if (logger) {
		logger->TraceInfo("*ppbData:");
		logger->PrintBuffer(*ppbData, *pcbData);
		logger->TraceInfo("CardReadFile returns %x", dwRet);
	}
	return dwRet;
}
#endif


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
#if 1 //verify write
	unsigned char	buf[SZ_MAX_PAGE + SZ_MAX_LEN + 1];
	DWORD			buflen = sizeof(buf)-1;
	memset(buf, 0, sizeof(buf));
	ykrc = ykpiv_fetch_object(&ykState, objID, buf, &buflen);
	if (ykrc != YKPIV_OK) {
		if (logger) { logger->TraceInfo("CardWriteFile failed because ykpiv_fetch_object failed with error: %d", ykrc); }
	} else {
		buflen = *((DWORD *)&buf[0]);
		if (logger) { logger->PrintBuffer(buf, buflen + SZ_MAX_LEN); }
	}
#endif

	if (logger) { logger->TraceInfo("CardWriteFile passed"); }
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
		logger->TraceInfo("\n");
		logger->TraceInfo("#####    CardQueryKeySizes    #####");
		logger->TraceInfo("###################################");
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
		logger->TraceInfo("\n");
		logger->TraceInfo("#####    CardSignData    #####");
		logger->TraceInfo("##############################");
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
		logger->TraceInfo("\n");
		logger->TraceInfo("#####    CardRSADecrypt    #####");
		logger->TraceInfo("################################");
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
		logger->TraceInfo("\n");
		logger->TraceInfo("#####    CardCreateContainerEx    #####");
		logger->TraceInfo("#######################################");
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
				logger->TraceInfo("----- DllMain -----");
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