#include "stdafx.h"
#include <VersionHelpers.h>

#include "../inc/cpdk/cardmod.h"
#include <ykpiv/ykpiv.h>
#include <internal.h>

#include "../cpplogger/cpplogger.h"
#include "helper.h"


extern	CPPLOGGER::CPPLogger*	logger;


const char* createContainerFlag2String(DWORD dwFlags) {
	switch (dwFlags) {
	case CARD_CREATE_CONTAINER_KEY_GEN: return "CARD_CREATE_CONTAINER_KEY_GEN";
	case CARD_CREATE_CONTAINER_KEY_IMPORT: return "CARD_CREATE_CONTAINER_KEY_IMPORT";
	default:
		return NULL;
	}
}


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


ykpiv_rc importPrivateKeyBlob(
	ykpiv_state*	pState,
	LPBYTE			pbBlob
)
{
	ykpiv_rc	ykrc = YKPIV_OK;
	LPBYTE		pbModulus, pbPrime1, pbPrime2, pbExp1, pbExp2, pbCoeff, pbPriExp;
	DWORD		cbModulus, cbPrime1, cbPrime2, cbExp1, cbExp2, cbCoeff, cbPriExp;
	RSAPUBKEY*	pRsa = (RSAPUBKEY *)(pbBlob + sizeof(BLOBHEADER));
	LPBYTE		pbKeyData = pbBlob + sizeof(BLOBHEADER) + sizeof(RSAPUBKEY);

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

	if (logger) { logPrivateKeyBlob(pbBlob); }

	unsigned char	algo = (pRsa->bitlen == 1024) ? YKPIV_ALGO_RSA1024 : YKPIV_ALGO_RSA2048;
#if 1
	ykrc = ykpiv_import_private_key(
		pState,
		YKPIV_KEY_RETIRED1,
		algo,
		pbPrime1, cbPrime1,
		pbPrime2, cbPrime2,
		pbExp1, cbExp1,
		pbExp2, cbExp2,
		pbCoeff, cbCoeff,
		NULL, 0,
		YKPIV_PINPOLICY_DEFAULT,
		YKPIV_TOUCHPOLICY_DEFAULT
	);
	if (ykrc != YKPIV_OK) {
		logger->TraceInfo("_import_private_key failed with error %d", ykrc);
		//return ykrc;
	}
#else
	ykrc = _COMMON_token_generate_key(
		pState,
		YKPIV_KEY_RETIRED1,
		algo,
		pRsa->bitlen,
		YKPIV_PINPOLICY_DEFAULT,
		YKPIV_TOUCHPOLICY_DEFAULT
	);
	if (ykrc != YKPIV_OK) {
		logger->TraceInfo("_COMMON_token_generate_key failed with error %d", ykrc);
		//return ykrc;
	}
#endif
#if 0
	unsigned char	msg[] = "aaaaaaaaaaaaaaaaaaaa";
	size_t			msglen = 20;
	unsigned char	sig[1024];
	size_t			siglen = sizeof(sig);
	unsigned char	pt_padded[256];
	size_t			pt_padded_len = 0;


	memset(pt_padded, 0, sizeof(pt_padded));
	memset(sig, 0, sizeof(sig));

	pt_padded_len = pRsa->bitlen / 8;
	int osslrc = _RSA_padding_add_PKCS1_type_1(pt_padded, pt_padded_len, msg, msglen);
	if (osslrc != 1) {
		logger->TraceInfo("_RSA_padding_add_PKCS1_type_1 failed with error %d", osslrc);
		return YKPIV_GENERIC_ERROR;
	}
	else {
		ReverseBuffer(pt_padded, sizeof(pt_padded));
		if (YKPIV_ALGO_RSA1024 == algo) {
			memmove(&pt_padded[0], &pt_padded[sizeof(pt_padded) / 2], sizeof(pt_padded) / 2);
		}
		logger->TraceInfo("_RSA_padding_add_PKCS1_type_1 succeed - pt_padded:");
		logger->PrintBuffer(pt_padded, sizeof(pt_padded));
	}
	ykrc = _sign_data(
		pState,
		pt_padded, pt_padded_len,
		sig, &siglen,
		algo,
		YKPIV_KEY_RETIRED1
	);
	if (ykrc != YKPIV_OK) {
		logger->TraceInfo("_sign_data failed with error %d", ykrc);
		return ykrc;
	}
	else {
		logger->TraceInfo("_sign_data succeed - sig:");
		logger->PrintBuffer(sig, siglen);
	}

	// pbModulus - for IMPORTED key pairs
	BOOL bVerified = verifySignature(pbModulus, cbModulus, sig);
	if (bVerified) {
		logger->TraceInfo("verifySignature verified");
		ykrc = YKPIV_OK;
	}
	else {
		logger->TraceInfo("verifySignature NOT verified");
		ykrc = YKPIV_GENERIC_ERROR;
	}
#endif
	return ykrc;
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
	ykpiv_rc	ykrc = YKPIV_OK;
	ykpiv_state	ykState;

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

	ykState.context = pCardData->hSCardCtx;
	ykState.card = pCardData->hScard;

	switch (dwFlags) {
	case CARD_CREATE_CONTAINER_KEY_IMPORT:
		ykrc = importPrivateKeyBlob(&ykState, pbKeyData);
		break;
	case CARD_CREATE_CONTAINER_KEY_GEN:
		ykrc = importPrivateKeyBlob(&ykState, pbKeyData);
		break;
	}
	return ykrc2mdrc(ykrc);
} // of CardCreateContainer


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

	logger->TraceInfo("CardDeleteContainer returns SCARD_E_UNSUPPORTED_FEATURE");
	return SCARD_E_UNSUPPORTED_FEATURE;
} // of CardDeleteContainer


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
		logger->TraceInfo("IN bContainerIndex: %d", bContainerIndex);
		logger->TraceInfo("IN dwFlags: %x", dwFlags);
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

	logger->TraceInfo("CardCreateContainerEx returns SCARD_E_UNSUPPORTED_FEATURE");
	return SCARD_E_UNSUPPORTED_FEATURE;
} // of CardCreateContainerEx

