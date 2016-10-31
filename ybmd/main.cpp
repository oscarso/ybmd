#include "stdafx.h"
#include <stdio.h>
#include <mutex>
#include <VersionHelpers.h>

#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "../inc/cpdk/cardmod.h"
#include <ykpiv/ykpiv.h>
#include <internal.h>

#include "../cpplogger/cpplogger.h"
#include "helper.h"


// OpenSSL defines
#define	RSA_PKCS1_PADDING_SIZE	11

// Global Variables
extern	CPPLOGGER::CPPLogger*	logger;

#define	SZ_MAX_PAGE			2048 //max size in bytes per flash page
#define	SZ_MAX_LEN			sizeof(DWORD) //max size in bytes to store the length of write data
#define	LOG_PATH			"C:\\Logs\\"
HMODULE						g_hDll = 0;


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
const char* cardDirAccessCond2String(const CARD_DIRECTORY_ACCESS_CONDITION cond) {
	switch (cond) {
	case 0: return "InvalidDirAc";
	case 1: return "UserCreateDeleteDirAc";
	case 2: return "AdminCreateDeleteDirAc";
	default: return "UNDEFINED";
	}
}
#if 0
BOOL verifySignature(
	LPBYTE	n,
	DWORD	nlen,
	LPBYTE	sig
)
{
	int				ret = 0;
	unsigned char	pt[256];
	unsigned char	_sig[256];
	RSA				*r = RSA_new();
	BIGNUM			*bne = BN_new();
	BIGNUM			*bnn = BN_new();

	if (logger) { logger->TraceInfo("verifySignature"); }
	ret = BN_set_word(bne, RSA_F4);
	if (ret != 1) {
		return FALSE;
	}

	/*
	ret = RSA_generate_key_ex(r, nlen*8, bne, NULL);
	if (ret != 1) {
		return FALSE;
	}
	memset(_sig, 0, sizeof(_sig));
	ret = RSA_private_encrypt(20, (const unsigned char *)"aaaaaaaaaaaaaaaaaaaa", _sig, r, RSA_PKCS1_PADDING);
	if (logger) { logger->TraceInfo("_sig:"); }
	if (logger) { logger->PrintBuffer(_sig, nlen); }
	if (ret == -1) {
		if (logger) { logger->TraceInfo("verifySignature: RSA_private_encrypt - err=%s", ERR_error_string(ERR_get_error(), NULL));}
		return FALSE;
	}
	memset(pt, 0, sizeof(pt));
	ret = RSA_public_decrypt(nlen, _sig, pt, r, RSA_PKCS1_PADDING);
	if (logger) { logger->TraceInfo("pt:"); }
	if (logger) { logger->PrintBuffer(pt, nlen); }
	if (ret == -1) {
		if (logger) { logger->TraceInfo("verifySignature: RSA_public_decrypt - err=%s", ERR_error_string(ERR_get_error(), NULL));}
		return FALSE;
	}
	*/

	if (logger) { logger->TraceInfo("verifySignature: r->n = bnn");}
	if (logger) { logger->TraceInfo("n (with bnn):"); }
	if (logger) { logger->PrintBuffer(n, nlen); }
	//ReverseBuffer(n, nlen);
	//if (logger) { logger->TraceInfo("n (reversed):"); }
	//if (logger) { logger->PrintBuffer(n, nlen); }
	bnn = BN_bin2bn(n, nlen, bnn);
	if (bnn == NULL) {
		return FALSE;
	}
	r->e = bne;
	r->n = bnn;
	r->d = NULL;
	r->dmp1 = NULL;
	r->dmq1 = NULL;
	r->p = NULL;
	r->q = NULL;
	memset(pt, 0, sizeof(pt));
	ret = RSA_public_decrypt(nlen, sig, pt, r, RSA_NO_PADDING);
	if (logger) { logger->TraceInfo("pt (with bnn):"); }
	if (logger) { logger->PrintBuffer(pt, nlen); }
	if (ret == -1) {
		if (logger) { logger->TraceInfo("verifySignature: RSA_public_decrypt - err=%s", ERR_error_string(ERR_get_error(), NULL));}
		return FALSE;
	}

	return TRUE;
}
RSA* openssl_test(void) {
	int		ret = 0; 
	RSA		*r = NULL;
	BIGNUM	*bne = NULL;
	BIO		*bp_public = NULL;
	BIO		*bp_private = NULL;
	int				bits = 2048;
	unsigned long	e = RSA_F4;
	unsigned char	hash[20];
	unsigned char	msg[] = "abcd";
	unsigned char	msglen = strlen((const char *)msg);
	unsigned char	sig[256];
	unsigned int	siglen = 0;

	bne = BN_new();
	ret = BN_set_word(bne, e);
	if (ret != 1) {
		return NULL;
	}

	r = RSA_new();
	ret = RSA_generate_key_ex(r, bits, bne, NULL);
	if (ret != 1) {
		return NULL;
	}

	if (!SHA1(msg, msglen, hash)) return NULL;
	memset(sig, 0, sizeof(sig));
	ret = RSA_sign(NID_sha1, hash, sizeof(hash), sig, &siglen, r);
	if (ret != 1) {
		return NULL;
	}

	ret = RSA_verify(NID_sha1, hash, sizeof(hash), sig, siglen, r);
	if (ret != 1) {
		return NULL;
	}
	return r;
}
#endif
#endif
#if 1
#if 0
ykpiv_rc _transfer_data(ykpiv_state *state, const unsigned char *templ,
	const unsigned char *in_data, long in_len,
	unsigned char *out_data, unsigned long *out_len, int *sw) {
	const unsigned char *in_ptr = in_data;
	unsigned long max_out = *out_len;
	ykpiv_rc res;
	long rc;
	*out_len = 0;

	if (logger) { logger->TraceInfo("_transfer_data"); }

	rc = SCardBeginTransaction(state->card);
	if (rc != SCARD_S_SUCCESS) {
		if (logger) { logger->TraceInfo("_transfer_data: SCardBeginTransaction rc=%x", rc); }
		return YKPIV_PCSC_ERROR;
	}

	do {
		size_t this_size = 0xff;
		unsigned char data[261];
		unsigned long recv_len = sizeof(data);
		APDU apdu;

		memset(apdu.raw, 0, sizeof(apdu.raw));
		memcpy(apdu.raw, templ, 4);
		if (in_ptr + 0xff < in_data + in_len) {
			apdu.st.cla = 0x10;
		}
		else {
			this_size = (size_t)((in_data + in_len) - in_ptr);
		}
		if (logger) { logger->TraceInfo("Going to send %lu bytes in this go.\n", (unsigned long)this_size); }
		apdu.st.lc = (unsigned char)this_size;
		memcpy(apdu.st.data, in_ptr, this_size);
		res = _send_data(state, &apdu, data, &recv_len, sw);
		if (logger) { logger->TraceInfo("1st _send_data: res=%d , recv_len=%d", res, recv_len); }
		if (res != YKPIV_OK) {
			return res;
		}
		else if (*sw != SW_SUCCESS && *sw >> 8 != 0x61) {
			return YKPIV_OK;
		}
		if (*out_len + recv_len - 2 > max_out) {
			if (logger) { logger->TraceInfo("Output buffer too small, wanted to write %lu, max was %lu.\n", *out_len + recv_len - 2, max_out); }
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

		if (logger) { logger->TraceInfo("The card indicates there is %d bytes more data for us.\n", *sw & 0xff); }

		memset(apdu.raw, 0, sizeof(apdu.raw));
		apdu.st.ins = 0xc0;
		res = _send_data(state, &apdu, data, &recv_len, sw);
		if (logger) { logger->TraceInfo("2nd _send_data: res=%d , recv_len=%d", res, recv_len); }
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
	rc = SCardEndTransaction(state->card, SCARD_LEAVE_CARD);
	if (rc != SCARD_S_SUCCESS) {
		if (logger) { logger->TraceInfo("_transfer_data: error: Failed to end pcsc transaction, rc=%08lx\n", rc); }
		return YKPIV_PCSC_ERROR;
	}
	return YKPIV_OK;
}
#endif
static int get_length(const unsigned char *buffer, size_t *len) {
	if (buffer[0] < 0x81) {
		*len = buffer[0];
		return 1;
	}
	else if ((*buffer & 0x7f) == 1) {
		*len = buffer[1];
		return 2;
	}
	else if ((*buffer & 0x7f) == 2) {
		size_t tmp = buffer[1];
		*len = (tmp << 8) + buffer[2];
		return 3;
	}
	return 0;
}
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

	if (logger) { logger->TraceInfo("_import_private_key"); }

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
static ykpiv_rc _general_authenticate(ykpiv_state *state,
	const unsigned char *sign_in, size_t in_len,
	unsigned char *out, size_t *out_len,
	unsigned char algorithm, unsigned char key, bool decipher) {
	unsigned char indata[1024];
	unsigned char *dataptr = indata;
	unsigned char data[1024];
	unsigned char templ[] = { 0, YKPIV_INS_AUTHENTICATE, algorithm, key };
	unsigned long recv_len = sizeof(data);
	size_t key_len = 0;
	int sw;
	size_t bytes;
	size_t len = 0;
	ykpiv_rc res;

	switch (algorithm) {
	case YKPIV_ALGO_RSA1024:
		key_len = 128;
	case YKPIV_ALGO_RSA2048:
		if (key_len == 0) {
			key_len = 256;
		}
		if (in_len != key_len) {
			return YKPIV_SIZE_ERROR;
		}
		break;
	case YKPIV_ALGO_ECCP256:
		key_len = 32;
	case YKPIV_ALGO_ECCP384:
		if (key_len == 0) {
			key_len = 48;
		}
		if (!decipher && in_len > key_len) {
			return YKPIV_SIZE_ERROR;
		}
		else if (decipher && in_len != (key_len * 2) + 1) {
			return YKPIV_SIZE_ERROR;
		}
		break;
	default:
		return YKPIV_ALGORITHM_ERROR;
	}

	if (in_len < 0x80) {
		bytes = 1;
	}
	else if (in_len < 0xff) {
		bytes = 2;
	}
	else {
		bytes = 3;
	}

	*dataptr++ = 0x7c;
	dataptr += set_length(dataptr, in_len + bytes + 3);
	*dataptr++ = 0x82;
	*dataptr++ = 0x00;
	*dataptr++ = YKPIV_IS_EC(algorithm) && decipher ? 0x85 : 0x81;
	dataptr += set_length(dataptr, in_len);
	memcpy(dataptr, sign_in, (size_t)in_len);
	dataptr += in_len;

	if ((res = ykpiv_transfer_data(state, templ, indata, dataptr - indata, data,
		&recv_len, &sw)) != YKPIV_OK) {
		if (state->verbose) {
			fprintf(stderr, "Sign command failed to communicate.\n");
		}
		return res;
	}
	else if (sw != SW_SUCCESS) {
		if (state->verbose) {
			fprintf(stderr, "Failed sign command with code %x.\n", sw);
		}
		if (sw == SW_ERR_SECURITY_STATUS)
			return YKPIV_AUTHENTICATION_ERROR;
		else
			return YKPIV_GENERIC_ERROR;
	}
	/* skip the first 7c tag */
	if (data[0] != 0x7c) {
		if (state->verbose) {
			fprintf(stderr, "Failed parsing signature reply.\n");
		}
		return YKPIV_PARSE_ERROR;
	}
	dataptr = data + 1;
	dataptr += get_length(dataptr, &len);
	/* skip the 82 tag */
	if (*dataptr != 0x82) {
		if (state->verbose) {
			fprintf(stderr, "Failed parsing signature reply.\n");
		}
		return YKPIV_PARSE_ERROR;
	}
	dataptr++;
	dataptr += get_length(dataptr, &len);
	if (len > *out_len) {
		if (state->verbose) {
			fprintf(stderr, "Wrong size on output buffer.\n");
		}
		return YKPIV_SIZE_ERROR;
	}
	*out_len = len;
	memcpy(out, dataptr, len);
	return YKPIV_OK;
}
ykpiv_rc _sign_data(ykpiv_state *state,
	const unsigned char *raw_in, size_t in_len,
	unsigned char *sign_out, size_t *out_len,
	unsigned char algorithm, unsigned char key) {

	if (logger) { logger->TraceInfo("_sign_data"); }
	return _general_authenticate(state, raw_in, in_len, sign_out, out_len,
		algorithm, key, false);
}
ykpiv_rc _decipher_data(ykpiv_state *state, const unsigned char *in,
	size_t in_len, unsigned char *out, size_t *out_len,
	unsigned char algorithm, unsigned char key) {

	if (logger) { logger->TraceInfo("_decipher_data"); }
	return _general_authenticate(state, in, in_len, out, out_len,
		algorithm, key, true);
}
static ykpiv_rc _COMMON_token_generate_key(
				ykpiv_state*		state,
				const unsigned char key,
				const unsigned char algorithm,
				const size_t		key_len,
				const unsigned char pin_policy,
				const unsigned char touch_policy
)
{
	// TODO: make a function in ykpiv for this
	unsigned char in_data[11];
	unsigned char *in_ptr = in_data;
	unsigned char data[1024];
	unsigned char templ[] = { 0, YKPIV_INS_GENERATE_ASYMMETRIC, 0, 0 };
	unsigned char *certptr;
	unsigned long recv_len = sizeof(data);
	int len_bytes;
	int sw;

	ykpiv_rc	ykrv = YKPIV_OK;

	if (logger) { logger->TraceInfo("_COMMON_token_generate_key"); }

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

	templ[3] = key;

	*in_ptr++ = 0xac;
	*in_ptr++ = 3;
	*in_ptr++ = YKPIV_ALGO_TAG;
	*in_ptr++ = 1;

	switch (key_len) {
	case 2048:
		if (YKPIV_ALGO_RSA2048 == algorithm)
			*in_ptr++ = YKPIV_ALGO_RSA2048;
		else
			return YKPIV_GENERIC_ERROR;

		break;

	case 1024:
		if (YKPIV_ALGO_RSA1024 == algorithm)
			*in_ptr++ = YKPIV_ALGO_RSA1024;
		else
			return YKPIV_GENERIC_ERROR;

		break;

	default:
		return YKPIV_GENERIC_ERROR;
	}

	// PIN policy and touch
	if (YKPIV_PINPOLICY_DEFAULT != pin_policy) {
		in_data[1] += 3;
		*in_ptr++ = YKPIV_PINPOLICY_TAG;
		*in_ptr++ = 0x01;
		*in_ptr++ = pin_policy;
	}

	if (YKPIV_TOUCHPOLICY_DEFAULT != touch_policy) {
		in_data[1] += 3;
		*in_ptr++ = YKPIV_TOUCHPOLICY_TAG;
		*in_ptr++ = 0x01;
		*in_ptr++ = touch_policy;
	}

	if (ykpiv_transfer_data(state, templ, in_data, in_ptr - in_data, data, &recv_len, &sw) != YKPIV_OK ||
		sw != 0x9000)
		return YKPIV_GENERIC_ERROR;

/*
	// Create a new empty certificate for the key
	recv_len = sizeof(data);
	if ((rv = do_create_empty_cert(data, recv_len, rsa, data, &recv_len)) != CKR_OK)
		return rv;

	if (recv_len < 0x80)
		len_bytes = 1;
	else if (recv_len < 0xff)
		len_bytes = 2;
	else
		len_bytes = 3;

	certptr = data;
	memmove(data + len_bytes + 1, data, recv_len);

	*certptr++ = 0x70;
	certptr += set_length(certptr, recv_len);
	certptr += recv_len;
	*certptr++ = 0x71;
	*certptr++ = 1;
	*certptr++ = 0;
	*certptr++ = 0xfe;
	*certptr++ = 0;

	// Store the certificate into the token
	if (ykpiv_save_object(state, key_to_object_id(key), data, (size_t)(certptr - data)) != YKPIV_OK)
		return CKR_DEVICE_ERROR;
*/
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







int getRetryCount(ykpiv_state *state) {
	int tries = 0;
	ykpiv_rc ykrc = ykpiv_verify(state, NULL, &tries);
	if (YKPIV_OK == ykrc) {
		return tries;
	}
	return -1;
}


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
int _RSA_padding_add_PKCS1_type_1(
		unsigned char *to,
		int tlen,
		const unsigned char *from,
		int flen
)
{
	int j;
	unsigned char *p;

	if (flen > (tlen - RSA_PKCS1_PADDING_SIZE)) {
		logger->TraceInfo("_RSA_padding_add_PKCS1_type_1: size error");
		return (0);
	}

	p = (unsigned char *)to;

	*(p++) = 0;
	*(p++) = 1;	/* Private Key BT (Block Type) */

	/* pad out with 0xff data */
	j = tlen - 3 - flen;
	memset(p, 0xff, j);
	p += j;
	*(p++) = '\0';
	memcpy(p, from, (unsigned int)flen);
	return (1);
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
	ykrc = _import_private_key(
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

	pt_padded_len = pRsa->bitlen/8;
	int osslrc = _RSA_padding_add_PKCS1_type_1(pt_padded, pt_padded_len, msg, msglen);
	if (osslrc != 1) {
		logger->TraceInfo("_RSA_padding_add_PKCS1_type_1 failed with error %d", osslrc);
		return YKPIV_GENERIC_ERROR;
	} else {
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
	} else {
		logger->TraceInfo("_sign_data succeed - sig:");
		logger->PrintBuffer(sig, siglen);
	}

	// pbModulus - for IMPORTED key pairs
	BOOL bVerified = verifySignature(pbModulus, cbModulus, sig);
	if (bVerified) {
		logger->TraceInfo("verifySignature verified");
		ykrc = YKPIV_OK;
	} else {
		logger->TraceInfo("verifySignature NOT verified");
		ykrc = YKPIV_GENERIC_ERROR;
	}
#endif
	return ykrc;
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

	logger->TraceInfo("CardCreateContainerEx returns SCARD_E_UNSUPPORTED_FEATURE");
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