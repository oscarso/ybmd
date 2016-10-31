/*
	These code are always commented out!
	Keeping these code for testing and experiment purpose only.

*/
#if 0
int		ret = 0;
RSA		*r = NULL;
BIGNUM	*bne = NULL;
BIO		*bp_public = NULL;
BIO		*bp_private = NULL;
int				bits = 2048;
unsigned long	e = RSA_F4;
unsigned char	hash[20];
unsigned char	msg[] = "abcd";
unsigned char	msglen = sizeof(msg);
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

ret = RSA_verify(NID_sha1, msg, msglen, sig, siglen, r);
if (ret != 1) {
	return NULL;
}

#define CHREF_ACT_CHANGE_PIN 0
#define CHREF_ACT_UNBLOCK_PIN 1
#define CHREF_ACT_CHANGE_PUK 2

ykpiv_rc _transfer_data(ykpiv_state *state, const unsigned char *templ,
	const unsigned char *in_data, long in_len,
	unsigned char *out_data, unsigned long *out_len, int *sw) {
	const unsigned char *in_ptr = in_data;
	unsigned long max_out = *out_len;
	ykpiv_rc res;
	long rc;
	*out_len = 0;

	logger->TraceInfo("_transfer_data");

	rc = SCardBeginTransaction(state->card);
	if (rc != SCARD_S_SUCCESS) {
		logger->TraceInfo("_transfer_data: SCardBeginTransaction rc=%x", rc);
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

	rc = SCardEndTransaction(state->card, SCARD_LEAVE_CARD);
	if (rc != SCARD_S_SUCCESS) {
		logger->TraceInfo("_transfer_data: error: Failed to end pcsc transaction, rc=%08lx\n", rc);
		return YKPIV_PCSC_ERROR;
	}
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
	}
	else if (action == CHREF_ACT_CHANGE_PUK) {
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
	}
	else if (sw != SW_SUCCESS) {
		if ((sw >> 8) == 0x63) {
			*tries = sw & 0xf;
			return YKPIV_WRONG_PIN;
		}
		else if (sw == SW_ERR_AUTH_BLOCKED) {
			return YKPIV_PIN_LOCKED;
		}
		else {
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
#endif
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

	if (logger) { logger->TraceInfo("verifySignature: r->n = bnn"); }
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
		if (logger) { logger->TraceInfo("verifySignature: RSA_public_decrypt - err=%s", ERR_error_string(ERR_get_error(), NULL)); }
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
#if 0
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
#endif

