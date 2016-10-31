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