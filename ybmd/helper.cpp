#include "stdafx.h"
#include "../cpplogger/cpplogger.h"
#include "helper.h"


CPPLOGGER::CPPLogger*		logger = NULL;


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


BOOL shouldSelectApplet(ykpiv_state *state) {
	int tries = 0;
	ykpiv_rc ykrc = ykpiv_verify(state, NULL, &tries);
	if (logger) { logger->TraceInfo("shouldSelectApplet returns ykrc=%d\n", ykrc); }
	return (ykrc != YKPIV_OK);
}


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
	}
	else {
		*sw = 0;
	}
	return YKPIV_OK;
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
	}
	else if (sw == SW_SUCCESS) {
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
		memset(&pSerial[len], ' ', 16 - len);
		return YKPIV_OK;
	}
	else {
		if (logger) { logger->TraceInfo("getSerialNumber: Failed selecting application: %04x\n", sw); }
	}

	return YKPIV_GENERIC_ERROR;
}
