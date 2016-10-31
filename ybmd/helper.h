#include "../inc/cpdk/cardmod.h"
#include <ykpiv/ykpiv.h>
#include <internal.h>


//CPPLOGGER::CPPLogger*	logger = NULL;


ykpiv_rc	_send_data(ykpiv_state *state, APDU *apdu, unsigned char *data, unsigned long *recv_len, int *sw);

ykpiv_rc	selectApplet(ykpiv_state *state);
ykpiv_rc	selectAppletYubiKey(ykpiv_state *state);
BOOL		shouldSelectApplet(ykpiv_state *state);
ykpiv_rc	getSerialNumber(ykpiv_state *state, char* pSerial);
