#include <iostream>
#include <Windows.h>
#include "xor_crypt.h"
void xor_crypt(char* pShellcode, size_t length) {
	for (size_t i = 0; i < length; i++) {
		pShellcode[i] = pShellcode[i] ^ xor_key;
	}
}