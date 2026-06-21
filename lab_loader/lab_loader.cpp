#include <iostream>
#include <Windows.h>
#include "resource.h"
#include "xor_crypt.h"
int main() {
	HRSRC	hrsrc = NULL; 
	HGLOBAL hglobal = NULL;
	PVOID	payloadaddress = NULL;
	SIZE_T payloadsize = NULL;
	hrsrc = FindResourceW(NULL, MAKEINTRESOURCEW(payload_num), RT_RCDATA);
	hglobal = LoadResource(NULL, hrsrc);
	payloadaddress = LockResource(hglobal);
	payloadsize = SizeofResource(NULL, hrsrc);
	PVOID tmpbuffer = HeapAlloc(GetProcessHeap(), 0, payloadsize);
	if (tmpbuffer != NULL) {
		memcpy(tmpbuffer, payloadaddress, payloadsize);
		char* p = (char*)tmpbuffer;
		for (int i = 0; i < payloadsize; i++) {
			std::cout << p[i];
		}
		std::cout << '\n';
		xor_crypt(p, payloadsize);
		for (int i = 0; i < payloadsize; i++) {
			std::cout << p[i];
		}
	}

}
