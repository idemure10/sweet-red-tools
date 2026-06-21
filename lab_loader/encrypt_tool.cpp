#include <fstream>
#include <iostream>
#include <Windows.h>
#include <vector>
#include "xor_crypt.h"
int main() {
   std::ifstream inFile;
   inFile.open("C:\\Users\\semoc\\Projects\\sweet_red_things\\lab_loader\\payload.bin");
   if (!inFile.is_open())
      return 1;
   inFile.seekg(0, std::ios::end);
   size_t length = inFile.tellg();
   inFile.seekg(0, std::ios::beg);
   std::vector<char> buffer(length);
   for(int i = 0; i< length; i++)
      inFile.get(buffer[i]);
   inFile.close();
   xor_crypt(buffer.data(), length);
   std::ofstream outFile;
   outFile.open("C:\\Users\\semoc\\Projects\\sweet_red_things\\lab_loader\\payload_enc.bin");
   if (outFile.is_open()) {
      for (int i = 0; i < length; i++)
         outFile.put(buffer[i]);
   }
   outFile.close();
	return 0;
}