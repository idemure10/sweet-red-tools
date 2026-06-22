#include <fstream>
#include <iostream>
#include <Windows.h>
#include <vector>
#include "xor_crypt.h"
int main() {
   std::ifstream inFile;
   char path[255];
   int size = GetModuleFileNameA(NULL, path, sizeof(path));
   for (int i = size - 1; i >= 0; i--) {
      if (path[i] == '\\') {
         path[i + 1] = '\0';
         break;
      }
   }
   std::string inpath = (std::string)path + "payload.bin";
   inFile.open(inpath);
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
   std::string outpath = (std::string)path + "payload_enc.bin";
   outFile.open(outpath);
   if (outFile.is_open()) {
      for (int i = 0; i < length; i++)
         outFile.put(buffer[i]);
   }
   outFile.close();
	return 0;
}