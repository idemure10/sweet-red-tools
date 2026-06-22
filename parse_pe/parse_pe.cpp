#include <iostream>
#include <fstream>
#include <Windows.h>

void dos_header_output(const IMAGE_DOS_HEADER* idh)
{
   if (idh->e_magic == IMAGE_DOS_SIGNATURE)
      std::cout << "e_magic: MZ\n";
   else
      std::cout << "invalid e_magic" <<  "\n";

   std::cout << "e_lfanew: 0x" << std::hex << idh->e_lfanew << "\n";
}

int main()
{
   char path[255];
   int size = GetModuleFileNameA(NULL, path, sizeof(path));
   for (int i = size - 1; i >= 0; i--) {
      if (path[i] == '\\') {
         path[i + 1] = '\0';
         break;
      }
   }

   const std::string inpath = std::string(path) + "g5_s03.exe";
   std::ifstream pe_file(inpath, std::ios::binary);
   if (!pe_file) {
      std::cerr << "Cannot open: " << inpath << "\n";
      return 1;
   }

   IMAGE_DOS_HEADER idh{};
   pe_file.read(reinterpret_cast<char*>(&idh), sizeof(idh));
   if (!pe_file) {
      std::cerr << "Failed to read DOS header\n";
      return 1;
   }

   dos_header_output(&idh);
   pe_file.seekg(idh.e_lfanew);
}
