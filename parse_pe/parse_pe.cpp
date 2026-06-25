#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <Windows.h>

typedef struct table_map {
   const char* name;
   uint8_t num;
} directory_structure;

directory_structure directory_map[] = {
    {"Export", 0}, {"Import", 1}, {".rsrc", 2}, {"Exception", 3}, {"Certificate", 4}, {"Relocations", 5}, {"Debug", 6}, {"(deprecated)", 7},
    {"MIPS", 8}, {"TLS", 9}, {"Load config", 10}, {"Bound import", 11}, {"IAT", 12}, {"Delay import", 13}, {".NET", 14}, {"Reserved", 15}
};

void dos_header_output(const IMAGE_DOS_HEADER* idh)
{
   std::cout << "IMAGE_DOS_HEADER\n\n";
   if (idh->e_magic == IMAGE_DOS_SIGNATURE)
      std::cout << "e_magic: MZ\n";
   else
      std::cout << "invalid e_magic\n";

   std::cout << std::hex << "e_lfanew: 0x" << idh->e_lfanew << "\n\n";
}

void pe_header_output(const IMAGE_FILE_HEADER* ifh)
{
   std::cout << "IMAGE_FILE_HEADER\n\n" << std::hex;
   std::cout << "Machine: 0x" << ifh->Machine << "\n";
   std::cout << "NumberOfSections: 0x" << ifh->NumberOfSections << "\n";
   std::cout << "TimeDateStamp: 0x" << ifh->TimeDateStamp << "\n";
   std::cout << "PointerToSymbolTable: 0x" << ifh->PointerToSymbolTable << "\n";
   std::cout << "NumberOfSymbols: 0x" << ifh->NumberOfSymbols << "\n";
   std::cout << "SizeOfOptionalHeader: 0x" << ifh->SizeOfOptionalHeader << "\n";
   std::cout << "Characteristics: 0x" << ifh->Characteristics << "\n\n";
}

void optional_header_output(const IMAGE_OPTIONAL_HEADER32* ioh)
{
   std::cout << "IMAGE_OPTIONAL_HEADER32\n\n" << std::hex;
   std::cout << "Magic: 0x" << ioh->Magic << "\n";
   std::cout << "AddressOfEntryPoint: 0x" << ioh->AddressOfEntryPoint << "\n";
   std::cout << "ImageBase: 0x" << ioh->ImageBase << "\n";
   std::cout << "SectionAlignment: 0x" << ioh->SectionAlignment << "\n";
   std::cout << "FileAlignment: 0x" << ioh->FileAlignment << "\n";
   std::cout << "SizeOfImage: 0x" << ioh->SizeOfImage << "\n";
   std::cout << "SizeOfHeaders: 0x" << ioh->SizeOfHeaders << "\n";
   std::cout << "Subsystem: 0x" << ioh->Subsystem << "\n\n";
}

void optional_header_output_64(const IMAGE_OPTIONAL_HEADER64* ioh)
{
   std::cout << "IMAGE_OPTIONAL_HEADER64\n\n" << std::hex;
   std::cout << "Magic: 0x" << ioh->Magic << "\n";
   std::cout << "AddressOfEntryPoint: 0x" << ioh->AddressOfEntryPoint << "\n";
   std::cout << "ImageBase: 0x" << ioh->ImageBase << "\n";
   std::cout << "SectionAlignment: 0x" << ioh->SectionAlignment << "\n";
   std::cout << "FileAlignment: 0x" << ioh->FileAlignment << "\n";
   std::cout << "SizeOfImage: 0x" << ioh->SizeOfImage << "\n";
   std::cout << "SizeOfHeaders: 0x" << ioh->SizeOfHeaders << "\n";
   std::cout << "Subsystem: 0x" << ioh->Subsystem << "\n\n";
}

void section_table_output(const IMAGE_SECTION_HEADER* ish, int count)
{
   std::cout << std::dec << "[" << count << "]" << "\t";
   char name[9] = {};
   memcpy(name, ish->Name, IMAGE_SIZEOF_SHORT_NAME);
   std::cout << "Name: " << name << "\n";
   std::cout << std::hex << "\t" << "VirtualAddress: 0x" << ish->VirtualAddress << "\n";
   std::cout << "\t" << "SizeOfRawData: 0x" << ish->SizeOfRawData << "\n";
   std::cout << "\t" << "PointerToRawData: 0x" << ish->PointerToRawData << "\n";
   std::cout << "\t" << "Characteristics: 0x" << ish->Characteristics << "\n\n";
}

void data_directory_output(const IMAGE_DATA_DIRECTORY* dir, int count)
{
   std::cout << std::dec << "[" << count << "]" << "\t";
   std::cout << directory_map[count].name << "\n";
   std::cout << std::hex << "\t" << "RVA: 0x" << dir->VirtualAddress << "\n";
   std::cout << "\t" << "Size: 0x" << dir->Size << "\n\n";
}

DWORD RvaToFileOffset(DWORD rva, const std::vector<IMAGE_SECTION_HEADER>& sections, DWORD sizeOfHeaders)
{
   if (rva < sizeOfHeaders)
      return rva;

   for (const auto& section : sections) {
      DWORD sectionSize = section.Misc.VirtualSize;
      if (sectionSize == 0)
         sectionSize = section.SizeOfRawData;

      if (rva >= section.VirtualAddress && rva < section.VirtualAddress + sectionSize)
         return section.PointerToRawData + (rva - section.VirtualAddress);
   }

   return 0;
}

bool ReadCStringAtOffset(std::ifstream& pe_file, DWORD offset, char* buffer, size_t bufferSize)
{
   pe_file.seekg(offset, std::ios::beg);
   for (size_t i = 0; i < bufferSize - 1; ++i) {
      char ch{};
      pe_file.read(&ch, 1);
      if (!pe_file)
         return false;

      buffer[i] = ch;
      if (ch == '\0')
         return true;
   }

   buffer[bufferSize - 1] = '\0';
   return true;
}

void imports_output(std::ifstream& pe_file, DWORD importRva, const std::vector<IMAGE_SECTION_HEADER>& sections, DWORD sizeOfHeaders, bool pe32)
{
   const DWORD importOffset = RvaToFileOffset(importRva, sections, sizeOfHeaders);

   std::cout << "IMPORTS\n\n" << std::dec;

   for (DWORD i = 0; ; ++i) {
      const DWORD descOffset = importOffset + i * sizeof(IMAGE_IMPORT_DESCRIPTOR);
      pe_file.seekg(descOffset, std::ios::beg);

      IMAGE_IMPORT_DESCRIPTOR iid{};
      pe_file.read(reinterpret_cast<char*>(&iid), sizeof(iid));
      if (!pe_file)
         break;

      if (iid.Name == 0)
         break;

      const DWORD nameOffset = RvaToFileOffset(iid.Name, sections, sizeOfHeaders);
      char dllName[256] = {};
      if (!ReadCStringAtOffset(pe_file, nameOffset, dllName, sizeof(dllName))) {
         std::cerr << "Failed to read DLL name\n";
         continue;
      }

      std::cout << "[" << i << "] " << dllName << "\n";

      const DWORD thunkRva = iid.OriginalFirstThunk ? iid.OriginalFirstThunk : iid.FirstThunk;
      const DWORD thunkOffset = RvaToFileOffset(thunkRva, sections, sizeOfHeaders);
      if (thunkOffset == 0)
         continue;

      for (DWORD j = 0; ; ++j) {
         if (pe32) {
            DWORD thunk{};
            pe_file.seekg(thunkOffset + j * sizeof(DWORD), std::ios::beg);
            pe_file.read(reinterpret_cast<char*>(&thunk), sizeof(thunk));
            if (!pe_file || thunk == 0)
               break;

            if (IMAGE_SNAP_BY_ORDINAL32(thunk)) {
               std::cout << "\tOrdinal: " << IMAGE_ORDINAL32(thunk) << "\n";
               continue;
            }

            const DWORD ibnOffset = RvaToFileOffset(thunk, sections, sizeOfHeaders);
            char funcName[256] = {};
            if (ReadCStringAtOffset(pe_file, ibnOffset + sizeof(WORD), funcName, sizeof(funcName)))
               std::cout << "\t" << funcName << "\n";
         } else {
            ULONGLONG thunk{};
            pe_file.seekg(thunkOffset + j * sizeof(ULONGLONG), std::ios::beg);
            pe_file.read(reinterpret_cast<char*>(&thunk), sizeof(thunk));
            if (!pe_file || thunk == 0)
               break;

            if (IMAGE_SNAP_BY_ORDINAL64(thunk)) {
               std::cout << "\tOrdinal: " << IMAGE_ORDINAL64(thunk) << "\n";
               continue;
            }

            const DWORD ibnOffset = RvaToFileOffset(static_cast<DWORD>(thunk), sections, sizeOfHeaders);
            char funcName[256] = {};
            if (ReadCStringAtOffset(pe_file, ibnOffset + sizeof(WORD), funcName, sizeof(funcName)))
               std::cout << "\t" << funcName << "\n";
         }
      }
   }

   std::cout << "\n";
}

int main(int argc, char* argv[])
{
   char path[255];
   int size = GetModuleFileNameA(NULL, path, sizeof(path));
   for (int i = size - 1; i >= 0; i--) {
      if (path[i] == '\\') {
         path[i + 1] = '\0';
         break;
      }
   }

   std::string inpath;
   if (argc > 1) {
      inpath = argv[1];
   }

   std::ifstream pe_file(inpath, std::ios::binary);
   if (!pe_file) {
      std::cerr << "Cannot open: " << inpath << "\n";
      return 1;
   }

   IMAGE_DOS_HEADER idh{};
   pe_file.read(reinterpret_cast<char*>(&idh), sizeof(idh));
  

   dos_header_output(&idh);

   pe_file.seekg(idh.e_lfanew, std::ios::beg);

   DWORD pe_signature{};
   pe_file.read(reinterpret_cast<char*>(&pe_signature), sizeof(pe_signature));
   

   IMAGE_FILE_HEADER ifh{};
   pe_file.read(reinterpret_cast<char*>(&ifh), sizeof(ifh));

   pe_header_output(&ifh);

   WORD magic{};
   pe_file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
   pe_file.seekg(-static_cast<std::streamoff>(sizeof(magic)), std::ios::cur);
   if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
      IMAGE_OPTIONAL_HEADER32 ioh{};
      pe_file.read(reinterpret_cast<char*>(&ioh), sizeof(ioh));

      optional_header_output(&ioh);

      pe_file.seekg(idh.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + ifh.SizeOfOptionalHeader, std::ios::beg);

      std::cout << "IMAGE_SECTION_HEADER\n\n";

      std::vector<IMAGE_SECTION_HEADER> sections;
      sections.reserve(ifh.NumberOfSections);

      for (int i = 0; i < ifh.NumberOfSections; i++) {
         IMAGE_SECTION_HEADER ish{};
         pe_file.read(reinterpret_cast<char*>(&ish), sizeof(ish));
         sections.push_back(ish);
         section_table_output(&ish, i);
      }

      std::cout << "DATA_DIRECTORY" << "\n\n";
      for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
         const IMAGE_DATA_DIRECTORY& dir = ioh.DataDirectory[i];
         data_directory_output(&dir, i);
      }

      const DWORD importRva = ioh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
      if (importRva != 0) {
         const bool pe32 = (ioh.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC);
         imports_output(pe_file, importRva, sections, ioh.SizeOfHeaders, pe32);
      }
   }
   else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
      IMAGE_OPTIONAL_HEADER64 ioh{};
      pe_file.read(reinterpret_cast<char*>(&ioh), sizeof(ioh));

      optional_header_output_64(&ioh);

      pe_file.seekg(idh.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + ifh.SizeOfOptionalHeader, std::ios::beg);

      std::cout << "IMAGE_SECTION_HEADER\n\n";

      std::vector<IMAGE_SECTION_HEADER> sections;
      sections.reserve(ifh.NumberOfSections);

      for (int i = 0; i < ifh.NumberOfSections; i++) {
         IMAGE_SECTION_HEADER ish{};
         pe_file.read(reinterpret_cast<char*>(&ish), sizeof(ish));
         sections.push_back(ish);
         section_table_output(&ish, i);
      }

      std::cout << "DATA_DIRECTORY" << "\n\n";
      for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
         const IMAGE_DATA_DIRECTORY& dir = ioh.DataDirectory[i];
         data_directory_output(&dir, i);
      }

      const DWORD importRva = ioh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
      if (importRva != 0) {
         const bool pe32 = (ioh.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC);
         imports_output(pe_file, importRva, sections, ioh.SizeOfHeaders, pe32);
      }
   }
 
   
}