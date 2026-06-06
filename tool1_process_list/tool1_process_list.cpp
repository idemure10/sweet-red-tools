#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
int main()
{
   HANDLE hprsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
   PROCESSENTRY32W pidstrct{};
   pidstrct.dwSize = sizeof(pidstrct);
   if(Process32FirstW(hprsnap, &pidstrct))
      wprintf(L"%d  %s\n", pidstrct.th32ProcessID, pidstrct.szExeFile);
   while (Process32NextW(hprsnap, &pidstrct))
      wprintf(L"%d  %s\n", pidstrct.th32ProcessID, pidstrct.szExeFile);
   CloseHandle(hprsnap);
   return 0;
}