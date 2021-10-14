#include "ntlib/util.h"
#include "misc.h"
#include <intrin.h>
#include <iostream>

#include <Psapi.h>
#include "misc.h"
#include "armor.h"
#include "ghosting.h"
#pragma warning(disable:4996)
using namespace std;

#define die(fmt, ...)               \
	{                               \
		printf(fmt, ##__VA_ARGS__); \
		ExitProcess(-1);            \
	}

void launcherMain(PIMAGE_SECTION_HEADER record) {


    // first time running? self-modify :)
    if (record->NumberOfLinenumbers == 0) armorExe(PPEB(__readgsqword(0x60))->ProcessParameters->ImagePathName.Buffer);

    auto hPipe = CreateNamedPipe(L"\\\\.\\pipe\\my_pipe", PIPE_ACCESS_OUTBOUND, PIPE_TYPE_BYTE, 1, 0, 0, 0, 0);

    // slave mode.
    if (StrStrW(PPEB(__readgsqword(0x60))->ProcessParameters->CommandLine.Buffer, L"slave")) {
        HANDLE pipe = CreateFile(L"\\\\.\\pipe\\my_pipe", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
        char dosHdr[128];
        BOOL result = ReadFile(pipe, dosHdr, sizeof(dosHdr), 0, NULL);

        auto exeData = &PCHAR(GetModuleHandle(0))[record->VirtualAddress];
        for (size_t indx = 0; indx < record->Misc.VirtualSize / sizeof(DWORD); indx++) PDWORD(exeData)[indx] ^= record->PointerToLinenumbers;

        *(DWORD*)exeData = *(DWORD*)dosHdr;
        exeGhosting(L"C:\\Windows\\Explorer.exe", exeData, record->Misc.VirtualSize);
        CloseHandle(hPipe);
    }
    else {
        ShellExecuteW(0, 0, PPEB(__readgsqword(0x60))->ProcessParameters->ImagePathName.Buffer, L"slave", 0, 0);
        ConnectNamedPipe(hPipe, NULL);
        WriteFile(hPipe, "\x4d\x5a\x90\x00", 4, 0, 0);
        CloseHandle(hPipe);
        return;
    }
}
int wmain(int argc, PWCH* argv) {

    // Launcher Main
    auto record = &getSectionArr(GetModuleHandle(0))[getNtHdr(GetModuleHandle(0))->FileHeader.NumberOfSections - 1];
    if (!stricmp((PCHAR)record->Name, "30cm.tw"))
        launcherMain(record);

    if (argc != 3) {
        #pragma region menu
                puts("Skrull 1.0BETA ( github.com/aaaddress1/Skrull )");
                puts("Usage: skrull [option] <exePath>");
                puts("");
                puts("Option");
                puts("       -s, --sign      give the EXE file a Microsoft signature");
                puts("       -b, --build     build a DRM launcher to run EXE file");
                puts("       -a, --armor     armor an EXE file with anti-copy DRM");
                puts("       -u, --unlink    remove EXE files on NTFS, like fileless ;)"); 
        #pragma endregion
        return 0;
    }

    wchar_t szTarget[MAX_PATH]; TCHAR* fileExt;
    GetFullPathNameW(argv[2], sizeof(szTarget) / 2, szTarget, &fileExt);
    

    // unlink mode
    if (0 == lstrcmpiW(argv[1], L"-u")) {
        unlink(PPEB(__readgsqword(0x60))->ProcessParameters->ImagePathName.Buffer);
        unlink(szTarget);
    }

    // mocking signature
    else if (0 == lstrcmpiW(argv[1], L"-s") || 0 == lstrcmpiW(argv[1], L"--sign")) {
        unlink(PPEB(__readgsqword(0x60))->ProcessParameters->ImagePathName.Buffer);
        PCHAR exeData(0); DWORD exeSize(0);
        if (!readBinFile(L"C:/Windows/explorer.exe", &exeData, exeSize))
            die("[x] read data failure.\n");

        unlink(szTarget);
        if (auto fp = _wfopen(szTarget, L"wb"))  {
            fwrite(exeData, 1, exeSize, fp);
            fclose(fp);
        }
    }

    // DRM armor
    else if (0 == lstrcmpiW(argv[1], L"-b") || 0 == lstrcmpiW(argv[1], L"--build")) {
        PCHAR launcherExe; DWORD launcherSize;
        genLauncherExe(szTarget, launcherExe, launcherSize);

        WCHAR launcherPath[MAX_PATH] = { 0 };
        StrCpyW(launcherPath, StrRChrW(szTarget, &szTarget[MAX_PATH], L'\\'));
        StrCpyW(StrRChrW(launcherPath, &launcherPath[MAX_PATH], L'\\'), L"Launcher.exe");

        if (FILE* fp = _wfopen(launcherPath, L"wb")) {
            printf("[+] build launcher sucessful.\n");
            std::wcout << (L"[+] check out ") << launcherPath << " :)" << endl;
            fwrite(launcherExe, 1, launcherSize, fp);
            fclose(fp);
        }

    }

    else if (0 == lstrcmpiW(argv[1], L"-a") || 0 == lstrcmpiW(argv[1], L"--armor")) {
        unlink(PPEB(__readgsqword(0x60))->ProcessParameters->ImagePathName.Buffer);
        armorExe(szTarget);
    }
    else die("[x] undefined behavior?");
    return 0;
}