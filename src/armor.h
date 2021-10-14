#pragma once
#include "misc.h"
#include <Windows.h>

size_t lookup_funcOrdinal(PCHAR impLib, PCHAR funcName)
{
    auto vaImpTable = getNtHdr(impLib)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    auto expDir = (PIMAGE_EXPORT_DIRECTORY)&impLib[vaImpTable];
    for (size_t funcIndx = expDir->NumberOfNames; funcIndx-- > 0;)
    {
        auto nameArr = (DWORD*)&impLib[expDir->AddressOfNames];
        if (!stricmp(&impLib[nameArr[funcIndx]], funcName))
        {
            auto numOrdinal = PWORD(&impLib[expDir->AddressOfNameOrdinals])[funcIndx] + expDir->Base;
            if (GetProcAddress(HMODULE(impLib), funcName) == GetProcAddress(HMODULE(impLib), PCHAR(numOrdinal)))
                return numOrdinal;
            else
                return 0;
        }
    }
    return 0;
}

bool patch_DynIat(PCHAR dynExeImage)
{
    auto successPatchYet = false;
    auto impLibDesc = (IMAGE_IMPORT_DESCRIPTOR*)(&dynExeImage[getNtHdr(dynExeImage)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress]);
    printf("[v] anti-copy armer enable\n");
    for (PCHAR szImpLib = &dynExeImage[impLibDesc->Name]; impLibDesc->Name; impLibDesc++, szImpLib = &dynExeImage[impLibDesc->Name])
    {
        size_t patchCount = 0;
        auto impLib = PCHAR(LoadLibraryA(szImpLib));
        auto callVia = (IMAGE_THUNK_DATA*)&dynExeImage[impLibDesc->FirstThunk],
            orgThunk = (IMAGE_THUNK_DATA*)(impLibDesc->OriginalFirstThunk ? &dynExeImage[impLibDesc->OriginalFirstThunk] : 0);
        for (int indx = 0; callVia[indx].u1.Function; indx++)
        {
            if (IMAGE_SNAP_BY_ORDINAL32(callVia[indx].u1.Function) || IMAGE_SNAP_BY_ORDINAL64(callVia[indx].u1.Function))
                continue;

            auto impName = (PIMAGE_IMPORT_BY_NAME)&dynExeImage[callVia[indx].u1.Function];
            auto numOrdinal = lookup_funcOrdinal(impLib, impName->Name);
            if (numOrdinal)
            {
                callVia[indx].u1.Ordinal = size_t(numOrdinal | IMAGE_ORDINAL_FLAG32 | IMAGE_ORDINAL_FLAG64);
                if (orgThunk) orgThunk[indx].u1.Ordinal = callVia[indx].u1.Ordinal;

                successPatchYet |= !!(patchCount++);
            }
        }
        if (patchCount)
            printf("\t- patched %i APIs for %s\n", patchCount, szImpLib);
    }
    return successPatchYet;
}

bool unlink(LPCWSTR szTarget) {

    typedef struct _FILE_RENAME_INFORMATION {
        BOOLEAN ReplaceIfExists;
        HANDLE RootDirectory;
        ULONG FileNameLength;
        WCHAR FileName[32];
    } FILE_RENAME_INFORMATION, * PFILE_RENAME_INFORMATION;


    HANDLE fp = CreateFileW(szTarget, DELETE | SYNCHRONIZE | GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
    bool done = (fp > 0);
    FILE_RENAME_INFORMATION renameInformation{ false, 0, 14, 0 };
    swprintf(renameInformation.FileName, L":%x%x\x00", GetTickCount(), GetTickCount());
    done &= SetFileInformationByHandle(fp, FileRenameInfo, &renameInformation, sizeof(renameInformation));
    done &= CloseHandle(fp);

    fp = CreateFileW(szTarget, DELETE | SYNCHRONIZE | GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
    done &= (fp > 0);
    done &= SetFileInformationByHandle(fp, FileDispositionInfo, new FILE_DISPOSITION_INFO{ true }, sizeof(FILE_DISPOSITION_INFO));
    done &= CloseHandle(fp);
    return done;
}



bool armorExe(PCWSTR szTarget) {
    PCHAR exeData, dynExeImage; DWORD exeSize, dynImgSize;

    if (!readBinFile(szTarget, &exeData, exeSize)) die("[x] read data failure.\n");
    if (!dumpMappedImgBin(exeData, dynExeImage, &dynImgSize)) die("\t[x] dump pe image failure.\n");
    if (patch_DynIat(dynExeImage))
        printf("[!] first time running? it's ok! under armer now.\n\n");
    else
        printf("[v] anti-copy armer mode ;)\n\n");
    unlink(szTarget);
 
    auto record = &getSectionArr(dynExeImage)[getNtHdr(dynExeImage)->FileHeader.NumberOfSections - 1];
    if (!stricmp((PCHAR)record->Name, "30cm.tw")) record->NumberOfLinenumbers = 0xDEADBEEF;
    flushImgToExe(szTarget, dynExeImage);
    return true;
}

bool genLauncherExe(PCWSTR szTarget, PCHAR& launcherData, DWORD& launcherSize)
{
    PCHAR loaderData(0), exeData(0); DWORD loaderSize(0), exeSize(0);
    if (!readBinFile(PPEB(__readgsqword(0x60))->ProcessParameters->ImagePathName.Buffer, &loaderData, loaderSize))
        die("[x] read data failure.\n");

    if (!readBinFile(szTarget, &exeData, exeSize)) die("[x] read data failure.\n");

    //
    auto fileAlign = getNtHdr(loaderData)->OptionalHeader.FileAlignment;
    auto sectAlign = getNtHdr(loaderData)->OptionalHeader.SectionAlignment;
    launcherSize = P2ALIGNUP(loaderSize + exeSize, fileAlign);
    launcherData = new char[launcherSize];
    memset(launcherData, '\x00', launcherSize);
    memcpy(launcherData, loaderData, loaderSize);
    
    // fix the last section
    auto sectArr = getSectionArr(launcherData);
    PIMAGE_SECTION_HEADER lastestSecHdr = &sectArr[getNtHdr(launcherData)->FileHeader.NumberOfSections - 1];
    lastestSecHdr->Misc.VirtualSize = P2ALIGNUP(lastestSecHdr->Misc.VirtualSize, sectAlign);


    PIMAGE_SECTION_HEADER newSectionHdr = lastestSecHdr + 1;
    memcpy(newSectionHdr->Name, "30cm.tw", 8);
    newSectionHdr->Misc.VirtualSize = P2ALIGNUP(exeSize, sectAlign);
    newSectionHdr->VirtualAddress = P2ALIGNUP((lastestSecHdr->VirtualAddress + lastestSecHdr->Misc.VirtualSize), sectAlign);
    newSectionHdr->SizeOfRawData = exeSize;
    newSectionHdr->PointerToRawData = lastestSecHdr->PointerToRawData + lastestSecHdr->SizeOfRawData;
    newSectionHdr->Characteristics =  IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    getNtHdr(launcherData)->FileHeader.NumberOfSections += 1;

    // easy encrypt :)
    newSectionHdr->PointerToLinenumbers = GetTickCount(); // decrypt key
    for (size_t indx = 0; indx < exeSize / sizeof(DWORD); indx++)
        PDWORD(exeData)[indx] ^= newSectionHdr->PointerToLinenumbers;
    memset(exeData, '\x00', 0x04);
    memcpy(&launcherData[newSectionHdr->PointerToRawData], exeData, exeSize);

    auto optHdr = &getNtHdr(launcherData)->OptionalHeader;
    optHdr->Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
    optHdr->SizeOfImage =
        getSectionArr(launcherData)[getNtHdr(launcherData)->FileHeader.NumberOfSections - 1].VirtualAddress +
        getSectionArr(launcherData)[getNtHdr(launcherData)->FileHeader.NumberOfSections - 1].Misc.VirtualSize;

    return true;
}