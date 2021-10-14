#pragma once
#include <windows.h>

bool readBinFile(const wchar_t fileName[], char** bufPtr, DWORD& length)
{
	if (FILE* fp = _wfopen(fileName, L"rb"))
	{
		fseek(fp, 0, SEEK_END);
		length = ftell(fp);
		*bufPtr = new char[length + 1];
		fseek(fp, 0, SEEK_SET);
		fread(*bufPtr, sizeof(char), length, fp);
		fclose(fp);
		return true;
	}
	else
		return false;
}

#define P2ALIGNUP(size, align) (int((float(size) / align) + 0.9) * (align))
#define getNtHdr(buf) ((IMAGE_NT_HEADERS *)((size_t)buf + ((IMAGE_DOS_HEADER *)buf)->e_lfanew))
#define getSectionArr(buf) ((IMAGE_SECTION_HEADER *)((size_t)buf + ((IMAGE_DOS_HEADER *)buf)->e_lfanew + sizeof(IMAGE_NT_HEADERS)))
#define die(fmt, ...)               \
	{                               \
		printf(fmt, ##__VA_ARGS__); \
		ExitProcess(-1);            \
	}

bool dumpMappedImgBin(char* buf, char*& mappedImg, DWORD* imgSize)
{
	PIMAGE_SECTION_HEADER stectionArr = getSectionArr(buf);
	*imgSize = getNtHdr(buf)->OptionalHeader.SizeOfImage;
	mappedImg = new char[*imgSize];
	memset(mappedImg, 0, *imgSize);
	memcpy(mappedImg, buf, getNtHdr(buf)->OptionalHeader.SizeOfHeaders);
	for (size_t i = 0; i < getNtHdr(buf)->FileHeader.NumberOfSections; i++)
		memcpy(&mappedImg[stectionArr[i].VirtualAddress], &buf[stectionArr[i].PointerToRawData], stectionArr[i].SizeOfRawData);
	return true;
}
char* flushImgToExe(LPCWSTR szTarget, char* image) {
	PIMAGE_SECTION_HEADER sArr = getSectionArr(image);
	DWORD exeFileSize =
		sArr[getNtHdr(image)->FileHeader.NumberOfSections - 1].PointerToRawData +
		sArr[getNtHdr(image)->FileHeader.NumberOfSections - 1].SizeOfRawData;
	auto exeFileData = new char[exeFileSize];
	memset(exeFileData, 0, exeFileSize);
	memcpy(exeFileData, image, getNtHdr(image)->OptionalHeader.SizeOfHeaders);
	for (size_t i = 0; i < getNtHdr(image)->FileHeader.NumberOfSections; i++)
		memcpy(&exeFileData[sArr[i].PointerToRawData], &image[sArr[i].VirtualAddress], sArr[i].SizeOfRawData);
	if (FILE* fp = _wfopen(szTarget, L"wb")) {
		fwrite(exeFileData, 1, exeFileSize, fp);
		fclose(fp);
	}
	return exeFileData;
}

