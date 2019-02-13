#include <Windows.h>
#include <stdio.h>
#include "CustomWinApi.h"

//////////////////////////////////////////////////////////////////////////////////////////////////
//										Usage examples below
//////////////////////////////////////////////////////////////////////////////////////////////////
int main()
{
	HMODULE hKernel32 = GetModuleA("kernel32");
	printf("hKernel32 = 0x%p\n\n",hKernel32);

	void* FncDeleteFileA = (void*)GetExportAddress( hKernel32, "DeleteFileA", TRUE );
	printf("GetExportAddress( hKernel32, \"DeleteFileA\", TRUE ) => 0x%p\n\n",FncDeleteFileA);

	printf("Function offset: (FncDeleteFileA - hKernel32) => 0x%X\n\n",(BYTE*)FncDeleteFileA - (BYTE*)hKernel32 );

	HANDLE hKernel32File = CreateFileA("c:\\windows\\system32\\kernel32.dll",GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
	ULONG Kernel32FileSize = GetFileSize(hKernel32File, NULL);
	BYTE* Kernel32FileContent = (BYTE*)VirtualAlloc(NULL, Kernel32FileSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	DWORD Kernel32FileNumberOfBytesRead = 0;
	ReadFile(hKernel32File, Kernel32FileContent, Kernel32FileSize, &Kernel32FileNumberOfBytesRead, NULL);
	CloseHandle(hKernel32File);

	printf("Kernel32FileContent => 0x%p\n\n",Kernel32FileContent);

	FncDeleteFileA = (void*)GetExportAddress( (HMODULE)Kernel32FileContent, "DeleteFileA", FALSE );

	printf("DeleteFileA inside Kernel32FileContent => 0x%p\n\n",FncDeleteFileA);

	DWORD DeleteFileA_RVA = ImageVaToRva( Kernel32FileContent, FncDeleteFileA );

	printf("DeleteFileA_RVA => 0x%X {will be same as function offset above ;)}\n\n",DeleteFileA_RVA);

	FncDeleteFileA = (void*)( (BYTE*)hKernel32 + DeleteFileA_RVA );
	printf("hKernel32 + DeleteFileA_RVA => 0x%p\n\n",FncDeleteFileA);

	VirtualFree( Kernel32FileContent, NULL, MEM_RELEASE );

	//can be used to get a function offset of a 32bit dll when currently running as 64bit ;)

	HANDLE h_32Bit_Kernel32File = CreateFileA("c:\\windows\\syswow64\\kernel32.dll",GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
	ULONG _32Bit_Kernel32FileSize = GetFileSize(h_32Bit_Kernel32File, NULL);
	BYTE* _32Bit_Kernel32FileContent = (BYTE*)VirtualAlloc(NULL, _32Bit_Kernel32FileSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	Kernel32FileNumberOfBytesRead = 0;
	ReadFile(h_32Bit_Kernel32File, _32Bit_Kernel32FileContent, _32Bit_Kernel32FileSize, &Kernel32FileNumberOfBytesRead, NULL);
	CloseHandle(h_32Bit_Kernel32File);

	void* _32Bit_FncDeleteFileA = (void*)GetExportAddress( (HMODULE)_32Bit_Kernel32FileContent, "DeleteFileA", FALSE );

	DWORD _32Bit_DeleteFileA_RVA = ImageVaToRva( _32Bit_Kernel32FileContent, _32Bit_FncDeleteFileA );
	printf("32Bit] DeleteFileA_RVA => 0x%X\n\n",_32Bit_DeleteFileA_RVA);

	VirtualFree( _32Bit_Kernel32FileContent, NULL, MEM_RELEASE );

	system("pause");
};
