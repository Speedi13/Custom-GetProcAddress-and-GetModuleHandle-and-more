#include <Windows.h>
#include <malloc.h>
#include "CustomWinApi.h"

//////////////////////////////////////////////////////////////////////////////////////////////////
//		Equivalent to the windows api function GetModuleHandleA and GetModuleHandleW
//////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>
/// Retrieves the address of an loaded module by name
/// </summary>
/// <param name="lpModuleName">name of the module, zero for current module</param>
/// <returns>returns address of the module in memory</returns>
HMODULE WINAPI GetModuleW( _In_opt_ LPCWSTR lpModuleName )
{
	struct CLIENT_ID
	{
		HANDLE UniqueProcess;
		HANDLE UniqueThread;
	};

	//https://processhacker.sourceforge.io/doc/ntpebteb_8h_source.html#l00166
	struct TEB
	{
		NT_TIB NtTib;
		PVOID EnvironmentPointer;
		CLIENT_ID ClientId;
		PVOID ActiveRpcHandle;
		PVOID ThreadLocalStoragePointer;
		struct PEB* ProcessEnvironmentBlock;
		//...
	};

	//https://processhacker.sourceforge.io/doc/ntpsapi_8h_source.html#l00063
	struct PEB_LDR_DATA
	{
		ULONG Length;
		BOOLEAN Initialized;
		HANDLE SsHandle;
		LIST_ENTRY InLoadOrderModuleList;
		LIST_ENTRY InMemoryOrderModuleList;
		LIST_ENTRY InInitializationOrderModuleList;
		PVOID EntryInProgress;
		BOOLEAN ShutdownInProgress;
		HANDLE ShutdownThreadId;
	};
	//https://processhacker.sourceforge.io/doc/ntpebteb_8h_source.html#l00008
	struct PEB
	{
		BOOLEAN InheritedAddressSpace;
		BOOLEAN ReadImageFileExecOptions;
		BOOLEAN BeingDebugged;
		union
		{
			BOOLEAN BitField;
			struct
			{
				BOOLEAN ImageUsesLargePages : 1;
				BOOLEAN IsProtectedProcess : 1;
				BOOLEAN IsImageDynamicallyRelocated : 1;
				BOOLEAN SkipPatchingUser32Forwarders : 1;
				BOOLEAN IsPackagedProcess : 1;
				BOOLEAN IsAppContainer : 1;
				BOOLEAN IsProtectedProcessLight : 1;
				BOOLEAN SpareBits : 1;
			};
		};
		HANDLE Mutant;
		PVOID ImageBaseAddress;
		PEB_LDR_DATA* Ldr;
		//...
	};
	struct UNICODE_STRING
	{
		USHORT Length;
		USHORT MaximumLength;
		PWCH Buffer;
	};
	//https://processhacker.sourceforge.io/doc/ntldr_8h_source.html#l00102
	struct LDR_DATA_TABLE_ENTRY
	{
		LIST_ENTRY InLoadOrderLinks;
		LIST_ENTRY InMemoryOrderLinks;
		union
		{
			LIST_ENTRY InInitializationOrderLinks;
			LIST_ENTRY InProgressLinks;
		};
		PVOID DllBase;
		PVOID EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
		//...
	};

	PEB* ProcessEnvironmentBlock = ((PEB*)((TEB*)((TEB*)NtCurrentTeb())->ProcessEnvironmentBlock));
	if (lpModuleName == nullptr) 
		return (HMODULE)( ProcessEnvironmentBlock->ImageBaseAddress );

	PEB_LDR_DATA* Ldr = ProcessEnvironmentBlock->Ldr;

	LIST_ENTRY* ModuleLists[3] = {0,0,0};
	ModuleLists[0] = &Ldr->InLoadOrderModuleList;
	ModuleLists[1] = &Ldr->InMemoryOrderModuleList;
	ModuleLists[2] = &Ldr->InInitializationOrderModuleList;
	for (int j = 0; j < 3; j++)
	{
		for (LIST_ENTRY*  pListEntry  = ModuleLists[j]->Flink;
						  pListEntry != ModuleLists[j];
						  pListEntry  = pListEntry->Flink)
		{
			LDR_DATA_TABLE_ENTRY* pEntry = (LDR_DATA_TABLE_ENTRY*)( (BYTE*)pListEntry - sizeof(LIST_ENTRY) * j ); //= CONTAINING_RECORD( pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks );

			if (_wcsicmp( pEntry->BaseDllName.Buffer, lpModuleName ) == 0)
				return (HMODULE)pEntry->DllBase;

			wchar_t* FileName = GetFileNameFromPath(pEntry->FullDllName.Buffer);
			if (!FileName)
				continue;

			if (_wcsicmp( FileName, lpModuleName ) == 0)
				return (HMODULE)pEntry->DllBase;

			wchar_t FileNameWithoutExtension[256];
			RemoveFileExtension( FileName, FileNameWithoutExtension, 256 );

			if (_wcsicmp( FileNameWithoutExtension, lpModuleName ) == 0)
				return (HMODULE)pEntry->DllBase;
		}
	}
	return nullptr;
}

/// <summary>
/// Retrieves the address of an loaded module by name
/// </summary>
/// <param name="lpModuleName">name of the module, zero for current module</param>
/// <returns>returns address of the module in memory</returns>
HMODULE WINAPI GetModuleA( _In_opt_ LPCSTR lpModuleName )
{
	if (!lpModuleName) return GetModuleW( NULL );

	DWORD ModuleNameLength = (DWORD)strlen( lpModuleName ) + 1;

	//allocate buffer for the string on the stack:
	DWORD NewBufferSize = sizeof(wchar_t) * ModuleNameLength;
	wchar_t* W_ModuleName = (wchar_t*)alloca( NewBufferSize );
	for (DWORD i = 0; i < ModuleNameLength; i++)
		W_ModuleName[i] = lpModuleName[i];

	HMODULE hReturnModule =  GetModuleW( W_ModuleName );

	RtlSecureZeroMemory( W_ModuleName, NewBufferSize );

	return hReturnModule;
}

//////////////////////////////////////////////////////////////////////////////////////////////////
//					Equivalent to the windows api function GetProcAddress
//////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>
/// Retrieves the address of an exported function inside the specified module
/// </summary>
/// <param name="hModule">Address of the module</param>
/// <param name="lpProcName">Name of the exported procedure</param>
/// <param name="MappedAsImage">Is the module mapped or a raw file? (TRUE / FALSE)</param>
/// <returns>returns the exported procedure address inside the specified module</returns>
FARPROC WINAPI GetExportAddress( _In_ HMODULE hModule, _In_ LPCSTR lpProcName, _In_ BOOLEAN MappedAsImage )
{
	if (lpProcName == NULL)
		return nullptr;

	unsigned short ProcOrdinal = 0xFFFF;
	if ( (ULONG_PTR)lpProcName < 0xFFFF )
		ProcOrdinal = (ULONG_PTR)lpProcName & 0xFFFF;
	else
	{
		//in case of "#123" resolve the ordinal to 123
		if ( lpProcName[0] == '#' )
		{
			DWORD OrdinalFromString = atoi( lpProcName + 1 );
			if ( OrdinalFromString < 0xFFFF &&
				 OrdinalFromString != 0 )
			{
				ProcOrdinal = OrdinalFromString & 0xFFFF;
				lpProcName = (LPCSTR)( ProcOrdinal );
			}
		}
	}
	IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)hModule;
	if ( !DosHeader || DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return nullptr;

	//only OptionalHeader is different between 64bit and 32bit so try not to touch it!
	IMAGE_NT_HEADERS* NtHeader = (IMAGE_NT_HEADERS*)( (DWORD_PTR)DosHeader + DosHeader->e_lfanew );
	if ( NtHeader->Signature != IMAGE_NT_SIGNATURE )
		return nullptr;

	ULONG ExportDirectorySize = NULL;
	IMAGE_EXPORT_DIRECTORY* ExportDirectory = (IMAGE_EXPORT_DIRECTORY*)ImageDirectoryEntryToDataEx( DosHeader, MappedAsImage, IMAGE_DIRECTORY_ENTRY_EXPORT, &ExportDirectorySize );
	if ( !ExportDirectory || !ExportDirectorySize )
		return nullptr;

	//check if any export functions are present
	if ( !ExportDirectory->NumberOfFunctions )
		return nullptr;

	//from BlackBone
	//https://github.com/DarthTon/Blackbone/blob/3dc33d815011b83855af607013d34c836b9d0877/src/BlackBone/Process/ProcessModules.cpp#L266
	// Fix invalid directory size
	if (ExportDirectorySize <= sizeof( IMAGE_EXPORT_DIRECTORY ))
	{
		// New size should take care of max number of present names (max name length is assumed to be 255 chars)
		ExportDirectorySize = static_cast<DWORD>( ExportDirectory->AddressOfNameOrdinals - (DWORD)( (BYTE*)(ExportDirectory) - (BYTE*)(DosHeader) )
												  + max( ExportDirectory->NumberOfFunctions, ExportDirectory->NumberOfNames ) * 255 );
	}

	DWORD AddressOfNamesRVA			= ExportDirectory->AddressOfNames;
	DWORD AddressOfFunctionsRVA		= ExportDirectory->AddressOfFunctions;
	DWORD AddressOfNameOrdinalsRVA	= ExportDirectory->AddressOfNameOrdinals;

	DWORD* ExportNames	= (DWORD*)( MappedAsImage ? ((BYTE*)DosHeader + AddressOfNamesRVA			) : ImageRvaToVa( NtHeader, DosHeader, AddressOfNamesRVA		) );
	DWORD* Functions	= (DWORD*)( MappedAsImage ? ((BYTE*)DosHeader + AddressOfFunctionsRVA		) : ImageRvaToVa( NtHeader, DosHeader, AddressOfFunctionsRVA	) );
	WORD*  Ordinals		= (WORD *)( MappedAsImage ? ((BYTE*)DosHeader + AddressOfNameOrdinalsRVA	) : ImageRvaToVa( NtHeader, DosHeader, AddressOfNameOrdinalsRVA	) );
	
	for (DWORD i = 0; i < ExportDirectory->NumberOfFunctions; i++)
	{
		unsigned short OrdinalIndex = Ordinals[i];

		DWORD ExportFncOffset = Functions[OrdinalIndex];
		if ( !ExportFncOffset )
			continue;

		char* ProcNamePtr = (char*)( MappedAsImage ? ((char*)DosHeader + ExportNames[i])  : ImageRvaToVa( NtHeader, DosHeader, ExportNames[i]  ) );
		BYTE* ExportFnc	  = (BYTE*)( MappedAsImage ? ((BYTE*)DosHeader + ExportFncOffset) : ImageRvaToVa( NtHeader, DosHeader, ExportFncOffset ) );

		//Forwarded exports:
		if ( MappedAsImage &&	//Not supported on images that are not mapped
								//Not supported with ordinals for forwarded export by name
			//Check for forwarded export:
			ExportFnc > ((BYTE*)ExportDirectory) && 
			ExportFnc < ((BYTE*)ExportDirectory + ExportDirectorySize))
		{
			//for example inside the Kernelbase.dll's export table
			//NTDLL.RtlDecodePointer
			//It could also forward an ordinal
			//NTDLL.#123
			char* ForwardedString = (char*)ExportFnc;
			DWORD ForwardedStringLen = (DWORD)strlen( ForwardedString )+1;
			if ( ForwardedStringLen >= 256 )
				continue;
			 char szForwardedLibraryName[256];
			memcpy( szForwardedLibraryName, ForwardedString, ForwardedStringLen );
			char* ForwardedFunctionName = NULL;
			char* ForwardedFunctionOrdinal = NULL;
			for (DWORD s = 0; s < ForwardedStringLen; s++)
			{
				if (szForwardedLibraryName[s] == '.')
				{
					szForwardedLibraryName[s] = NULL;
					ForwardedFunctionName = &ForwardedString[s+1];
					break;
				}
			}

			//forwarded by ordinal
			if ( ForwardedFunctionName != nullptr && ForwardedFunctionName[0] == '#' )
			{
				ForwardedFunctionOrdinal = ForwardedFunctionName + 1;
				ForwardedFunctionName = NULL;
			}
			if ( ForwardedFunctionName )
			{
				if ( strcmp( lpProcName, ForwardedFunctionName) != NULL )
					continue;

				HMODULE hForwardedDll = LoadLibraryA( szForwardedLibraryName );
				FARPROC ForwardedFunction = (FARPROC)GetExportAddress( hForwardedDll, ForwardedFunctionName, MappedAsImage );
				return (FARPROC)ForwardedFunction;
			}
			else
			if ( ForwardedFunctionOrdinal && ProcOrdinal < 0xFFFF )
			{
				DWORD ForwardedOrdinal = atoi( ForwardedFunctionOrdinal );
				if ( ForwardedOrdinal > 0xFFFF || 
					 ForwardedOrdinal == 0 ||
					 ForwardedOrdinal != ProcOrdinal ) 
					continue;
				
				HMODULE hForwardedDll = LoadLibraryA( szForwardedLibraryName );
				FARPROC ForwardedFunction = (FARPROC)GetExportAddress( hForwardedDll, (char*)(ForwardedOrdinal&0xFFFF), MappedAsImage );
				return (FARPROC)ForwardedFunction;
			}
			else
				continue;
		}
		
		if ( (ULONG_PTR)lpProcName > 0xFFFF && strcmp( lpProcName, ProcNamePtr) == NULL )
			return (FARPROC)ExportFnc;
		else
		{
			if ( (OrdinalIndex+1) == ProcOrdinal )
				return (FARPROC)ExportFnc;
		}
	}
	return nullptr;
}


//////////////////////////////////////////////////////////////////////////////////////////////////
//			Equivalent to the windows api function ImageDirectoryEntryToDataEx
//////////////////////////////////////////////////////////////////////////////////////////////////
PVOID WINAPI ImageDirectoryEntryToDataInternal( PVOID Base, BOOLEAN MappedAsImage, ULONG* Size, DWORD SizeOfHeaders, IMAGE_DATA_DIRECTORY* DataDirectory, IMAGE_FILE_HEADER *ImageFileHeader, void* ImageOptionalHeader )
{
	*(ULONG*)Size = NULL;

	if ( !DataDirectory->VirtualAddress || !DataDirectory->Size || !SizeOfHeaders )
		return nullptr;

	*(ULONG*)Size = DataDirectory->Size;
	if ( MappedAsImage || DataDirectory->VirtualAddress < SizeOfHeaders )
		return (char *)Base + DataDirectory->VirtualAddress;

	WORD SizeOfOptionalHeader = ImageFileHeader->SizeOfOptionalHeader;
	WORD NumberOfSections = ImageFileHeader->NumberOfSections;
	if ( !NumberOfSections || !SizeOfOptionalHeader )
		return nullptr;

	IMAGE_SECTION_HEADER* pSectionHeaders = (IMAGE_SECTION_HEADER*)( (BYTE*)ImageOptionalHeader + SizeOfOptionalHeader );
	for (DWORD i = 0; i < NumberOfSections; i++)
	{
		IMAGE_SECTION_HEADER* pSectionHeader = &pSectionHeaders[i];
		if ( (DataDirectory->VirtualAddress >= pSectionHeader->VirtualAddress) && 
			 (DataDirectory->VirtualAddress < (pSectionHeader->SizeOfRawData + pSectionHeader->VirtualAddress)) )
		{
			return (char *)Base + (DataDirectory->VirtualAddress - pSectionHeader->VirtualAddress) + pSectionHeader->PointerToRawData;
		}
	}
	return nullptr;
}
PVOID WINAPI ImageDirectoryEntryToData32(PVOID Base, BOOLEAN MappedAsImage, USHORT DirectoryEntry, ULONG* Size, IMAGE_FILE_HEADER *ImageFileHeader, IMAGE_OPTIONAL_HEADER32 *ImageOptionalHeader)
{
	*(ULONG*)Size = NULL;

	if ( DirectoryEntry >= ImageOptionalHeader->NumberOfRvaAndSizes )
		return nullptr;

	IMAGE_DATA_DIRECTORY* DataDirectory = &ImageOptionalHeader->DataDirectory[DirectoryEntry];
	if ( !DataDirectory->VirtualAddress || !DataDirectory->Size )
		return nullptr;

	return ImageDirectoryEntryToDataInternal(	Base, 
												MappedAsImage, 
												Size, 
												ImageOptionalHeader->SizeOfHeaders, 
												DataDirectory, 
												ImageFileHeader, 
												ImageOptionalHeader );
}
PVOID WINAPI ImageDirectoryEntryToData64(PVOID Base, BOOLEAN MappedAsImage, USHORT DirectoryEntry, ULONG* Size, IMAGE_FILE_HEADER *ImageFileHeader, IMAGE_OPTIONAL_HEADER64 *ImageOptionalHeader)
{
	*(ULONG*)Size = NULL;

	if ( DirectoryEntry >= ImageOptionalHeader->NumberOfRvaAndSizes )
		return nullptr;

	IMAGE_DATA_DIRECTORY* DataDirectory = &ImageOptionalHeader->DataDirectory[DirectoryEntry];
	if ( !DataDirectory->VirtualAddress || !DataDirectory->Size )
		return nullptr;

	return ImageDirectoryEntryToDataInternal(	Base, 
												MappedAsImage, 
												Size, 
												ImageOptionalHeader->SizeOfHeaders, 
												DataDirectory, 
												ImageFileHeader, 
												ImageOptionalHeader );
}
PVOID WINAPI ImageDirectoryEntryToDataRom(PVOID Base, WORD HeaderMagic, USHORT DirectoryEntry, ULONG* Size, IMAGE_FILE_HEADER *ImageFileHeader, IMAGE_ROM_OPTIONAL_HEADER *ImageRomHeaders)
{
	*(ULONG*)Size = NULL;

	if ( ImageFileHeader->NumberOfSections <= 0u || !ImageFileHeader->SizeOfOptionalHeader )
		return nullptr;

	IMAGE_SECTION_HEADER* pSectionHeader = (IMAGE_SECTION_HEADER*)( (BYTE*)ImageRomHeaders + ImageFileHeader->SizeOfOptionalHeader );

	WORD j = 0;
	for ( ; j < ImageFileHeader->NumberOfSections; j++, pSectionHeader++)
	{
		if ( DirectoryEntry == 3 && _stricmp((char *)pSectionHeader->Name, ".pdata") == NULL )
			break;
		if ( DirectoryEntry == 6 && _stricmp((char *)pSectionHeader->Name, ".rdata") == NULL )
		{
			*(ULONG*)Size = NULL;
			for ( BYTE* i = (BYTE *)Base + pSectionHeader->PointerToRawData + 0xC; *(DWORD *)i; i += 0x1C )
				*Size += 0x1C;
			break;
		}
	}
	if ( j >= ImageFileHeader->NumberOfSections )
		return nullptr;	

	return (char *)Base + pSectionHeader->PointerToRawData;
}

/// <summary>
/// Locates a directory entry within the image header and returns the address of the data for the directory entry
/// </summary>
/// <param name="Base">The base address of the image or data file</param>
/// <param name="MappedAsImage">If the flag is TRUE, the file is mapped by the system as an image. If this flag is FALSE, the file is mapped as a data file by the MapViewOfFile / ReadFile function</param>
/// <param name="DirectoryEntry">The directory entry to be located</param>
/// <param name="Size">A pointer to a variable that receives the size of the data for the directory entry that is located</param>
/// <returns>If the function succeeds, the return value is a pointer to the data for the directory entry</returns>
PVOID WINAPI ImageDirectoryEntryToDataEx(PVOID Base, BOOLEAN MappedAsImage, USHORT DirectoryEntry, ULONG* Size)
{
	*(ULONG*)Size = NULL;

	IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)Base;
	if (!pDosHeader)
		return nullptr;

	IMAGE_FILE_HEADER* ImageFileHeader = nullptr;
	IMAGE_OPTIONAL_HEADER* ImageOptionalHeader = nullptr;

	LONG NtHeaderFileOffset = pDosHeader->e_lfanew;
	IMAGE_NT_HEADERS* ImageNtHeader = (PIMAGE_NT_HEADERS)( (LPBYTE)pDosHeader + NtHeaderFileOffset );

	if (	pDosHeader->e_magic == IMAGE_DOS_SIGNATURE 
		&&	NtHeaderFileOffset > 0 
		&&	NtHeaderFileOffset < 0x10000000u 
		&&	ImageNtHeader->Signature == IMAGE_NT_SIGNATURE )
	{
		ImageFileHeader = &ImageNtHeader->FileHeader;	
		ImageOptionalHeader = &ImageNtHeader->OptionalHeader;
	}
	else
	{
		ImageFileHeader = (IMAGE_FILE_HEADER *)Base;
		ImageOptionalHeader = (IMAGE_OPTIONAL_HEADER *)( (BYTE*)Base + 0x14 );
	}
	switch ( ImageOptionalHeader->Magic )
	{
	case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
		return ImageDirectoryEntryToData32(
			Base,
			MappedAsImage,
			DirectoryEntry,
			Size,
			ImageFileHeader,
			(IMAGE_OPTIONAL_HEADER32 *)ImageOptionalHeader);
	case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
		return ImageDirectoryEntryToData64(
			Base,
			MappedAsImage,
			DirectoryEntry,
			Size,
			ImageFileHeader,
			(IMAGE_OPTIONAL_HEADER64 *)ImageOptionalHeader);
	case IMAGE_ROM_OPTIONAL_HDR_MAGIC:
		return ImageDirectoryEntryToDataRom(
			Base,
			IMAGE_ROM_OPTIONAL_HDR_MAGIC,
			DirectoryEntry,
			Size,
			ImageFileHeader,
			(IMAGE_ROM_OPTIONAL_HEADER *)ImageOptionalHeader);
	}
	return nullptr;
}
//////////////////////////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////////////////////
//			Equivalent to the windows api function ImageRvaToSection and ImageRvaToVa
//////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>
/// Locates a relative virtual address (RVA) within the image header of a file that is mapped as a file and returns a pointer to the section table entry for that RVA
/// </summary>
/// <param name="NtHeaders">A pointer to an IMAGE_NT_HEADERS structure. This structure can be obtained by calling the ImageNtHeader function.</param>
/// <param name="Base">This parameter is reserved</param>
/// <param name="Rva">The relative virtual address to be located</param>
/// <returns>If the function succeeds, the return value is a pointer to an IMAGE_SECTION_HEADER structure</returns>
IMAGE_SECTION_HEADER* WINAPI ImageRvaToSection(PIMAGE_NT_HEADERS NtHeaders, PVOID Base, ULONG Rva)
{
	if (!NtHeaders)
		return nullptr;

	DWORD dwNumberOfSections = NtHeaders->FileHeader.NumberOfSections;
	if (!dwNumberOfSections)
		return nullptr;

	WORD SizeOfOptionalHeader = NtHeaders->FileHeader.SizeOfOptionalHeader;
	IMAGE_SECTION_HEADER* pSectionHeaders = (IMAGE_SECTION_HEADER*)( (BYTE*)&NtHeaders->OptionalHeader + SizeOfOptionalHeader );
	for (DWORD i = 0; i < dwNumberOfSections; i++)
	{
		DWORD VirtualAddress = pSectionHeaders[i].VirtualAddress;
		DWORD SizeOfRawData = pSectionHeaders[i].SizeOfRawData;
		if ( (Rva >= VirtualAddress) && (Rva < (SizeOfRawData + VirtualAddress)) )
			return &pSectionHeaders[i];
	}
	return nullptr;
}

/// <summary>
/// Locates a relative virtual address (RVA) within the image header of a file that is mapped as a file and returns the virtual address of the corresponding byte in the file.
/// </summary>
/// <param name="NtHeaders">A pointer to an IMAGE_NT_HEADERS structure. This structure can be obtained by calling the ImageNtHeader function</param>
/// <param name="Base">The base address of an image that is mapped into memory through a call to the MapViewOfFile / ReadFile function</param>
/// <param name="Rva">The relative virtual address to be located</param>
/// <returns>If the function succeeds, the return value is the virtual address in the mapped file</returns>
PVOID WINAPI ImageRvaToVa(PIMAGE_NT_HEADERS NtHeaders, void* Base, DWORD Rva)
{
	IMAGE_SECTION_HEADER* ResultSection = nullptr;

	ResultSection = ImageRvaToSection(NtHeaders, (PVOID)Base, Rva);
	if ( !ResultSection )
		return nullptr;

	return (char *)Base + (Rva - ResultSection->VirtualAddress) + ResultSection->PointerToRawData;
}

//////////////////////////////////////////////////////////////////////////////////////////////////
//			Opposite to the windows api function ImageRvaToSection and ImageRvaToVa
//////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>
/// Locates the section header containing the virtual address (VA) in a non mapped file buffer
/// </summary>
/// <param name="NtHeaders">A pointer to an IMAGE_NT_HEADERS structure. This structure can be obtained by calling the ImageNtHeader function.</param>
/// <param name="Base">This parameter is reserved</param>
/// <param name="Va">Pointer to data inside the Images buffer</param>
/// <returns>If the function succeeds, the return value is a pointer to an IMAGE_SECTION_HEADER structure</returns>
IMAGE_SECTION_HEADER* WINAPI ImageVaToSection(PIMAGE_NT_HEADERS NtHeaders, PVOID Base, void* Va)
{
	if (!NtHeaders)
		return nullptr;

	DWORD dwNumberOfSections = NtHeaders->FileHeader.NumberOfSections;
	if (!dwNumberOfSections)
		return nullptr;

	UINT_PTR ImageOffset = (BYTE*)Va - (BYTE*)Base;

	WORD SizeOfOptionalHeader = NtHeaders->FileHeader.SizeOfOptionalHeader;
	IMAGE_SECTION_HEADER* pSectionHeaders = (IMAGE_SECTION_HEADER*)( (BYTE*)&NtHeaders->OptionalHeader + SizeOfOptionalHeader );
	for (DWORD i = 0; i < dwNumberOfSections; i++)
	{
		DWORD PointerToRawData = pSectionHeaders[i].PointerToRawData;
		DWORD SizeOfRawData = pSectionHeaders[i].SizeOfRawData;
		if ( ( ImageOffset >= PointerToRawData ) && (ImageOffset < ( PointerToRawData + SizeOfRawData )) )
			return &pSectionHeaders[i];
	}
	return nullptr;
}

/// <summary>
/// Locates the relative virtual address (RVA) of a pointer into the non mapped file buffer
/// </summary>
/// <param name="NtHeaders">A pointer to an IMAGE_NT_HEADERS structure. This structure can be obtained by calling the ImageNtHeader function</param>
/// <param name="Base">The base address of an image that is mapped into memory through a call to the MapViewOfFile function</param>
/// <param name="VA">ointer to data inside the Images buffer</param>
/// <returns>If the function succeeds, the return value is the relative virtual address (RVA) in the mapped file</returns>
DWORD WINAPI ImageVaToRva(PIMAGE_NT_HEADERS NtHeaders, void* Base, void* Va)
{
	IMAGE_SECTION_HEADER* ResultSection = nullptr;

	ResultSection = ImageVaToSection(NtHeaders, (PVOID)Base, Va);
	if ( !ResultSection )
		return NULL;

	DWORD ImageOffset = (BYTE*)Va - (BYTE*)Base;

	return (ImageOffset - ResultSection->PointerToRawData) + ResultSection->VirtualAddress;
}

/// <summary>
/// Locates the relative virtual address (RVA) of a pointer into the non mapped file buffer
/// </summary>
/// <param name="Base">The base address of an image that is mapped into memory through a call to the MapViewOfFile function</param>
/// <param name="VA">ointer to data inside the Images buffer</param>
/// <returns>If the function succeeds, the return value is the relative virtual address (RVA) in the mapped file</returns>
DWORD WINAPI ImageVaToRva(void* Base, void* Va)
{
	IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)Base;
	IMAGE_NT_HEADERS* ImageNtHeader = (PIMAGE_NT_HEADERS)( (LPBYTE)pDosHeader + pDosHeader->e_lfanew );

	return ImageVaToRva( ImageNtHeader, Base, Va );
}

//////////////////////////////////////////////////////////////////////////////////////////////////
//			Equivalent to the windows api function ImageNtHeader
//////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>
/// Locates the IMAGE_NT_HEADERS structure in a PE image and returns a pointer to the data
/// </summary>
/// <param name="Base">The base address of an image that is mapped into memory by a call to the MapViewOfFile function</param>
/// <returns>If the function succeeds, the return value is a pointer to an IMAGE_NT_HEADERS structure</returns>
IMAGE_NT_HEADERS* WINAPI ImageNtHeader( _In_ PVOID Base )
{
	IMAGE_DOS_HEADER *DosHeader = (IMAGE_DOS_HEADER*)Base;
	if ( DosHeader
		&& DosHeader->e_magic == IMAGE_DOS_SIGNATURE
		&& DosHeader->e_lfanew >= 0u
		&& DosHeader->e_lfanew < 0x10000000u )
	{
		IMAGE_NT_HEADERS* ImageNtHeader = (IMAGE_NT_HEADERS *)((BYTE *)DosHeader + DosHeader->e_lfanew);
		if ( ImageNtHeader->Signature == IMAGE_NT_SIGNATURE )
			return ImageNtHeader;
	}
	return nullptr;
}

//////////////////////////////////////////////////////////////////////////////////////////////////
//							Utility functions for GetModuleW
//////////////////////////////////////////////////////////////////////////////////////////////////
wchar_t* GetFileNameFromPath( wchar_t* Path )
{
	wchar_t* LastSlash = NULL;
	for (DWORD i = 0; Path[i] != NULL; i++)
	{
		if ( Path[i] == '\\' )
			LastSlash = &Path[i + 1];
	}
	return LastSlash;
}
wchar_t* RemoveFileExtension( wchar_t* FullFileName, wchar_t* OutputBuffer, DWORD OutputBufferSize )
{
	wchar_t* LastDot = NULL;
	for (DWORD i = 0; FullFileName[i] != NULL; i++)
		if ( FullFileName[i] == '.' )
			LastDot = &FullFileName[i];
	
	for (DWORD j = 0; j < OutputBufferSize; j++)
	{
		OutputBuffer[j] = FullFileName[j];
		if ( &FullFileName[j] == LastDot )
		{
			OutputBuffer[j] = NULL;
			break;
		}
	}
	OutputBuffer[OutputBufferSize-1] = NULL;
	return OutputBuffer;
}
