#pragma once
#include <Windows.h>
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
FARPROC WINAPI GetExportAddress( _In_ HMODULE hModule, _In_ LPCSTR lpProcName, _In_ BOOLEAN MappedAsImage );

//////////////////////////////////////////////////////////////////////////////////////////////////
//		Equivalent to the windows api function GetModuleHandleA and GetModuleHandleW
//////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>
/// Retrieves the address of an loaded module by name
/// </summary>
/// <param name="lpModuleName">name of the module, zero for current module</param>
/// <returns>returns address of the module in memory</returns>
HMODULE WINAPI GetModuleA( _In_opt_ LPCSTR  lpModuleName );

/// <summary>
/// Retrieves the address of an loaded module by name
/// </summary>
/// <param name="lpModuleName">name of the module, zero for current module</param>
/// <returns>returns address of the module in memory</returns>
HMODULE WINAPI GetModuleW( _In_opt_ LPCWSTR lpModuleName );

//////////////////////////////////////////////////////////////////////////////////////////////////
//			Equivalent to the windows api function ImageNtHeader
//////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>
/// Locates the IMAGE_NT_HEADERS structure in a PE image and returns a pointer to the data
/// </summary>
/// <param name="Base">The base address of an image that is mapped into memory by a call to the MapViewOfFile / ReadFile function</param>
/// <returns>If the function succeeds, the return value is a pointer to an IMAGE_NT_HEADERS structure</returns>
IMAGE_NT_HEADERS* WINAPI ImageNtHeader( _In_ PVOID Base );

//////////////////////////////////////////////////////////////////////////////////////////////////
//			Equivalent to the windows api function ImageDirectoryEntryToDataEx
//////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>
/// Locates a directory entry within the image header and returns the address of the data for the directory entry
/// </summary>
/// <param name="Base">The base address of the image or data file</param>
/// <param name="MappedAsImage">If the flag is TRUE, the file is mapped by the system as an image. If this flag is FALSE, the file is mapped as a data file by the MapViewOfFile/ ReadFile function</param>
/// <param name="DirectoryEntry">The directory entry to be located</param>
/// <param name="Size">A pointer to a variable that receives the size of the data for the directory entry that is located</param>
/// <returns>If the function succeeds, the return value is a pointer to the data for the directory entry</returns>
PVOID WINAPI ImageDirectoryEntryToDataEx(PVOID Base, BOOLEAN MappedAsImage, USHORT DirectoryEntry, ULONG* Size);

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
IMAGE_SECTION_HEADER* WINAPI ImageRvaToSection(PIMAGE_NT_HEADERS NtHeaders, PVOID Base, ULONG Rva);

/// <summary>
/// Locates a relative virtual address (RVA) within the image header of a file that is mapped as a file and returns the virtual address of the corresponding byte in the file.
/// </summary>
/// <param name="NtHeaders">A pointer to an IMAGE_NT_HEADERS structure. This structure can be obtained by calling the ImageNtHeader function</param>
/// <param name="Base">The base address of an image that is mapped into memory through a call to the MapViewOfFile function</param>
/// <param name="Rva">The relative virtual address to be located</param>
/// <returns>If the function succeeds, the return value is the virtual address in the mapped file</returns>
PVOID WINAPI ImageRvaToVa(PIMAGE_NT_HEADERS NtHeaders, void* Base, DWORD Rva);

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
IMAGE_SECTION_HEADER* WINAPI ImageVaToSection(PIMAGE_NT_HEADERS NtHeaders, PVOID Base, void* Va);

/// <summary>
/// Locates the relative virtual address (RVA) of a pointer into the non mapped file buffer
/// </summary>
/// <param name="NtHeaders">A pointer to an IMAGE_NT_HEADERS structure. This structure can be obtained by calling the ImageNtHeader function</param>
/// <param name="Base">The base address of an image that is mapped into memory through a call to the MapViewOfFile function</param>
/// <param name="VA">ointer to data inside the Images buffer</param>
/// <returns>If the function succeeds, the return value is the relative virtual address (RVA) in the mapped file</returns>
DWORD WINAPI ImageVaToRva(PIMAGE_NT_HEADERS NtHeaders, void* Base, void* Va);

/// <summary>
/// Locates the relative virtual address (RVA) of a pointer into the non mapped file buffer
/// </summary>
/// <param name="Base">The base address of an image that is mapped into memory through a call to the MapViewOfFile function</param>
/// <param name="VA">ointer to data inside the Images buffer</param>
/// <returns>If the function succeeds, the return value is the relative virtual address (RVA) in the mapped file</returns>
DWORD WINAPI ImageVaToRva(void* Base, void* Va);

//////////////////////////////////////////////////////////////////////////////////////////////////
//							Utility functions for GetModuleW
//////////////////////////////////////////////////////////////////////////////////////////////////
wchar_t* GetFileNameFromPath( wchar_t* Path );
wchar_t* RemoveFileExtension( wchar_t* FullFileName, wchar_t* OutputBuffer, DWORD OutputBufferSize );
