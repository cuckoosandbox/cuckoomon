/*
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2010-2014 Cuckoo Sandbox Developers

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <windows.h>
#include <tchar.h>
#include "ntapi.h"

#define FILE_OPEN                       0x00000001 
#define FILE_DIRECTORY_FILE                     0x00000001 

#define OBJ_CASE_INSENSITIVE 0x00000040
#define OBJ_KERNEL_HANDLE 0x00000200

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);        \
    (p)->RootDirectory = r;                         \
    (p)->Attributes = a;                            \
    (p)->ObjectName = n;                            \
    (p)->SecurityDescriptor = s;                    \
    (p)->SecurityQualityOfService = NULL;           \
    }

VOID (WINAPI *pRtlInitUnicodeString)(PUNICODE_STRING DestinationString,
    PCWSTR SourceString);

NTSTATUS (WINAPI *pZwDeleteFile)(POBJECT_ATTRIBUTES ObjectAttributes);

NTSTATUS (WINAPI *pZwCreateFile)(PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID AllocationSize,
    ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition,
    ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);

NTSTATUS (WINAPI *pZwSetInformationFile)(HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass);

int write_file(const char *fname, const char *s)
{
    FILE *fp = fopen(fname, "wb");
    if(fp != NULL) {
        fputs(s, fp);
        fclose(fp);

		return 0;
    }

	fprintf( stderr, "Error writing %s\n", fname );

	return 1;
}

int main(void)
{
    UNICODE_STRING dir_fname, file_fname;
    OBJECT_ATTRIBUTES obj_dir, obj_file;
    IO_STATUS_BLOCK io_dir;
    HANDLE dir_handle;
    NTSTATUS ret;


    printf(
        "Going to try to delete files using various techiques.\n"
        "Note that the MoveFileEx method will fail (see source why)\n"
    );

    if ( write_file("abc.txt", "DeleteFile") == 0 )
	{
		//
		// delete the file using the well-known DeleteFile function
		//

		if ( DeleteFile( _T( "abc.txt" )) != 0 )
			printf("DeleteFile: SUCCESS\n" );
		else
		{
			fprintf( stderr, "Error DeleteFile LAST ERROR %d\n", GetLastError() );
			return 1;
		}
	}
	else 
		return 1;

    if ( write_file("abc.txt", "MoveFileEx") == 0 )
	{
		//
		// delete the file using MoveFileEx, note that a NULL destination filename
		// is only supported when the MOVEFILE_DELAY_UNTIL_REBOOT flag is set.
		// (so this call will actually fail..)
		//

		printf("MoveFileEx: %s (0x%08x)\n", MoveFileEx( _T( "abc.txt" ), NULL, 0 ) ?
			"SUCCESS" : "FAILURE", GetLastError());
	}
	else
		return 1;

	if ( write_file("abc.txt", "ZwDeleteFile") == 0 )
	{
		//
		// delete the file using ZwDeleteFile
		//
		*(FARPROC *) &pRtlInitUnicodeString = GetProcAddress(
			GetModuleHandle( _T( "ntdll" ) ), "RtlInitUnicodeString");
		*(FARPROC *) &pZwDeleteFile = GetProcAddress(
			GetModuleHandle( _T( "ntdll" ) ), "ZwDeleteFile");
		*(FARPROC *) &pZwCreateFile = GetProcAddress(
			GetModuleHandle( _T( "ntdll" ) ), "ZwCreateFile");
		*(FARPROC *) &pZwSetInformationFile = GetProcAddress(
			GetModuleHandle( _T( "ntdll" ) ), "ZwSetInformationFile");

		if ( pRtlInitUnicodeString == NULL || pZwDeleteFile == NULL || pZwCreateFile == NULL || pZwSetInformationFile == NULL )
		{
			fprintf( stderr, "Error getprocaddress: pRtlInitUnicodeString %x pZwDeleteFile %x pZwCreateFile %x pZwSetInformationFile %x", pRtlInitUnicodeString, pZwDeleteFile, pZwCreateFile, pZwSetInformationFile );
			return 1;
		}

		// prepend the path with "\\??\\"
		wchar_t cur_dir[MAX_PATH] = L"\\??\\";
		if ( GetCurrentDirectoryW(MAX_PATH-4, cur_dir+4) == 0 )
		{
			fprintf( stderr, "Error: GetCurrentDirectoryW" );
			return 1;
		}

		pRtlInitUnicodeString(&dir_fname, cur_dir);
		pRtlInitUnicodeString(&file_fname, L"abc.txt");

		InitializeObjectAttributes(&obj_dir, &dir_fname,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

		// open the directory
		ret = pZwCreateFile(&dir_handle, FILE_TRAVERSE, &obj_dir,
			&io_dir, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
			FILE_DIRECTORY_FILE, NULL, 0);

		if(NT_SUCCESS(ret)) 
		{
			InitializeObjectAttributes(&obj_file, &file_fname,
				OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, dir_handle, NULL);

			// delete the file
			ret = pZwDeleteFile(&obj_file);
			printf("ZwDeleteFile: %s (0x%08x)\n", NT_SUCCESS(ret) ?
				"SUCCESS" : "FAILURE", ret);
			CloseHandle(dir_handle);

			if (!NT_SUCCESS(ret))
			{
				fprintf( stderr, "Error: ZwDeleteFile\n" );
				return 1;
			}
		}
		else {
			fprintf( stderr, "ZwDeleteFile: FAILURE (0x%08x)\n", ret);
			return 1;
		}
	}
	else
		return 1;

    if ( write_file("abc.txt", "ZwSetInformationFile") == 0 )
	{

		//
		// delete the file using ZwSetInformationFile
		//

		IO_STATUS_BLOCK io_file;
		HANDLE file_handle;

		// prepend the path with "\\??\\" and append "abc.txt"
		wchar_t file_name[MAX_PATH] = L"\\??\\";
		if ( GetCurrentDirectoryW(MAX_PATH-4, file_name+4) == 0 )
		{
			fprintf( stderr, "Error: GetCurrentDirectoryW\n" );
			return 1;
		}
		lstrcatW(file_name, L"\\abc.txt");

		pRtlInitUnicodeString(&file_fname, file_name);
		InitializeObjectAttributes(&obj_file, &file_fname,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

		// open the file with DELETE access rights
		ret = pZwCreateFile(&file_handle, DELETE, &obj_file, &io_file, NULL,
			FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, 0, NULL, 0);
		if(NT_SUCCESS(ret)) {
			BOOLEAN disp_info = TRUE;
			ret = pZwSetInformationFile(file_handle, &io_file, &disp_info,
				sizeof(disp_info), FileDispositionInformation);
			CloseHandle(file_handle);

			printf("ZwSetInformationFile: %s (0x%08x)\n", NT_SUCCESS(ret) ?
				"SUCCESS" : "FAILURE", ret);

			if ( ! NT_SUCCESS(ret) )
			{
				fprintf( stderr, "Error: ZwSetInformationFile\n" );
				return 1;
			}
		}
		else {
			fprintf( stderr, "Error: ZwSetInformationFile: FAILURE (0x%08x)\n", ret);
			return 1;
		}
	}
	else
		return 1;

	return 0;
}
