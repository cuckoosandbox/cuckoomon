
//
// File Hooks
//

extern HOOKDEF(NTSTATUS, WINAPI, NtCreateFile,
  __out     PHANDLE FileHandle,
  __in      ACCESS_MASK DesiredAccess,
  __in      POBJECT_ATTRIBUTES ObjectAttributes,
  __out     PIO_STATUS_BLOCK IoStatusBlock,
  __in_opt  PLARGE_INTEGER AllocationSize,
  __in      ULONG FileAttributes,
  __in      ULONG ShareAccess,
  __in      ULONG CreateDisposition,
  __in      ULONG CreateOptions,
  __in      PVOID EaBuffer,
  __in      ULONG EaLength
);

extern HOOKDEF(NTSTATUS, WINAPI, NtOpenFile,
  __out  PHANDLE FileHandle,
  __in   ACCESS_MASK DesiredAccess,
  __in   POBJECT_ATTRIBUTES ObjectAttributes,
  __out  PIO_STATUS_BLOCK IoStatusBlock,
  __in   ULONG ShareAccess,
  __in   ULONG OpenOptions
);

extern HOOKDEF(NTSTATUS, WINAPI, NtReadFile,
  __in      HANDLE FileHandle,
  __in_opt  HANDLE Event,
  __in_opt  PIO_APC_ROUTINE ApcRoutine,
  __in_opt  PVOID ApcContext,
  __out     PIO_STATUS_BLOCK IoStatusBlock,
  __out     PVOID Buffer,
  __in      ULONG Length,
  __in_opt  PLARGE_INTEGER ByteOffset,
  __in_opt  PULONG Key
);

extern HOOKDEF(NTSTATUS, WINAPI, NtWriteFile,
  __in      HANDLE FileHandle,
  __in_opt  HANDLE Event,
  __in_opt  PIO_APC_ROUTINE ApcRoutine,
  __in_opt  PVOID ApcContext,
  __out     PIO_STATUS_BLOCK IoStatusBlock,
  __in      PVOID Buffer,
  __in      ULONG Length,
  __in_opt  PLARGE_INTEGER ByteOffset,
  __in_opt  PULONG Key
);

extern HOOKDEF(BOOL, WINAPI, MoveFileWithProgressW,
  __in      LPWSTR lpExistingFileName,
  __in_opt  LPWSTR lpNewFileName,
  __in_opt  LPPROGRESS_ROUTINE lpProgressRoutine,
  __in_opt  LPVOID lpData,
  __in      DWORD dwFlags
);

extern HOOKDEF(BOOL, WINAPI, DeleteFileW,
  __in  LPWSTR lpFileName
);

//
// Registry Hooks
//

extern HOOKDEF(LONG, WINAPI, RegOpenKeyExA,
  __in        HKEY hKey,
  __in_opt    LPCTSTR lpSubKey,
  __reserved  DWORD ulOptions,
  __in        REGSAM samDesired,
  __out       PHKEY phkResult
);

extern HOOKDEF(LONG, WINAPI, RegOpenKeyExW,
  __in        HKEY hKey,
  __in_opt    LPWSTR lpSubKey,
  __reserved  DWORD ulOptions,
  __in        REGSAM samDesired,
  __out       PHKEY phkResult
);

extern HOOKDEF(LONG, WINAPI, RegCreateKeyExA,
  __in        HKEY hKey,
  __in        LPCTSTR lpSubKey,
  __reserved  DWORD Reserved,
  __in_opt    LPTSTR lpClass,
  __in        DWORD dwOptions,
  __in        REGSAM samDesired,
  __in_opt    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  __out       PHKEY phkResult,
  __out_opt   LPDWORD lpdwDisposition
);

extern HOOKDEF(LONG, WINAPI, RegCreateKeyExW,
  __in        HKEY hKey,
  __in        LPWSTR lpSubKey,
  __reserved  DWORD Reserved,
  __in_opt    LPWSTR lpClass,
  __in        DWORD dwOptions,
  __in        REGSAM samDesired,
  __in_opt    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  __out       PHKEY phkResult,
  __out_opt   LPDWORD lpdwDisposition
);

extern HOOKDEF(LONG, WINAPI, RegDeleteKeyA,
  __in  HKEY hKey,
  __in  LPCTSTR lpSubKey
);

extern HOOKDEF(LONG, WINAPI, RegDeleteKeyW,
  __in  HKEY hKey,
  __in  LPWSTR lpSubKey
);

extern HOOKDEF(LONG, WINAPI, RegEnumKeyW,
  __in   HKEY hKey,
  __in   DWORD dwIndex,
  __out  LPWSTR lpName,
  __in   DWORD cchName
);

extern HOOKDEF(LONG, WINAPI, RegEnumKeyExA,
  __in         HKEY hKey,
  __in         DWORD dwIndex,
  __out        LPTSTR lpName,
  __inout      LPDWORD lpcName,
  __reserved   LPDWORD lpReserved,
  __inout      LPTSTR lpClass,
  __inout_opt  LPDWORD lpcClass,
  __out_opt    PFILETIME lpftLastWriteTime
);

extern HOOKDEF(LONG, WINAPI, RegEnumKeyExW,
  __in         HKEY hKey,
  __in         DWORD dwIndex,
  __out        LPWSTR lpName,
  __inout      LPDWORD lpcName,
  __reserved   LPDWORD lpReserved,
  __inout      LPWSTR lpClass,
  __inout_opt  LPDWORD lpcClass,
  __out_opt    PFILETIME lpftLastWriteTime
);

extern HOOKDEF(LONG, WINAPI, RegEnumValueA,
  __in         HKEY hKey,
  __in         DWORD dwIndex,
  __out        LPTSTR lpValueName,
  __inout      LPDWORD lpcchValueName,
  __reserved   LPDWORD lpReserved,
  __out_opt    LPDWORD lpType,
  __out_opt    LPBYTE lpData,
  __inout_opt  LPDWORD lpcbData
);

extern HOOKDEF(LONG, WINAPI, RegEnumValueW,
  __in         HKEY hKey,
  __in         DWORD dwIndex,
  __out        LPWSTR lpValueName,
  __inout      LPDWORD lpcchValueName,
  __reserved   LPDWORD lpReserved,
  __out_opt    LPDWORD lpType,
  __out_opt    LPBYTE lpData,
  __inout_opt  LPDWORD lpcbData
);

extern HOOKDEF(LONG, WINAPI, RegSetValueExA,
  __in        HKEY hKey,
  __in_opt    LPCTSTR lpValueName,
  __reserved  DWORD Reserved,
  __in        DWORD dwType,
  __in        const BYTE *lpData,
  __in        DWORD cbData
);

extern HOOKDEF(LONG, WINAPI, RegSetValueExW,
  __in        HKEY hKey,
  __in_opt    LPWSTR lpValueName,
  __reserved  DWORD Reserved,
  __in        DWORD dwType,
  __in        const BYTE *lpData,
  __in        DWORD cbData
);

extern HOOKDEF(LONG, WINAPI, RegQueryValueExA,
  __in         HKEY hKey,
  __in_opt     LPCTSTR lpValueName,
  __reserved   LPDWORD lpReserved,
  __out_opt    LPDWORD lpType,
  __out_opt    LPBYTE lpData,
  __inout_opt  LPDWORD lpcbData
);

extern HOOKDEF(LONG, WINAPI, RegQueryValueExW,
  __in         HKEY hKey,
  __in_opt     LPWSTR lpValueName,
  __reserved   LPDWORD lpReserved,
  __out_opt    LPDWORD lpType,
  __out_opt    LPBYTE lpData,
  __inout_opt  LPDWORD lpcbData
);

extern HOOKDEF(LONG, WINAPI, RegDeleteValueA,
  __in      HKEY hKey,
  __in_opt  LPCTSTR lpValueName
);

extern HOOKDEF(LONG, WINAPI, RegDeleteValueW,
  __in      HKEY hKey,
  __in_opt  LPWSTR lpValueName
);

//
// Window Hooks
//

extern HOOKDEF(HWND, WINAPI, FindWindowA,
  __in_opt  LPCTSTR lpClassName,
  __in_opt  LPCTSTR lpWindowName
);

extern HOOKDEF(HWND, WINAPI, FindWindowW,
  __in_opt  LPWSTR lpClassName,
  __in_opt  LPWSTR lpWindowName
);

extern HOOKDEF(HWND, WINAPI, FindWindowExA,
  __in_opt  HWND hwndParent,
  __in_opt  HWND hwndChildAfter,
  __in_opt  LPCTSTR lpszClass,
  __in_opt  LPCTSTR lpszWindow
);

extern HOOKDEF(HWND, WINAPI, FindWindowExW,
  __in_opt  HWND hwndParent,
  __in_opt  HWND hwndChildAfter,
  __in_opt  LPWSTR lpszClass,
  __in_opt  LPWSTR lpszWindow
);

//
// Sync Hooks
//

extern HOOKDEF(NTSTATUS, WINAPI, NtCreateMutant,
    __out       PHANDLE MutantHandle,
    __in        ACCESS_MASK DesiredAccess,
    __in_opt    POBJECT_ATTRIBUTES ObjectAttributes,
    __in        BOOLEAN InitialOwner
);

extern HOOKDEF(NTSTATUS, WINAPI, NtOpenMutant,
    __out       PHANDLE MutantHandle,
    __in        ACCESS_MASK DesiredAccess,
    __in        POBJECT_ATTRIBUTES ObjectAttributes
);

extern HOOKDEF(NTSTATUS, WINAPI, NtCreateProcess,
    __out       PHANDLE ProcessHandle,
    __in        ACCESS_MASK DesiredAccess,
    __in_opt    POBJECT_ATTRIBUTES ObjectAttributes,
    __in        HANDLE ParentProcess,
    __in        BOOLEAN InheritObjectTable,
    __in_opt    HANDLE SectionHandle,
    __in_opt    HANDLE DebugPort,
    __in_opt    HANDLE ExceptionPort
);

extern HOOKDEF(NTSTATUS, WINAPI, NtCreateProcessEx,
    __out       PHANDLE ProcessHandle,
    __in        ACCESS_MASK DesiredAccess,
    __in_opt    POBJECT_ATTRIBUTES ObjectAttributes,
    __in        HANDLE ParentProcess,
    __in        ULONG Flags,
    __in_opt    HANDLE SectionHandle,
    __in_opt    HANDLE DebugPort,
    __in_opt    HANDLE ExceptionPort,
    __in        BOOLEAN InJob
);

extern HOOKDEF(BOOL, WINAPI, CreateProcessInternalW,
    __in_opt    LPVOID lpUnknown1,
    __in_opt    LPWSTR lpApplicationName,
    __inout_opt LPWSTR lpCommandLine,
    __in_opt    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    __in_opt    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    __in        BOOL bInheritHandles,
    __in        DWORD dwCreationFlags,
    __in_opt    LPVOID lpEnvironment,
    __in_opt    LPWSTR lpCurrentDirectory,
    __in        LPSTARTUPINFO lpStartupInfo,
    __out       LPPROCESS_INFORMATION lpProcessInformation,
    __in_opt    LPVOID lpUnknown2
);

extern HOOKDEF(HANDLE, WINAPI, OpenProcess,
  __in  DWORD dwDesiredAccess,
  __in  BOOL bInheritHandle,
  __in  DWORD dwProcessId
);

extern HOOKDEF(BOOL, WINAPI, TerminateProcess,
  __in  HANDLE hProcess,
  __in  UINT uExitCode
);

extern HOOKDEF(VOID, WINAPI, ExitProcess,
  __in  UINT uExitCode
);

extern HOOKDEF(BOOL, WINAPI, ShellExecuteExW,
  __inout  SHELLEXECUTEINFOW *pExecInfo
);
