
ULONG_PTR parent_process_id(); // By Napalm @ NetCore2K (rohitab.com)
DWORD pid_from_process_handle(HANDLE process_handle);
DWORD pid_from_thread_handle(HANDLE thread_handle);
DWORD random();
BOOL is_directory_objattr(const OBJECT_ATTRIBUTES *obj);

// imported but for some doesn't show up when #including string.h etc
int wcsnicmp(const wchar_t *a, const wchar_t *b, int len);
int wcsicmp(const wchar_t *a, const wchar_t *b);
