#include <stdio.h>
#include <windows.h>

int main()
{
    // there we go
    LoadLibrary("../cuckoomon.dll");

    fclose(fopen("test-hello", "w"));
    FILE *fp = fopen("test-hello", "wb");
    fwrite("whatsup", 1, 6, fp);
    fclose(fp);
    fp = fopen("test-hello", "rb");
    char buf[6];
    fread(buf, 1, 6, fp);
    fclose(fp);

    DeleteFile("test-hello");

    HKEY hKey;
    if(RegCreateKeyEx(HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, NULL, 0,
            KEY_ALL_ACCESS, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueEx(hKey, "TestApiHooks", 0, REG_SZ, (BYTE *) "Hoi", 3);
        RegDeleteValue(hKey, "TestApiHooks");
        RegCloseKey(hKey);
    }

    system("echo hai");

    WinExec("echo hi there", SW_SHOW);

    CreateMutex(NULL, FALSE, "MutexNam3");
    OpenMutex(MUTEX_ALL_ACCESS, FALSE, "OpenMutexName");

    // just some random dll
    LoadLibrary("urlmon.dll");
}
