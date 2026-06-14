#ifndef DIE_WEB_LIBC_PROTOTYPES_H
#define DIE_WEB_LIBC_PROTOTYPES_H

namespace die_web {

static const char *LIBC_PROTOTYPES = R"libc(
typedef unsigned long size_t;
typedef long ssize_t;
typedef int wchar_t;

extern void *malloc(size_t size);
extern void *calloc(size_t nmemb, size_t size);
extern void *realloc(void *ptr, size_t size);
extern void free(void *ptr);

extern size_t strlen(const char *s);
extern char *strcpy(char *dest, const char *src);
extern char *strncpy(char *dest, const char *src, size_t n);
extern char *strcat(char *dest, const char *src);
extern int strcmp(const char *s1, const char *s2);
extern int strncmp(const char *s1, const char *s2, size_t n);
extern char *strchr(const char *s, int c);
extern char *strstr(const char *haystack, const char *needle);
extern char *strdup(const char *s);

extern void *memcpy(void *dest, const void *src, size_t n);
extern void *memmove(void *dest, const void *src, size_t n);
extern void *memset(void *s, int c, size_t n);
extern int memcmp(const void *s1, const void *s2, size_t n);

extern int printf(const char *format);
extern int fprintf(void *stream, const char *format);
extern int sprintf(char *str, const char *format);
extern int snprintf(char *str, size_t size, const char *format);
extern int scanf(const char *format);
extern int sscanf(const char *str, const char *format);
extern int puts(const char *s);
extern int putchar(int c);
extern int getchar(void);

extern void *fopen(const char *path, const char *mode);
extern int fclose(void *stream);
extern size_t fread(void *ptr, size_t size, size_t nmemb, void *stream);
extern size_t fwrite(const void *ptr, size_t size, size_t nmemb, void *stream);

extern void exit(int status);
extern void abort(void);
extern int atoi(const char *nptr);
extern long atol(const char *nptr);

extern int open(const char *pathname, int flags);
extern int close(int fd);
extern ssize_t read(int fd, void *buf, size_t count);
extern ssize_t write(int fd, const void *buf, size_t count);

/* Additional C runtime (incl. the MSVC CRT entry points seen in PE binaries).
   These are matched by name against imported symbols, so a `char *` argument
   makes the decompiler fold a constant pointer into the string literal. */
extern char *fgets(char *s, int n, void *stream);
extern char *gets(char *s);
extern int fputs(const char *s, void *stream);
extern int fputc(int c, void *stream);
extern int fflush(void *stream);
extern int ferror(void *stream);
extern int feof(void *stream);
extern void perror(const char *s);
extern char *getenv(const char *name);
extern int system(const char *command);
extern long strtol(const char *nptr, char **endptr, int base);
extern int toupper(int c);
extern int tolower(int c);
extern void *__acrt_iob_func(unsigned int index);
extern void _exit(int status);

/* Windows API: minimal typedefs so the output reads like real Win32 code, then
   the most common kernel32/user32 entry points. DWORD is unsigned int (4 bytes
   on every data model), pointers stay pointer-width. */
typedef void *HANDLE;
typedef void *HMODULE;
typedef void *HINSTANCE;
typedef void *HWND;
typedef void *HRSRC;
typedef void *HGLOBAL;
typedef void *LPVOID;
typedef const void *LPCVOID;
typedef unsigned int DWORD;
typedef int BOOL;
typedef const char *LPCSTR;
typedef char *LPSTR;
typedef const wchar_t *LPCWSTR;
typedef wchar_t *LPWSTR;

extern HMODULE LoadLibraryA(LPCSTR lpLibFileName);
extern HMODULE LoadLibraryW(LPCWSTR lpLibFileName);
extern HMODULE GetModuleHandleA(LPCSTR lpModuleName);
extern HMODULE GetModuleHandleW(LPCWSTR lpModuleName);
extern void *GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
extern BOOL FreeLibrary(HMODULE hLibModule);

extern HRSRC FindResourceA(HMODULE hModule, LPCSTR lpName, LPCSTR lpType);
extern HRSRC FindResourceW(HMODULE hModule, LPCWSTR lpName, LPCWSTR lpType);
extern HGLOBAL LoadResource(HMODULE hModule, HRSRC hResInfo);
extern LPVOID LockResource(HGLOBAL hResData);
extern DWORD SizeofResource(HMODULE hModule, HRSRC hResInfo);

extern LPVOID VirtualAlloc(LPVOID lpAddress, size_t dwSize, DWORD flAllocationType, DWORD flProtect);
extern BOOL VirtualProtect(LPVOID lpAddress, size_t dwSize, DWORD flNewProtect, DWORD *lpflOldProtect);
extern BOOL VirtualFree(LPVOID lpAddress, size_t dwSize, DWORD dwFreeType);
extern LPVOID HeapAlloc(HANDLE hHeap, DWORD dwFlags, size_t dwBytes);
extern HANDLE GetProcessHeap(void);

extern HANDLE CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPVOID lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
extern HANDLE CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPVOID lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
extern BOOL ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, DWORD *lpNumberOfBytesRead, LPVOID lpOverlapped);
extern BOOL WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, DWORD *lpNumberOfBytesWritten, LPVOID lpOverlapped);
extern BOOL CloseHandle(HANDLE hObject);
extern HANDLE GetStdHandle(DWORD nStdHandle);

extern DWORD GetLastError(void);
extern void SetLastError(DWORD dwErrCode);
extern void Sleep(DWORD dwMilliseconds);
extern void ExitProcess(DWORD uExitCode);
extern int MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, DWORD uType);
extern int MessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, DWORD uType);
extern DWORD GetModuleFileNameA(HMODULE hModule, LPSTR lpFilename, DWORD nSize);
)libc";

}

#endif
