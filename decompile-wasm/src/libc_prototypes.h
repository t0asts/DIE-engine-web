#ifndef DIE_WEB_LIBC_PROTOTYPES_H
#define DIE_WEB_LIBC_PROTOTYPES_H

namespace die_web {

static const char *LIBC_PROTOTYPES = R"libc(
typedef unsigned long size_t;
typedef long ssize_t;
typedef int wchar_t;

void *malloc(size_t size);
void *calloc(size_t nmemb, size_t size);
void *realloc(void *ptr, size_t size);
void free(void *ptr);

size_t strlen(const char *s);
char *strcpy(char *dest, const char *src);
char *strncpy(char *dest, const char *src, size_t n);
char *strcat(char *dest, const char *src);
int strcmp(const char *s1, const char *s2);
int strncmp(const char *s1, const char *s2, size_t n);
char *strchr(const char *s, int c);
char *strstr(const char *haystack, const char *needle);
char *strdup(const char *s);

void *memcpy(void *dest, const void *src, size_t n);
void *memmove(void *dest, const void *src, size_t n);
void *memset(void *s, int c, size_t n);
int memcmp(const void *s1, const void *s2, size_t n);

int printf(const char *format);
int fprintf(void *stream, const char *format);
int sprintf(char *str, const char *format);
int snprintf(char *str, size_t size, const char *format);
int scanf(const char *format);
int sscanf(const char *str, const char *format);
int puts(const char *s);
int putchar(int c);
int getchar(void);

void *fopen(const char *path, const char *mode);
int fclose(void *stream);
size_t fread(void *ptr, size_t size, size_t nmemb, void *stream);
size_t fwrite(const void *ptr, size_t size, size_t nmemb, void *stream);

void exit(int status);
void abort(void);
int atoi(const char *nptr);
long atol(const char *nptr);

int open(const char *pathname, int flags);
int close(int fd);
ssize_t read(int fd, void *buf, size_t count);
ssize_t write(int fd, const void *buf, size_t count);
)libc";

}

#endif
