#include <stdio.h>

#ifdef _MSC_VER
#define forceinline __forceinline
#elif defined __GNUC__
#define forceinline __inline__ __attribute__((always_inline))
#else
#define forceinline
#endif

#ifdef linux
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#ifdef __x86_64__
#define __VM_X64
#elif __i386__
#define __VM_X32
#endif
forceinline void * __runable_malloc(int size) {
	int fd = open("/dev/zero", O_RDONLY);
	void * ret = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, fd, 0);
	close(fd);
	return ret;
}
#else
#include <Windows.h>
#ifdef _WIN64
#define __VM_X64
#else
#define __VM_X32
#endif
forceinline void * __runable_malloc(int size) {
	return VirtualAlloc(0, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
}
#endif

forceinline void * __makefuncttion(unsigned char * shellcode, int len) {
	void * address_shellcode = __runable_malloc(len + 1);
	memcpy((char *)address_shellcode, shellcode, len);
	*((char *)address_shellcode + len) = 0xc3;
	return address_shellcode;
}

int main() {
typedef unsigned long(*func)();
#ifdef __VM_X64
	unsigned char shellcode[] = { 0x48,0xC7,0xC0,0x01,0x00,0x00,0x00 };
#else
	unsigned char shellcode[] = { 0xb8,0x01,0x00,0x00,0x00 };
#endif
	func fun = (func)__makefuncttion(shellcode, sizeof(shellcode));
	int ret = fun();
	printf("ret is : %d\n", ret);
	getchar();
	return 0;
}
