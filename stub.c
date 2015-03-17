#include "davinci.h"

payload_meta_t payload __attribute__((section(".data"))) = {0x00};
static int watermark = 0;
char *passwd = NULL;
int keylen;

static long afm_ptrace(long request, long pid, void *addr, void *data) 
{
        long ret;

        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov %2, %%rdx\n"
                        "mov %3, %%r10\n"
                        "mov $101, %%rax\n"
                        "syscall" : : "g"(request), "g"(pid), "g"(addr), "g"(data));
        asm("mov %%rax, %0" : "=r"(ret));
        
        return ret;
}

static long afm_write(long fd, char *buf, unsigned long len)
{
        long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov %2, %%rdx\n"
                        "mov $1, %%rax\n"
                        "syscall" : : "g"(fd), "g"(buf), "g"(len));
        asm("mov %%rax, %0" : "=r"(ret));
        return ret;
}

void bail_out(void)
{
	fprintf(stderr, "The gates of heaven remain closed\n");
	kill(getpid(), SIGKILL);
	exit(-1);
}


void enable_anti_debug(void)
{
	if (afm_ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) 
		bail_out();
	watermark++;
}

void decode_payload_struct(size_t len)
{
	size_t i;
	uint8_t *p;

	for (p = (uint8_t *)&payload, i = 0; i < len; i++) {
		*p ^= ((i << 0xE) & 0xFF);
		p++;
	}
}
 
		
void decode_payload_data(size_t len)
{
	size_t i, b;
	uint8_t *p;
	
	/*
	 * The program was supplied with the ability to self-decrypt
	 * without a user supplied key.
	 */
	if (payload.keylen) {
		for (p = (uint8_t *)payload.data, i = 0, b = 0; i < len; i++) {
			p[i] ^= payload.key[b++];
			if (b > payload.keylen - 1)
				b = 0;
		}
		goto done;
	}
	/*
	 * The program requires a key from the user to decrypt msg
	 */
	for (p = (uint8_t *)payload.data, i = 0, b = 0; i < len; i++) {
		p[i] ^= passwd[b++];
		if (b > keylen - 1)
			b = 0;
	}
	
done:
	return;
}		

void denied(void)
{
	bail_out();
}

void accepted(void)
{
	__asm__ __volatile__("nop\n");
}

#define CHUNK_SIZE 512

int main(int argc, char **argv)
{
	size_t i, len, offset = 0;
	size_t total_plen = sizeof(payload);
	uint64_t a[2], x;
	void (*f)();
	

	/*
 	 * Enable anti-debug code which performs
	 * self tracing with direct syscall ptrace
	 * code.
	 */
	enable_anti_debug();

	/*
	 * Decrypt the meta data 
	 */
	decode_payload_struct(total_plen);
	
	if (!payload.keylen) {
		if (argc < 2) {
			fprintf(stderr, "This message requires that you supply a key to decrypt\n");
			exit(0);
		}
		passwd = argv[1];
		keylen = strlen(passwd);
	}
	
	/*
	 * Decrypt the payload data
	 */
	decode_payload_data(payload.payload_len);
	
	/*
	 * Simple watermarking to see if antidebugging
	 * code was tampered with. If so, then exit.
	 */
	a[0] = (uint64_t)&denied;
	a[1] = (uint64_t)&accepted;
	x = a[!(!(watermark))];
	f = (void *)x;
	f(); 
	
	/*
	 * Write the payload data to stdout
	 */
	offset = 0;
	len = payload.payload_len;
	do {
		if (len < CHUNK_SIZE) {
			afm_write(1, (char *)&payload.data[offset], len);
			break;
		}
		afm_write(1, (char *)&payload.data[offset], CHUNK_SIZE);
		offset += CHUNK_SIZE;
		len -= CHUNK_SIZE;
	}	while (len > 0);
	exit(0);
}

