#include <sgx.h>
#include <stdlib.h>

extern int sgx_init();
extern tcs_t *init_enclave(void *base_addr, unsigned int entry_offset,
		                   unsigned int n_of_pages, char *conf);

extern char __start_sgxtext;
extern char __stop_sgxtext;

tcs_t *__llvmsgx_enclave_tcs;

void __llvmsgx_enclave_init(void *entry)
{
	if (!sgx_init())
	{
		fprintf(stderr, "sgx_init failed\n");
		abort();
	}

	if (entry < (void*)&__start_sgxtext || entry >= (void*)&__stop_sgxtext)
	{
		fprintf(stderr, "enclave entry point not in 'sgxtext'\n");
		abort();
	}

	printf("Start: %p, stop: %p\n", &__start_sgxtext, &__stop_sgxtext);
	size_t sectionSize = (size_t)((char*)&__stop_sgxtext - (char*)&__start_sgxtext);
	// SGX only deals in full pages, so round up to nearest full page
	size_t alignedSectionSize = (sectionSize + (PAGE_SIZE - 1)) / PAGE_SIZE * PAGE_SIZE;

	void *mem = aligned_alloc(PAGE_SIZE, alignedSectionSize);
	memset(mem, 0, alignedSectionSize);
	memcpy(mem, &__start_sgxtext, sectionSize);

	unsigned int entryOffset = (unsigned int)((char*)entry - (char*)&__start_sgxtext);
	tcs_t *tcs = init_enclave(mem, entryOffset, alignedSectionSize / PAGE_SIZE, 0);
	if (tcs == 0)
	{
		fprintf(stderr, "could not init enclave\n");
		abort();
	}

	__llvmsgx_enclave_tcs = tcs;
}

// Ensure an "sgxtext" section is created so we don't get linker errors
// on __start_sgxtext and __stop_sgxtext if there are no secure functions.
__attribute__((section("sgxtext")))
char __llvmsgx_force_section;
