#include <sgx.h>
#include <stdlib.h>
#include <stdint.h>

extern int sgx_init();
extern tcs_t *init_enclave(void *base_addr, unsigned int entry_offset,
		                   unsigned int n_of_pages, char *conf);

extern char __start_sgxtext;
extern char __stop_sgxtext;

__attribute__((section("sgxtext")))
extern void __llvmsgx_enclave_switchboard(int64_t func_index, int8_t *frame);

__attribute__((section("sgxtext"), always_inline))
static void xtea_encrypt(uint32_t v[2], uint32_t const k[4])
{
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], sum=0, delta=0x9E3779B9;
    for (i=0; i < 32; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum>>11) & 3]);
    }
    v[0]=v0; v[1]=v1;
}

typedef struct
{
	uint32_t Offset;
	uint32_t Size;
} Region;

__attribute__((section("sgxtext")))
struct
{
	bool Encrypted;
	uint32_t CryptoKey[4];
	Region EncryptedRegions[32];
} __llvmsgx_enclave_data;

__attribute__((section("sgxtext")))
void __llvmsgx_enclave_entry(int64_t func_index, int8_t *frame)
{
	if (__llvmsgx_enclave_data.Encrypted)
	{
		// XTEA in counter mode
		// TODO: Currently we use __llvmsgx_enclave_data, which contains
		// the crypto key. Naturally this is unsafe as anyone can access
		// it on disk and decrypt the data. In the future, this function
		// should be changed to obtain the crypto key via remote attestation
		// instead.
		uint64_t counter = 0;
		uint32_t cipherStream[2];
		int cipherIndex = 8;

		const int maxNumRegions = sizeof(__llvmsgx_enclave_data.EncryptedRegions) /
			                      sizeof(__llvmsgx_enclave_data.EncryptedRegions[0]);

		for (int i = 0; i < maxNumRegions; i++)
		{
			Region region = __llvmsgx_enclave_data.EncryptedRegions[i];
			if (region.Size == 0)
				break;

			char *regionStart = &__start_sgxtext + region.Offset;
			for (uint32_t j = 0; j < region.Size; j++)
			{
				if (cipherIndex == 8)
				{
					memcpy(cipherStream, &counter, 8);
					xtea_encrypt(cipherStream, __llvmsgx_enclave_data.CryptoKey);
					counter++;
					cipherIndex = 0;
				}

				regionStart[j] ^= ((char*)cipherStream)[cipherIndex++];
			}
		}

		__llvmsgx_enclave_data.Encrypted = false;
	}

	__llvmsgx_enclave_switchboard(func_index, frame);

	// EEXIT back to entering caller.
	__asm__ volatile(
			"enclu"
			:
			: "a"((uint64_t)ENCLU_EEXIT),
			  "b"(0));
	__builtin_unreachable();
}

tcs_t *__llvmsgx_enclave_tcs;

void __llvmsgx_enclave_init()
{
	if (!sgx_init())
	{
		fprintf(stderr, "sgx_init failed\n");
		abort();
	}

	size_t sectionSize = (size_t)((char*)&__stop_sgxtext - (char*)&__start_sgxtext);
	// SGX only deals in full pages, so round up to nearest full page
	size_t alignedSectionSize = (sectionSize + (PAGE_SIZE - 1)) / PAGE_SIZE * PAGE_SIZE;

	void *mem = aligned_alloc(PAGE_SIZE, alignedSectionSize);
	memset(mem, 0, alignedSectionSize);
	memcpy(mem, &__start_sgxtext, sectionSize);

	unsigned int entryOffset =
		(unsigned int)((char*)__llvmsgx_enclave_entry - (char*)&__start_sgxtext);

	tcs_t *tcs = init_enclave(mem, entryOffset, alignedSectionSize / PAGE_SIZE, 0);
	if (tcs == 0)
	{
		fprintf(stderr, "could not init enclave\n");
		abort();
	}

	__llvmsgx_enclave_tcs = tcs;
	free(mem);
}
