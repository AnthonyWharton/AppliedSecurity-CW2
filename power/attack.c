#include "attack.h"
#include "consts.h"

// The number of power trace samples to use for this attack.
#define SAMPLE_SIZE 20

// I know we should be smarter than to use printf debugging, but when it's so
// easy, why not?
#define GOT printf("Got to %d\n", __LINE__);

// Checks if a pointer is not NULL, frees the memory and sets the pointer to
// NULL. Does not check if pointer points to heap memory.
#define FREE_AND_NULLIFY(VAR) if (VAR) { free(VAR); VAR = NULL; }

// Performs FREE_AND_NULLIFY on an array (VAR) of pointers sized (SIZE). Upon
// freeing all pointers within the array, the array itself is freed.
#define FREE_AND_NULLIFY_MULTIPLE(VAR, SIZE)                                   \
	if (VAR) {                                                             \
		for (uint32_t VAR##_ctr = 0; VAR##_ctr < SIZE; VAR##_ctr++)    \
			FREE_AND_NULLIFY(VAR[VAR##_ctr])                       \
		FREE_AND_NULLIFY(VAR);                                         \
	}

// Converts a single ASCII character C, to a binary integer value.
#define ASCII_HEXTOI(C) ((C > '9') ? (C & ~0x20) - 'A' + 10 : C - '0')

static pid_t pid = 0;              // Process ID from fork

static int target_raw[2];          // Unbuffered comms: attacker -> target
static int attack_raw[2];          // Unbuffered comms: target -> attacker

static FILE* target_out = NULL;    // Buffered attack target input  stream
static FILE* target_in  = NULL;    // Buffered attack target output stream

static uint8_t  **Sectors = NULL;
static uint32_t   T_alloc = 0;     // Number of allocated traces
static uint32_t   T_len   = UINT32_MAX; // Length that all traces have values
static uint32_t  *T_lens  = NULL;  // Full Trace Lengths
static uint8_t  **T       = NULL;  // Trace Power Values
static uint8_t  **P       = NULL;  // Plaintext Message Bytes
static uint8_t  **H       = NULL;  // Hypothetical Power Traces
static uint8_t  **I       = NULL;  // Intermediate values between 1st/2nd stage
static uint8_t   *K1      = NULL;  // Key 1 Bytes
static uint8_t   *K2      = NULL;  // Key 2 Bytes

static clock_t c_start;            // CPU time at start of attack
static clock_t c_end;              // CPU time up until this variable was set
static struct timespec r_start;    // Real time at start of attack
static struct timespec r_end;      // Real time up until this variable was set

/**
 * Initialises the memory for a 2D hypothetical power consumption array of
 * dimension h[16*256][SAMPLE_SIZE].
 * Arguments:
 *   h - The hypothetical power traces pointer to allocate at.
 */
static void initialise_hypotheses(uint8_t ***h)
{
	*h = malloc(sizeof(uint8_t *) * 16 * 256);
	for (uint16_t i = 0; i < 16*256; i++)
		(*h)[i] = malloc(sizeof(uint8_t) * SAMPLE_SIZE);

}

/**
 * Initialises the memory for the keys to be put in once worked out.
 * Arguments:
 *   K1 - Pointer for Key 1 Bytes
 *   K2 - Pointer for Key 2 Bytes
 */
static void initialise_keys(uint8_t **K1, uint8_t **K2)
{
	*K1 = malloc(sizeof(uint8_t) * 16);
	memset(*K1, 0, sizeof(uint8_t) * 16);
	*K2 = malloc(sizeof(uint8_t) * 16);
	memset(*K2, 0, sizeof(uint8_t) * 16);
}

/**
 * Interacts with the attack target, putting the results in the global arrays.
 * NOT thread safe.
 * Arguments:
 *   j      - The block address for the target to decrypt. Valid inputs are
 *            0 <= u < 256, but input type allows for invalid inputs ;)
 *   sample - The (empty) index in the global arrays to write to. Note this does
 *            not check for already occupied indexes.
 */
static void interact(const int16_t  j,
                     const uint32_t sample)
{
	// Send i and j to the attack target.
	fprintf(target_in, "%d\n", j);
	for (uint8_t b = 0; b < 16; b++)
		fprintf(target_in, "%02x", Sectors[b][sample]);
	fprintf(target_in, "\n");
	fflush(target_in);

	// Receive length of power trace from attack target.
	if (1 != fscanf(target_out, "%u", &T_lens[sample])) abort();

	// Dynamically (Re)Allocate memory for T if required.
	if (T_lens[sample] >= T_alloc) {
		// Round up allocated traces to the nearest 16.
		uint32_t old_T_alloc = T_alloc;
		T_alloc = T_lens[sample] + 16 + (T_lens[sample] % 16);

		// Reallocate memory safely,
		uint8_t **_tmp_T = realloc(T, sizeof(uint8_t *) * T_alloc);
		if (_tmp_T == NULL) {
			printf("Error reallocating T ("__FILE__":%d)\n", __LINE__);
			abort();
		}
		T = _tmp_T;

		// Initialise second dimension of array,
		for (uint32_t i = old_T_alloc; i < T_alloc; i++) {
			T[i] = malloc(sizeof(uint8_t) * SAMPLE_SIZE);
		}
	}

	// Update maximum safe T_len (value for which all traces have at least
	// that number of traces),
	if (T_lens[sample] < T_len) T_len = T_lens[sample];

	// Recieve the traces.
	// Note: This is stored in column major order, so correlation
	// calculations later in the attack can be row major, thus slightly
	// faster.
	for (int i = 0; i < T_lens[sample]; i++) {
		if (1 != fscanf(target_out, ",%hhu", &T[i][sample])) abort();
	}

	// Recieve the plaintext message.
	char buf[33];
	if (1 != fscanf(target_out, "\n%32s", buf)) abort();

	// Work out length of the input.
	uint8_t len = 32;
	while (buf[len] != '\0' && len >= 0) len--;
	if (len != 32) {
		printf("WARNING! Read HEX Plaintext that was not 32 "
		       "characters, parsing of this is not "
		       "implemented.\n");
		abort();
	}

	// Convert the recieved plaintext into byte.
	for (uint8_t i = 0; i < 16; i++) {
		P[i][sample] = (ASCII_HEXTOI(buf[ 2*i     ]) << 4)
		             | (ASCII_HEXTOI(buf[(2*i) + 1])     );
	}
}

/**
 * Collects all SAMPLE_SIZE samples, using an invalid block such that the
 * ciphertext used is null - as per the target specification.
 */
static void init_and_collect_samples()
{
	printf("[INIT] Starting Collection of %d samples...\n", SAMPLE_SIZE);

	int random = open("/dev/urandom", O_RDONLY);
	if (random < 0) {
		printf("Error trying to open /dev/urandom\n");
		abort();
	}

	// Initialise Global Memory.
	// Note: T is allocated dynamically within interact().
	T_lens  = malloc(sizeof(uint32_t  ) * SAMPLE_SIZE);
	P       = malloc(sizeof( uint8_t *) * 16);
	Sectors = malloc(sizeof( uint8_t *) * 16);
	for (uint8_t i = 0; i < 16; i++) {
		P[i]       = malloc(sizeof(uint8_t) * SAMPLE_SIZE);
		Sectors[i] = malloc(sizeof(uint8_t) * SAMPLE_SIZE);

		// Generate random sectors (XTS tweaks) for the target.
		if (read(random, Sectors[i], SAMPLE_SIZE) < 0) {
			printf("Error trying to read /dev/urandom\n");
			abort();
		}
	}
	close(random);

	for (uint8_t i = 0; i < 16; i++) {
		Sectors[i][0] = 0xFF;
	}

	// Get all our samples from the target.
	for (uint32_t s = 0; s < SAMPLE_SIZE; s++) {
		// Ensure all sectors are invalid for ciphertext exploit.
		if (!Sectors[0][s]) Sectors[0][s] += 1;
		interact(0, s);
	}

	printf("[INIT] %d samples read in succesfully!\n", SAMPLE_SIZE);
	printf("[INIT] Trace length for attack is %d.\n\n", T_len);
}

/**
 * Internal function used to create 256 key hypotheses for the given sample and
 * AES byte.
 * Arguments:
 *   b    - The current byte we are iterating over.
 *   k    - The current key hypothesis we are iterating over.
 *   sbox - The sbox that we are using.
 *   h    - The key hypotheses array we are using.
 *   p    - The plaintext to use for this key hypothesis generation.
 */
static inline void _create_key_hypotheses(const uint8_t         b,
                                          const uint16_t        k,
                                          const unsigned char   sbox[256],
                                                uint8_t       **h,
                                                uint8_t       **p)
{
	// For each sample.
	for (uint32_t sample = 0; sample < SAMPLE_SIZE; sample++) {
		// Calculate hypothetical power consumption (hamming weight of
		// SBox calculation on `plaintext ^ key_hypothesis`).
		uint8_t t = sbox[p[b][sample] ^ k];
		h[(256*b) + k][sample] = __builtin_popcount(t);
	}
}

/**
 * Generates the hypotheses power values as if running through SBOX in the first
 * round of AES-128.
 * Arguments:
 *   sbox - The sbox that we are using.
 *   h    - The key hypotheses array we are using.
 *   p    - The plaintext to use for this key hypothesis generation.
 */
static void generate_hyp_sbox(const unsigned char  sbox[256],
                                    uint8_t       **h,
                                    uint8_t       **p)
{
	printf("[HYPO] Starting generation of hypothetical power "
	       "consumptions...\n");

	// For each byte in the plaintext.
	for (uint8_t b = 0; b < 16; b++) {
		// For each different key hypothesis.
		for (uint16_t k = 0; k < 256; k++) {
			_create_key_hypotheses(b, k, sbox, h, p);
		}
	}

	printf("[HYPO] Completed generation of hypothtical power "
	       "consumptions!\n\n");
}

/**
 * Worker function for correlate_data(), calculates the Pearson Correlation.
 * Coefficient: https://en.wikipedia.org/wiki/Pearson_correlation_coefficient
 * Arguments:
 *   b   - The current byte we are iterating over.
 *   k   - The current key hypothesis we are iterating over.
 *   t   - The current trace power value we are iterating over.
 *   hyp - The key hypotheses array we are using.
 *   trc - The traces array we are using.
 */
static inline double work_over_samples(const uint16_t   b,
                                       const uint16_t   k,
                                       const uint32_t   t,
                                             uint8_t  **hyp,
                                             uint8_t  **trc)
{
	double sig_kt = 0.f;  // Σ (k*t)
	double sig_k  = 0.f;  // Σ ( k )
	double sig_t  = 0.f;  // Σ ( t )
	double sig_k2 = 0.f;  // Σ (k*k)
	double sig_t2 = 0.f;  // Σ (t*t)

	for (uint32_t sample = 0; sample < SAMPLE_SIZE; sample++) {
		double kk = (double) hyp[(256*b) + k][sample];
		double tt = (double) trc[     t     ][sample];
		sig_kt += kk * tt;
		sig_k  += kk;
		sig_t  += tt;
		sig_k2 += kk * kk;
		sig_t2 += tt * tt;
	}

	return ((SAMPLE_SIZE * sig_kt) - (sig_k * sig_t))
	       / (
	          sqrt((SAMPLE_SIZE * sig_k2) - (sig_k * sig_k)) *
                  sqrt((SAMPLE_SIZE * sig_t2) - (sig_t * sig_t))
                 );
}

/**
 * Correlates hypothetical power values for key hypotheses with the collected
 * trace power values, and then works out the most likely key.
 * Arguments:
 *   key - The key array to store the broken key in.
 *   hyp - The key hypotheses array we are using.
 *   trc - The traces array we are using.
 */
static void correlate_data(uint8_t *key, uint8_t **hyp, uint8_t **trc)
{
	printf("[CORR] +-- Starting Key Guess/Correlation Calculation...\n");

	// Initialise Memory.
	double  working = 0.f;

	// For each byte of the key,
	#pragma omp parallel for private(working) schedule(dynamic)
	for (uint16_t b = 0; b < 16; b++) {
		double bestC = 0.f;
		// For each key hypothesis.
		for (uint16_t k = 0; k < 256; k++) {
			// For each trace timestep value.
			for (uint32_t t = 0; t < T_len; t++) {
				// Calculate Correlation.
				working = work_over_samples(b, k, t, hyp, trc);
				key[b]  = working > bestC  ?    k    : key[b];
				bestC   = working > bestC  ? working : bestC;
			}
		}
		printf("[CORR] | Byte %02d... Key: %02X, Correlation: %f\n", 
		       b, key[b], bestC);
	}
	printf("[CORR] +-- Completed Key Guess/Correlation Calculation!\n");
	printf("[CORR] Found Key: ");
	for (uint8_t b = 0; b < 16; b++) printf("%02X", key[b]);
	printf("\n\n");
}

/**
 * Prints an error from OpenSSL (Used for EVP Encryption/Decryption) and aborts.
 */
static void evp_handle_error()
{
	ERR_print_errors_fp(stderr);
	abort();
}

/**
 * Encrypts a single 16 byte plaintext block with AES-128.
 * Argumnets:
 *   key - Array of the key to encrypt with.
 *   p   - Array with 16 plaintext bytes to encrypt.
 *   c   - Array with 16 ciphertext bytes to put encryption in.
 */
static void aes128enc_block(uint8_t *key, uint8_t *p, uint8_t *c)
{
	EVP_CIPHER_CTX *ctx = NULL;

	// Create EVP Context.
	if (!(ctx = EVP_CIPHER_CTX_new()))
		evp_handle_error();

	// Give EVP Context the AES Key.
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, 0))
		evp_handle_error();

	// Actually encrypt the plaintext byte.
	int _ = 0;
	if (1 != EVP_EncryptUpdate(ctx, c, &_, p, 16))
		evp_handle_error();
	// Ommited EVP_EncryptFinal_ex() as we are only encrypting one block.
	EVP_CIPHER_CTX_free(ctx);
}

/**
 * Decrypts a single 16 byte plaintext block with AES-128.
 * Argumnets:
 *   key - Array of the key to decrypt with.
 *   c   - Array with 16 ciphertext bytes to decrypt.
 *   d   - Array with 16 plaintext bytes to put decryption in.
 */
static void aes128dec_block(uint8_t *key, uint8_t *c, uint8_t *p)
{
	EVP_CIPHER_CTX *ctx = NULL;

	// Create EVP Context.
	if (!(ctx = EVP_CIPHER_CTX_new()))
		evp_handle_error();

	// Give EVP Context the AES Key.
	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, 0))
		evp_handle_error();

	// Actually decrypt the ciphertext byte.
	int _ = 0;
	if (1 != EVP_DecryptUpdate(ctx, p, &_, c, 16))
		evp_handle_error();
	// Ommited EVP_DecryptFinal_ex() as we are only decrypting one block.
	EVP_CIPHER_CTX_free(ctx);
}

/**
 * Encrypts all sectors with Key 2 in preparation for attacking Key 1.
 */
static void encrypt_sectors()
{
	printf("[ENCR] Encrypting sectors for next stage of the attack...\n");

	// Initialise global memory.
	I = malloc(sizeof(uint8_t *) * 16);
	for (uint8_t i = 0; i < 16; i++)
		I[i] = malloc(sizeof(uint8_t) * SAMPLE_SIZE);

	// Initialise local memory.
	uint8_t *p = malloc(sizeof(uint8_t) * 16);
	uint8_t *c = malloc(sizeof(uint8_t) * 16);

	// Encrypt all samples.
	for (uint32_t s = 0; s < SAMPLE_SIZE; s++) {
		for (uint8_t b = 0; b < 16; b++) p[b] = Sectors[b][s];
		aes128enc_block(K2, p, c);
		for (uint8_t b = 0; b < 16; b++) I[b][s] = c[b];
	}

	free(p);
	free(c);
	printf("[ENCR] Done! Ready to attack Key 1\n\n");
}

/**
 * XOR's the plaintext recieved from the target with the intermediate values
 * (used for a backwards attack on Key 1).
 */
static void xor_intermediates()
{
	for (uint8_t b = 0; b < 16; b++) {
		for (uint32_t s = 0; s < SAMPLE_SIZE; s++) {
			I[b][s] ^= P[b][s];
		}
	}
}

/**
 * Decrypts first sectors with Key 1 to verify attack.
 */
static int verify()
{
	printf("[VRFY] Decrypting first block to verify key...\n");

	// Initialise local memory.
	uint8_t *p = malloc(sizeof(uint8_t) * 32);
	uint8_t *c = malloc(sizeof(uint8_t) * 16);

	// Decrypt all samples.
	for (uint32_t s = 0; s < SAMPLE_SIZE; s++) {
		for (uint8_t b = 0; b < 16; b++) c[b] = I[b][s] ^ P[b][s];
		aes128dec_block(K1, c, p);
		for (uint8_t b = 0; b < 16; b++) if (I[b][s] != p[b]) return 0;
	}

	free(p);
	free(c);
	printf("[VRFY] Self verification succeeded!\n\n");
	return 1;
}

/**
 * Main Attack Function; Orchestrates the attack on the XTS-AES target.
 */
static void attack()
{
	// Save start time.
	c_start = clock();
	clock_gettime(CLOCK_MONOTONIC, &r_start);

	// Initialise memory and collect all samples required for the attack.
	init_and_collect_samples();
	initialise_hypotheses(&H);
	initialise_keys(&K1, &K2);

	// First Stage, attacking Key 2 as per the XTS-AES spec.
	// 1) Generate hypothetical power values for key 2.
	// 2) Calculate correlation and find key 2.
	generate_hyp_sbox(s, H, Sectors);
	correlate_data(K2, H, T);

	// Intermediate step, encrypt sectors to create plaintext for the
	// attack on key 1.
	encrypt_sectors();
	xor_intermediates();

	// Second Stage, attack Key 1 as per the XTS-AES spec..
	//  1) Generate hypothetical power values for plaintexts returned from
	//     the target - We plan to attack key 1 backwards.
	//  2) Calculate correlation and find key 1.
	generate_hyp_sbox(s, H, I);
	correlate_data(K1, H, T);

	// Verify Attack Succeded.
	if (!verify()) {
		printf("Self verification failed, please try again.\n");
		abort();
	}

	// Save end time.
	c_end = clock();
	clock_gettime(CLOCK_MONOTONIC, &r_end);

	// Calculate duration.
	double r_elapsed =  (r_end.tv_sec  - r_start.tv_sec)
		         + ((r_end.tv_nsec - r_start.tv_nsec) / 1000000000.0);
	double c_elapsed = (double) (c_end - c_start) / CLOCKS_PER_SEC;

	// Final printout.
	printf("+++++++++++++++++++ KEY FOUND +++++++++++++++++++\n");
	printf("Time Taken: real - %fs\n", r_elapsed);
	printf("        user+sys - %fs\n", c_elapsed);

	printf("\nExtracted Material: ");
	for (uint8_t i = 0; i < 16; i++) printf("%02X", K1[i]);
	for (uint8_t i = 0; i < 16; i++) printf("%02X", K2[i]);
	printf("\nInteractions with Target: %d\n", SAMPLE_SIZE);
}

/**
 * Cleans up all used resources and then exits the program with the given code.
 * Arguments:
 *   s - Exit Signal.
 */
static void cleanup(int s)
{
	// Frees the memory that was allocated.
	FREE_AND_NULLIFY_MULTIPLE(Sectors,  16)
	FREE_AND_NULLIFY(T_lens)
	FREE_AND_NULLIFY_MULTIPLE(T,   T_alloc)
	FREE_AND_NULLIFY_MULTIPLE(P,        16)
	FREE_AND_NULLIFY_MULTIPLE(H,  16 * 256)
	FREE_AND_NULLIFY_MULTIPLE(I,        16)
	FREE_AND_NULLIFY(K1);
	FREE_AND_NULLIFY(K2);

	// Close the buffered communication handles.
	fclose(target_in );
	fclose(target_out);

	// Close the unbuffered communication handles.
	close(target_raw[0]);
	close(target_raw[1]);
	close(attack_raw[0]);
	close(attack_raw[1]);

	// Forcibly terminate the attack target process.
	if (pid > 0)
		kill(pid, SIGKILL);

	// Forcibly terminate the attacker process with the given signal.
	exit(s);
}

int main(int argc, char* argv[])
{
	// Ensure we clean-up correctly if Control-C (or similar) is signalled.
	signal(SIGINT, &cleanup);

	// Create pipes to/from attack target
	if (pipe(target_raw) == -1) abort();
	if (pipe(attack_raw) == -1) abort();

	pid = fork();

	if (pid > 0) { // parent
		// Construct handles to attack target standard input and output.
		if ((target_out = fdopen(attack_raw[0], "r")) == NULL) abort();
		if ((target_in  = fdopen(target_raw[1], "w")) == NULL) abort();

		// Execute a function representing the attacker.
		attack();
	} else if (pid == 0) { // child
		// (Re)connect standard input and output to pipes.
		close( STDOUT_FILENO );
		if (dup2(attack_raw[1], STDOUT_FILENO) == -1) abort();

		close(  STDIN_FILENO );
		if (dup2(target_raw[0],  STDIN_FILENO) == -1) abort();

		// Produce a sub-process representing the attack target.
		execl(argv[1], argv[0], NULL );
	} else if (pid < 0) { // error
		// The fork failed; reason is stored in errno, but we'll abort.
		abort();
	}

	// Clean up any resources we've hung on to.
	cleanup(EXIT_SUCCESS);

	return 0;
}


