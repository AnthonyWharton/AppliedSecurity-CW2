#include "attack.h"
#include "consts.h"

// The number of power trace samples to use for this attack
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

// Gets the N'th byte (0 <= N < 16) of an AES 128 block (starting with the 0th
// byte being the most significant, and the 15th being the least significant).
#define AES128_BYTE(AES_BLOCK, N) ((AES_BLOCK >> (128 - (8*N))) & 0xFF)

// Converts a single ASCII character C, to a binary integer value
#define ASCII_HEXTOI(C) ((C > '9') ? (C & ~0x20) - 'A' + 10 : C - '0')

static pid_t pid = 0;              // Process ID (of either parent or child) from fork

static int target_raw[2];          // Unbuffered communication: attacker -> attack target
static int attack_raw[2];          // Unbuffered communication: attack target -> attacker

static FILE* target_out = NULL;    // Buffered attack target input  stream
static FILE* target_in  = NULL;    // Buffered attack target output stream

static uint8_t  **Sectors = NULL;
static uint32_t   T_alloc = 0;     // Number of allocated traces
static uint32_t   T_len   = UINT32_MAX; // Length for which all traces have values
static uint32_t  *T_lens  = NULL;  // Trace Lengths
static uint8_t  **T       = NULL;  // Trace Values
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
	// Send i and j to the attack target
	fprintf(target_in, "%d\n", j);
	for (uint8_t b = 0; b < 16; b++)
		fprintf(target_in, "%02x", Sectors[b][sample]);
	fprintf(target_in, "\n");
	fflush(target_in);

	// Receive length of power trace from attack target
	if (1 != fscanf(target_out, "%u", &T_lens[sample])) abort();

	// Dynamically (Re)Allocate memory for T if required
	if (T_lens[sample] >= T_alloc) {
		// Round up allocated traces to the nearest 16
		uint32_t old_T_alloc = T_alloc;
		T_alloc = T_lens[sample] + 16 + (T_lens[sample] % 16);

		// Reallocate memory safely
		uint8_t **_tmp_T = realloc(T, sizeof(uint8_t *) * T_alloc);
		if (_tmp_T == NULL) {
			printf("Error reallocating T ("__FILE__":%d)\n", __LINE__);
			abort();
		}
		T = _tmp_T;

		// Initialise second dimension of array
		for (uint32_t i = old_T_alloc; i < T_alloc; i++) {
			T[i] = malloc(sizeof(uint8_t) * SAMPLE_SIZE);
		}
	}

	// Update maximum safe T_len (value for which all traces have at least
	// that number of traces)
	if (T_lens[sample] < T_len) T_len = T_lens[sample];

	// Recieve the traces
	// Note: This is stored in column major order, so correlation
	// calculations later in the attack can be row major, thus slightly
	// faster
	for (int i = 0; i < T_lens[sample]; i++) {
		if (1 != fscanf(target_out, ",%hhu", &T[i][sample])) abort();
	}

	// Recieve the plaintext message
	char buf[33];
	if (1 != fscanf(target_out, "\n%32s", buf)) abort();

	// Work out length of the input
	uint8_t len = 32;
	while (buf[len] != '\0' && len >= 0) len--;
	if (len != 32) {
		printf("WARNING! Read HEX Plaintext that was not 32 "
		       "characters, parsing of this is not "
		       "implemented.\n");
		abort();
	}

	// Convert the recieved plaintext into bytes
	for (uint8_t i = 0; i < 16; i++) {
		P[i][sample] = (ASCII_HEXTOI(buf[ 2*i     ]) << 4)
		             | (ASCII_HEXTOI(buf[(2*i) + 1])     );
	}
}

/**
 * Collects all SAMPLE_SIZE samples, using an invalid block such that the
 * ciphertext used is null - as per the target specification.
 */
static void collect_samples()
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

	// Get all our samples from the target
	for (int s = 0; s < SAMPLE_SIZE; s++) {
		interact(s, s);
	}

	printf("[INIT] %d samples read in succesfully!\n", SAMPLE_SIZE);
	printf("[INIT] Trace length for attack is %d.\n\n", T_len);
}

/**
 * Internal function used to create 256 key hypotheses for the given sample and
 * AES byte.
 */
static inline void _create_key_hypotheses(const uint8_t    b, 
                                          const uint16_t   k, 
                                                uint8_t  **h, 
                                                uint8_t  **p)
{
	// For each sample
	for (uint32_t sample = 0; sample < SAMPLE_SIZE; sample++) {
		// Calculate hypothetical power consumption (hamming weight of
		// SBox calculation on `plaintext ^ key_hypothesis`)
		uint8_t t = s[p[b][sample] ^ k];
		h[(256*b) + k][sample] = __builtin_popcount(t);
	}
}

/**
 * Generates the hypotheses power values as if running through SBOX in the first
 * round of AES-128.
 */
static void generate_hyp_sbox(uint8_t **h, uint8_t **p)
{
	printf("[HYPO] Starting generation of hypothetical power "
	       "consumptions...\n");


	// For each byte in the plaintext
	for (uint8_t b = 0; b < 16; b++) {
		// For each different key hypothesis
		for (uint16_t k = 0; k < 256; k++) {
			_create_key_hypotheses(b, k, h, p);
		}
	}

	printf("[HYPO] Completed generation of hypothtical power "
	       "consumptions!\n\n");
}

static void initialise_hypotheses(uint8_t ***h)
{
	*h = malloc(sizeof(uint8_t *) * 16 * 256);
	for (uint16_t i = 0; i < 16*256; i++)
		(*h)[i] = malloc(sizeof(uint8_t) * SAMPLE_SIZE);

}

static inline void work_over_samples(const uint16_t   b,
                                     const uint16_t   k,
                                     const uint32_t   t,
                                           uint8_t  **hyp,
                                           uint8_t  **trc,
                                           double    *ans)
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

	// Pearson Correlation Coefficient
	// https://en.wikipedia.org/wiki/Pearson_correlation_coefficient
	*ans = ((SAMPLE_SIZE * sig_kt) - (sig_k * sig_t))
	     / (
	        sqrt((SAMPLE_SIZE * sig_k2) - (sig_k * sig_k)) *
                sqrt((SAMPLE_SIZE * sig_t2) - (sig_t * sig_t))
               );
}

static void correlate_data(uint8_t **key, uint8_t **hyp, uint8_t **trc)
{
	printf("[CORR] Starting Key Guess/Correlation Calculation...\n");

	// Initialise Memory
	*key = malloc(sizeof(uint8_t) * 16);
	memset(*key, 0, sizeof(uint8_t) * 16);
	double working = 0.f; // Working value for correlation values

	// For each byte of the key
	for (uint16_t b = 0; b < 16; b++) {
		printf("[CORR] +-- Starting Byte %d...\n", b);
		double bestC = 0.f; // Best correlation value for this byte
		// For each key hypothesis
		#pragma omp parallel for private(working) schedule(dynamic)
		for (uint16_t k = 0; k < 256; k++) {
			// For each trace timestep value
			for (uint32_t t = 0; t < T_len; t++) {
				// Calculate Correlation
				work_over_samples(b, k, t, hyp, trc, &working);
				(*key)[b] = working > bestC ? k : (*key)[b];
				bestC     = working > bestC ? working : bestC;
			}
		}
		printf("[CORR] | Estimate of Key Byte: %02X\n",  (*key)[b]);
		printf("[CORR] | Power Trace Correlation: %f\n", bestC);
	}
	printf("[CORR] +-- Completed Key Guess/Correlation Calculation!\n");
	printf("[CORR] Found Key: ");
	for (uint8_t b = 0; b < 16; b++) printf("%02X", (*key)[b]);
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
 * Sets up an EVP Context for encryption of AES128 blocks. No validation is done
 * on the given key pointer.
 */
static EVP_CIPHER_CTX *aes128_block_setup(const uint8_t *key)
{
	EVP_CIPHER_CTX *ctx = NULL;

	// Create EVP Context
	if (!(ctx = EVP_CIPHER_CTX_new()))
		evp_handle_error();

	// Give EVP Context the AES Key
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, 0))
		evp_handle_error();

	return ctx;
}

/**
 * Encrypts a single 16 byte plaintext block.
 */
static void aes128_block_encrypt(EVP_CIPHER_CTX *ctx, 
		                 uint8_t        *p,
		                 uint8_t        *c)
{
	int _ = 0;
	if (1 != EVP_EncryptUpdate(ctx, c, &_, p, 16)) 
		evp_handle_error();
	// Ommited EVP_EncryptFinal_ex() as we are only encrypting one block
}

/**
 * Encrypts all sectors with Key 2 in preparation for attacking Key 1
 */
static void encrypt_sectors()
{
	printf("[MISC] Encrypting sectors for next stage of the attack...\n");
	EVP_CIPHER_CTX *ctx = aes128_block_setup(K2);

	// Initialise global memory
	I = malloc(sizeof(uint8_t *) * 16);
	for (uint8_t i = 0; i < 16; i++) 
		I[i] = malloc(sizeof(uint8_t) * SAMPLE_SIZE);

	// Initialise local memory
	uint8_t *p = malloc(sizeof(uint8_t) * 16);
	uint8_t *c = malloc(sizeof(uint8_t) * 16);
	for (uint32_t s = 0; s < SAMPLE_SIZE; s++) {
		// Extract column (sample) from Sectors array
		for (uint8_t b = 0; b < 16; b++) {
			p[b] = Sectors[b][s];
		}

		aes128_block_encrypt(ctx, p, c);

		// Put column (sample) into the intermediate value array
		for (uint8_t b = 0; b < 16; b++) {
			p[b] = I[b][s];
		}
	}
	free(p);
	free(c);

	EVP_CIPHER_CTX_free(ctx);
	printf("[MISC] Done! Ready to attack Key 1\n\n");
}

/**
 * Main Attack Function; Orchestrates the attack on the XTS-AES target.
 */
static void attack()
{
	// Save start time
	c_start = clock();
	clock_gettime(CLOCK_MONOTONIC, &r_start);

	// Collect all samples required for the attack
	collect_samples();

	// Generate hypothetical power values for key 2
	initialise_hypotheses(&H);
	generate_hyp_sbox(H, Sectors);

	// Calculate correlation/find key 2
	correlate_data(&K2, H, T);

	// Intermediate step, encrypt sectors to create plaintext for the attack
	// on key 1
	encrypt_sectors();

	// Save end time
	c_end = clock();
	clock_gettime(CLOCK_MONOTONIC, &r_end);

	// Calculate duration and print out
	double r_elapsed =  (r_end.tv_sec  - r_start.tv_sec)
		         + ((r_end.tv_nsec - r_start.tv_nsec) / 1000000000.0);
	double c_elapsed = (double) (c_end - c_start) / CLOCKS_PER_SEC;
	printf("Time Taken: real - %fs\n", r_elapsed);
	printf("        user+sys - %fs\n", c_elapsed);

}

/**
 * Cleans up all used resources and then exits the program with the given code.
 * Arguments:
 *   s - Exit Signal
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
	if (pid > 0) {
		kill(pid, SIGKILL);
	}

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
		// The fork failed; reason is stored in errno, but we'll just abort.
		abort();
	}

	// Clean up any resources we've hung on to.
	cleanup(EXIT_SUCCESS);

	return 0;
}


