#include "attack.h"

#define SAMPLE_SIZE 1000

// I know we should be smarter than to use printf debugging, but when it's so
// easy, why not?
#define GOT printf("Got to %d\n", __LINE__);

pid_t pid = 0;            // process ID (of either parent or child) from fork

int target_raw[2];        // unbuffered communication: attacker -> attack target
int attack_raw[2];        // unbuffered communication: attack target -> attacker

FILE* target_out = NULL;  // buffered attack target input  stream
FILE* target_in  = NULL;  // buffered attack target output stream

uint32_t  *T_lens;        // Trace Lengths
uint8_t  **T;             // Trace Values
char     **P;             // Plaintext Messages

/**
 * Interacts with the attack target, putting the results in the global arrays
 * Arguments:
 *   j     - The block address for the target to decrypt. Valid inputs are
 *           0 <= u < 256, but input type allows for invalid inputs ;)
 *   i     - The sector address for the target to decrypt (XTS Tweak).
 *   index - The (empty) index in the global arrays to write to. Note this does
 *           not check for already occupied indexes.
 */
void interact(const int16_t j, const uint32_t i, const uint32_t index)
{
	// Send i and j to the attack target
	fprintf(target_in, "%d\n%032x\n", j, i);
	fflush(target_in);

	// Receive length of power trace from attack target
	if (1 != fscanf(target_out, "%u", &T_lens[index])) abort();

	// Allocate memory for and recieve the traces
	T[index] = malloc(sizeof(uint8_t) * T_lens[index]);
	for (int i = 0; i < T_lens[index]; i++) {
		if (1 != fscanf(target_out, ",%hhu", &T[index][i])) abort();
	}

	// Allocate memory for and recieve the plaintext message
	P[index] = malloc(sizeof(char) * 32);
	if (1 != fscanf(target_out, "\n%32c", P[index])) abort();
}

/**
 * Collects all SAMPLE_SIZE samples, using an invalid block such that the
 * ciphertext used is null - as per the target specification.
 */
void collect_samples()
{
	for (int i = 0; i < SAMPLE_SIZE; i++) {
		interact(-1, i, i);
	}
}

/**
 * Main Attack Function; Orchestrates the attack on the XTS-AES target.
 */
void attack()
{
	// Initialise memory, and collect all the samples that will be used for
	// the attack.
	T_lens = malloc(sizeof( uint32_t) * SAMPLE_SIZE); // Global
	T      = malloc(sizeof(uint8_t *) * SAMPLE_SIZE); // Global
	P      = malloc(sizeof(   char *) * SAMPLE_SIZE); // Global
	collect_samples();
}

/**
 * Cleans up all used resources and then exits the program with the given code.
 * Arguments:
 *   s - Exit Signal
 */
void cleanup(int s)
{
	// Frees the memory that was allocated.
	free(T_lens);
	for (int i = 0; i < SAMPLE_SIZE; i++) {
		free(T[i]);
		free(P[i]);
	}

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


