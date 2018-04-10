#!/bin/python2.7
import sys, subprocess, random, time
from Crypto.Cipher import AES
from aes_misc import *

# Reference 1:
# Tunstall, M., Mukhopadhyay, D. and Ali, S., 2011, June. Differential fault
# analysis of the advanced encryption standard using a single fault. In IFIP
# International Workshop on Information Security Theory and Practices
# (pp. 224-233). Springer, Berlin, Heidelberg.

################################################################################
# Generates random 128 bit plaintexts
# Arguments:
#   sample_size - integer: Number of ciphertexts to generate
# Return:
#   [integer]: A list of randomly generated sample plaintexts in integer form
def generate_plaintexts(sample_size):
	rng = random.SystemRandom()
	samples = []
	for i in range(sample_size):
		c = rng.getrandbits(128)
		samples.append(c)
	return samples

################################################################################
# Feeds a given fault_spec and plaintext to the target, and returns the
# ciphertext = aes_encrypt(plaintext)
# Arguments:
#   target     - subprocess: Target to interact with
#   fault_spec - string:     Specification for the fault
#   plaintext  - string:     Challenge RSAES-OAP Ciphertext
# Return:
#   integer: The encrypted ciphertext
_interaction_count = 0 # Global challenge/interaction count
def interact(target, fault_spec, plaintext):
	target.stdin.write(fault_spec + "\n")
	target.stdin.write(plaintext + "\n")
	target.stdin.flush()
	global _interaction_count
	_interaction_count = _interaction_count + 1
	c = int(target.stdout.readline().strip(), 16)
	return c

################################################################################
# Generates global multiplication table under gf 2^8 (Rijndael's Finite Field)
m = [[gf28_mul(i,j) for i in range(256)] for j in range(256)]

################################################################################
# Gets the n'th byte from the 128 bit binary number. (0 indexed)
# Arguments:
#   b - integer: 128 bit binary digit to get the byte from
#   n - integer: Byte to retrieve (0 indexed)
# Return:
#   integer: The requested byte
def bl(bin, n):
	return (bin & (0xff000000000000000000000000000000 >> (8*n))) >> (120 - 8*n)

################################################################################
# Finds the intersection of two lists
# Arguments:
#   a - [type] List of any object that works with the in operator
#   b - [type] List of any object that works with the in operator
# Return:
#   [type]: list containing items that are common to a and b
def intersect(a,b):
	return [i for i in a if i in b]

################################################################################
# Initial printout for Step 1
def step1_init_printout():
	print "+-------------------------------------------------------------+"
	print "| ==================    RUNNING STEP 1    =================== |"
	print "+-------------------------------------------------------------+"
	print "| ====================   PRINTOUT KEY   ===================== |"
	print "| msg - Plaintext Message ID                                  |"
	print "| eqs - Step 1 Equation Set ID                                |"
	print "| pos - Number of possible key configurations                 |"
	print "| val - The list of actual combinations for this equation set |"
	print "+-------------------------------------------------------------+"

################################################################################
# Main calculation from Step 1 in the attack in Reference 1
# Arguments:
#   coeff    - [integer]:   List of the 4 lhs coefficients for the 4 equations
#   blocks   - [integer]:   List of the block numbers these equations use
#   sample_c - integer:     The correct sample
#   sample_f - integer:     The faulty sample
# Return:
#   [[integer]]: List of combinations of possible values that satisfy the given
#                configuration of equation
def step1_calc(coeff, blocks, sample_c, sample_f):
	global m
	if not (len(coeff) == 4) and not (len(blocks) == 4):
		raise(AssertionError, "Can only provide 4 coefficients/block ids")

	output_grouped = []
	# Checking for every possible value of delta
	for d in range(256):
		o_acc = []
		successful = True
		# Loop through the 4 'simultaneous' equations, find keys that work
		# with our value of delta
		for step in range(4):
			options = []
			for key in range(256):
				lhs = m[coeff[step]][d]
				rhs = SBox.i[bl(sample_c, blocks[step]) ^ key] \
				    ^ SBox.i[bl(sample_f, blocks[step]) ^ key]
				if lhs == rhs:
					options.append(key)
			# Check if we had any working keys, store them in our accumulator
			if len(options) > 0:
				o_acc.append(options)
			else:
				successful = False
				break # This equation didn't work so this delta can be skipped

		# If all 4 equations worked, create all permutations for output
		if successful:
			for a in o_acc[0]:
				for b in o_acc[1]:
					for c in o_acc[2]:
						for d in o_acc[3]:
							output_grouped.append([a,b,c,d])
	return output_grouped

################################################################################
# Step 1 from the attack in Reference 1
# Arguments:
#   samples_c    - [integer]: List of correct samples
#   samples_f    - [integer]: List of faulty samples
#   coeff_config - [integer]: List of the 4 lhs coefficients for the 4 equations
#   block_config - [integer]: List of the block numbers these equations use
# Return:
#   [[integer]]: 16 lists of possible keys, given the samples
def step1(samples_c, samples_f, coeff_config, block_config):
	if not len(samples_c) == len(samples_f):
		raise(AssertionError, "Samples arrays are not the same length")

	# Storage for key combinations that are common, per set of equations, over
	# multiple samples
	os = [[],[],[],[]]

	# Loop through samples, run each equation and get the key possibilities
	step1_init_printout()
	for s in range(len(samples_c)):
		for eq in range(4):
			o = step1_calc(coeff_config[eq],
			               block_config[eq],
			               samples_c[s],
			               samples_f[s])
			print "msg:"         + str(s)      + \
			      " eqs:"  + str(eq)     + \
			      " pos:" + str(len(o)) + \
			      " val:"        + str(o)

			# Keep track of the intersection of options between samples
			# This vastly narrows down the number of equations we must deal with
			if s == 0:
				os[eq] = o # First Time; store all options
			else:
				os[eq] = intersect(os[eq], o) # Else; only store intersection

	# Generate a new k from the intersection
	k_ = [[] for i in range(16)]
	for eq in range(4):
		for i in range(len(os[eq])):
			k_[block_config[eq][0]].append(os[eq][i][0])
			k_[block_config[eq][1]].append(os[eq][i][1])
			k_[block_config[eq][2]].append(os[eq][i][2])
			k_[block_config[eq][3]].append(os[eq][i][3])
		if len(os[eq]) == 0:
			raise(RuntimeError, "No intersected results found for equation set"
			                    + str(eq) + ".. Unable to continue")
	return k_

################################################################################
# Initial printout for Step 2
def step2_init_printout():
	print "\n"
	print "+-------------------------------------------------------------+"
	print "| ==================    RUNNING STEP 2    =================== |"
	print "+-------------------------------------------------------------+"

################################################################################
# Does the calculations and checks the equations specified in Step 2 of the
# attack in Reference 1
# Arguments:
#   k        - [integer]: The 16 individual bytes of the 10th round key
#   k9       - [integer]: The 16 individual bytes of the 9th round key
#   sample_c - integer:   A correct sample ciphertext
#   sample_f - integer:   A faulty sample ciphertext
# Return:
#   boolean: Whether or not the equations for Step 2 were satisfied or not
def step2_check_equation(k, k9, sample_c, sample_f):
	a   = SBox.i[ m[14][SBox.i[bl(sample_c,  0) ^ k[ 0]] ^ k9[ 0]]
	            ^ m[11][SBox.i[bl(sample_c, 13) ^ k[13]] ^ k9[ 1]]
	            ^ m[13][SBox.i[bl(sample_c, 10) ^ k[10]] ^ k9[ 2]]
	            ^ m[ 9][SBox.i[bl(sample_c,  7) ^ k[ 7]] ^ k9[ 3]] ] \
	    ^ SBox.i[ m[14][SBox.i[bl(sample_f,  0) ^ k[ 0]] ^ k9[ 0]]
	            ^ m[11][SBox.i[bl(sample_f, 13) ^ k[13]] ^ k9[ 1]]
	            ^ m[13][SBox.i[bl(sample_f, 10) ^ k[10]] ^ k9[ 2]]
	            ^ m[ 9][SBox.i[bl(sample_f,  7) ^ k[ 7]] ^ k9[ 3]] ]
	b   = SBox.i[ m[ 9][SBox.i[bl(sample_c, 12) ^ k[12]] ^ k9[12]]
	            ^ m[14][SBox.i[bl(sample_c,  9) ^ k[ 9]] ^ k9[13]]
	            ^ m[11][SBox.i[bl(sample_c,  6) ^ k[ 6]] ^ k9[14]]
	            ^ m[13][SBox.i[bl(sample_c,  3) ^ k[ 3]] ^ k9[15]] ] \
	    ^ SBox.i[ m[ 9][SBox.i[bl(sample_f, 12) ^ k[12]] ^ k9[12]]
	            ^ m[14][SBox.i[bl(sample_f,  9) ^ k[ 9]] ^ k9[13]]
	            ^ m[11][SBox.i[bl(sample_f,  6) ^ k[ 6]] ^ k9[14]]
	            ^ m[13][SBox.i[bl(sample_f,  3) ^ k[ 3]] ^ k9[15]] ]
	# Check 2*a == b (as 2^-1 === 141 under Rijndael's Galois Field)
	if m[a][141] != b:
		return False

	c   = SBox.i[ m[13][SBox.i[bl(sample_c,  8) ^ k[ 8]] ^ k9[ 8]]
	            ^ m[ 9][SBox.i[bl(sample_c,  5) ^ k[ 5]] ^ k9[ 9]]
	            ^ m[14][SBox.i[bl(sample_c,  2) ^ k[ 2]] ^ k9[10]]
	            ^ m[11][SBox.i[bl(sample_c, 15) ^ k[15]] ^ k9[11]] ] \
	    ^ SBox.i[ m[13][SBox.i[bl(sample_f,  8) ^ k[ 8]] ^ k9[ 8]]
	            ^ m[ 9][SBox.i[bl(sample_f,  5) ^ k[ 5]] ^ k9[ 9]]
	            ^ m[14][SBox.i[bl(sample_f,  2) ^ k[ 2]] ^ k9[10]]
	            ^ m[11][SBox.i[bl(sample_f, 15) ^ k[15]] ^ k9[11]] ]
	# Check if b == c
	if b != c:
		return False

	d   = SBox.i[ m[11][SBox.i[bl(sample_c,  4) ^ k[ 4]] ^ k9[ 4]]
	            ^ m[13][SBox.i[bl(sample_c,  1) ^ k[ 1]] ^ k9[ 5]]
	            ^ m[ 9][SBox.i[bl(sample_c, 14) ^ k[14]] ^ k9[ 6]]
	            ^ m[14][SBox.i[bl(sample_c, 11) ^ k[11]] ^ k9[ 7]]] \
	    ^ SBox.i[ m[11][SBox.i[bl(sample_f,  4) ^ k[ 4]] ^ k9[ 4]]
	            ^ m[13][SBox.i[bl(sample_f,  1) ^ k[ 1]] ^ k9[ 5]]
	            ^ m[ 9][SBox.i[bl(sample_f, 14) ^ k[14]] ^ k9[ 6]]
	            ^ m[14][SBox.i[bl(sample_f, 11) ^ k[11]] ^ k9[ 7]]]

	# Return the check if c == 3*c (as 3^-1 === 246 under this field)
	return m[d][246] == c

################################################################################
# Verify that the given AES key works with the given plain/ciphertext
# Arguments:
#    key_list - [integer]: List of all the 16 AES key bytes in integer form
#    sample_p - integer:   The given plaintext to verify with
#    sample_c - integer:   The given corresponding ciphertext to verify with
def step2_verify_AES_Key(key_list, sample_p, sample_c):
	key = str(bytearray(key_list))
	aes = AES.new(key)
	msg = str(bytearray.fromhex("{0:x}".format(sample_p)))
	enc = aes.encrypt(msg)
	# Sorry for the awful conversion (bytearray -> [hex_str] -> hex_str -> int)
	enc = int(''.join(["{0:02X}".format(i) for i in bytearray(enc)]), 16)
	return enc == sample_c

################################################################################
# Step 2 from the attack in Reference 1
# Arguments:
#   sample_p     - integer      A sample plaintext
#   sample_c     - integer:     The correct sample ciphertext of the plaintext
#   sample_f     - integer:     The faulty sample ciphertext of the plaintext
#   block_config - [integer]:   List of the block numbers these equations use
#   keys         - [[integer]]: The possible key list from the previous step
# Return:
#   string: The 128 bit recovered AES Key as a hex string, or None if none found
def step2(sample_p, sample_c, sample_f, block_config, keys):
	k = [0 for i in range(16)]

	step2_init_printout()
	print "Key Possibilities for Equation Set 0: " + str(len(keys[0]))
	print "Key Possibilities for Equation Set 1: " + str(len(keys[1]))
	print "Key Possibilities for Equation Set 2: " + str(len(keys[2]))
	print "Key Possibilities for Equation Set 3: " + str(len(keys[3]))
	# Byte Set One
	for a in range(len(keys[0])):
		# Load our desired keys
		k[block_config[0][0]] = keys[block_config[0][0]][a]
		k[block_config[0][1]] = keys[block_config[0][1]][a]
		k[block_config[0][2]] = keys[block_config[0][2]][a]
		k[block_config[0][3]] = keys[block_config[0][3]][a]

		# Byte Set Two
		for b in range(len(keys[1])):
			# Load our desired keys
			k[block_config[1][0]] = keys[block_config[1][0]][b]
			k[block_config[1][1]] = keys[block_config[1][1]][b]
			k[block_config[1][2]] = keys[block_config[1][2]][b]
			k[block_config[1][3]] = keys[block_config[1][3]][b]

			# Byte Set Three
			for c in range(len(keys[2])):
				# Load our desired keys
				k[block_config[2][0]] = keys[block_config[2][0]][c]
				k[block_config[2][1]] = keys[block_config[2][1]][c]
				k[block_config[2][2]] = keys[block_config[2][2]][c]
				k[block_config[2][3]] = keys[block_config[2][3]][c]

				# Byte Set Four
				for d in range(len(keys[3])):
					# Load our desired keys
					k[block_config[3][0]] = keys[block_config[3][0]][d]
					k[block_config[3][1]] = keys[block_config[3][1]][d]
					k[block_config[3][2]] = keys[block_config[3][2]][d]
					k[block_config[3][3]] = keys[block_config[3][3]][d]

					# Set up our keys from round 9
					k9 = aes_rk_windback(k, 10, 9)

					# Check equations
					if step2_check_equation(k, k9, sample_c, sample_f):
						# If successful, wind back key to AES key and verify
						key_list = aes_rk_windback(k9, 9, 0)
						if step2_verify_AES_Key(key_list, sample_p, sample_c):
							print "\nKey found!\n"
							# Forgive me for this awful conversion
							return ''.join(["{0:02X}".format(i)
							                for i in bytearray(key_list)])
	return None

################################################################################
# Performs the attack
# Arguments:
#   target      - subprocess: Target to interact with
#   sample_size - integer:    Number of samples to use, if unsure leave default
# Returns:
#   string: Extracted material from the target, in this case a key in
#           hexadecimal representation
def attack(target, sample_size=2):
	if sample_size > 32:
		print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
		print "Warning: The sample size is now quite large. If you have not"
		print "         manually set such a large sample size, you may wish to"
		print "         consider force closing this process as something "
		print "         fundamental may have gone wrong."
		print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"

	# Compute the formatting string for challenges
	global _challenge_fmt
	_challenge_fmt = "{0:X}"

	# Generate the plaintexts
	samples_p = generate_plaintexts(sample_size)
	samples_c = []
	samples_f = []

	# Encrypt the plaintexts with and without errors
	nf = FaultConfig(True)
	f  = FaultConfig(False, 8, AESRoundFunction.SubBytes, FaultLoc.Before, 0, 0)
	for i in range(sample_size):
		s = interact(target, nf.export(), _challenge_fmt.format(samples_p[i]))
		samples_c.append(s)
		s = interact(target, f.export(),  _challenge_fmt.format(samples_p[i]))
		samples_f.append(s)

	# Configure the LHS coefficients, and which AES key blocks should be used
	# with which set of equations
	coeff_config = [[ 2,  1,  1,  3],
	                [ 1,  1,  3,  2],
	                [ 1,  3,  2,  1],
	                [ 3,  2,  1,  1]]
	block_config = [[ 0, 13, 10,  7],
	                [ 4,  1, 14, 11],
	                [ 8,  5,  2, 15],
	                [12,  9,  6,  3]]

	# Perform Step One on each of the 4 sets of equations
	k   = step1(samples_c, samples_f, coeff_config, block_config)
	key = step2(samples_p[0], samples_c[0], samples_f[0], block_config, k)

	# In the unlikely event of a failure restart
	if key == None:
		print "Something appears to have gone wrong, restarting..."
		return attack(target, sample_size*2)

	return key

################################################################################
# Main
# Arguments:
#   None
# Returns:
#   None, prints out some intermediary data, ending with two lines containing
#   the extracted material and number of interactions with the target.
def main():
	version_warning()

	# Get the file locations for the "e-commerce server" (target) and public
	# configuration parameters
	server_path = sys.argv[1]

	# Produce a sub-process representing the attack target.
	target = subprocess.Popen(args=[server_path],
	                          stdout=subprocess.PIPE,
	                          stdin=subprocess.PIPE)

	# Execute the attack
	start = time.time()
	m = attack(target)
	end = time.time()
	print "Time Taken: " + str(end - start) + " seconds\n"

	version_warning()
	global _interaction_count
	print "Extracted Material: " + m
	print "Interactions with Target: " + str(_interaction_count)

################################################################################
# Checks to see if the version is the same as the one developed in, which was
# the same version as on the lab machines at the time of writing.
# Arguments:
#   None
# Returns:
#   None, prints out warning to stdout unless version of python is not 2.7.5
#   (on lab machines at the time of writing) or 2.6.6 (on snowy at the time of
#   writing)
def version_warning():
	if not sys.version_info[:3] == (2,7,5):
		print "!" * 80
		print "!!!!" + " " * 13 + \
		      "WARNING, RUNNING ON UNTESTED VERSION OF PYTHON" + \
		      " " * 13 + "!!!!"
		print "!!!!" + " There could be untested behaviour, thus " + \
		      "it is recommended you run with " + "!" * 4
		print "!!!!" + " " * 13 + \
		      "Python 2.7.5 or compatible for optimum results" + \
		      " " * 13 + "!!!!"
		print "!" * 80

################################################################################
# Catch for when running standalone
if __name__ == "__main__":
	main()