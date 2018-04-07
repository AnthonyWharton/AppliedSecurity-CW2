#!/bin/python2.7
import sys, subprocess, random, time
from aes_misc import *

# Reference 1:
# Dhem, Jean-Francois, et al. "A `practical implementation of the timing attack."
# International Conference on Smart Card Research and Advanced Applications.
# Springer, Berlin, Heidelberg, 1998.

################################################################################
# Helper function to truncate long strings (s) into a length (ln)
# Arguments:
#   ln - integer: The length of the string to produce
#   s  - string:  The string to truncate
# Returns:
#   string: A string of size min(ln, len(s)), with the center truncated out and
#   replaced with " ... " or " .... "
def centre_trunc_string(ln, s):
	if ln % 2 == 0:
		return s[:(ln/2)-3] + " .... " + s[-(ln/2)+2:] if len(s) > ln else s
	else:
		return s[:(ln/2)-2] + " ... "  + s[-(ln/2)+2:] if len(s) > ln else s

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
# Generates random 8 bit ciphertexts
# Arguments:
#   sample_size - integer: Number of ciphertexts to generate
# Return:
#   [integer]: A list of randomly generated sample ciphertexts in integer form
def generate_ciphertexts(sample_size):
	rng = random.SystemRandom()
	samples = []
	for i in range(sample_size):
		c = rng.getrandbits(8)
		samples.append(c)
	return samples

################################################################################
# Generates global multiplication table under gf 2^8 (Rijndael's Finite Field)
m = [[gf28_mul(i,j) for i in range(256)] for j in range(256)]

################################################################################
# Gets the n'th byte from the 128 bit binary number. 0 indexes
# Arguments:
#   bin - integer: 128 bit binary digit to get the byte from
#   n   - integer: Byte to retrieve (0 indexed)
# Return:
#   integer: The requested byte
def b(bin, n):
	return (bin & (0xff000000000000000000000000000000 >> (8*n))) >> (120 - 8*n)

################################################################################
# Step 1 from the attack
# Arguments:
#   coeff    - [integer]:   List of the 4 lhs coefficients for the 4 equations
#   blocks   - [integer]:   List of the block numbers these equations use
#   sample_c - integer:     The correct sample
#   sample_f - integer:     The faulty sample
#   p        - [[integer]]: The results array
# Return:
#   Nothing - Results are added to `p`
def step1(coeff, blocks, sample_c, sample_f, p):
	global m
	if not (len(coeff) == 4) and not (len(blocks) == 4):
		raise(AssertionError, "Can only provide 4 coefficients/block ids")
	# if not len(samples_c) == len(samples_f):
	# 	raise(AssertionError, "Samples arrays are not the same length")
	# Checking for every possible value of delta
	for d in range(1,256):
		o_acc = []
		successful = True
		# Loop through the 4 'simultaneous' equations, find keys that work
		# with our value of delta
		for step in range(4):
			options = []
			for key in range(256):
				lhs = m[coeff[step]][d]
				rhs = SBox.i[b(sample_c, blocks[step]) ^ key] \
				    ^ SBox.i[b(sample_f, blocks[step]) ^ key]
				if lhs == rhs:
					options.append(key)
			# Check if we had any working keys, store them in our accumulator
			if len(options) > 0:
				o_acc.append(options)
			else:
				successful = False
				break # This equation didn't work so this delta can be skipped
		# If all 4 equations worked, keep track of those options
		if successful:
			for a in o_acc[0]:
				for b in o_acc[1]:
					for c in o_acc[2]:
						for d in o_acc[3]:
							p[blocks[0]].append(a)
							p[blocks[1]].append(b)
							p[blocks[2]].append(c)
							p[blocks[3]].append(d)


################################################################################
# Performs the attack
# Arguments:
#   target      - subprocess: Target to interact with
# Returns:
#   string: Extracted material from the target, in this case a key in
#           hexadecimal representation
def attack(target):

	sample_c = 309576198173487898485272507802272752224
	sample_f = 213524607176099836202173306380891822739
	p        = [[] for i in range(16)]

	# Perform Step One on each of the 4 sets of equations
	step1([2, 1, 1, 3], [ 0, 13, 10,  7], sample_c, sample_f, p)
	step1([3, 2, 1, 1], [ 4,  1, 14, 11], sample_c, sample_f, p)
	step1([1, 3, 2, 1], [ 8,  5,  2, 15], sample_c, sample_f, p)
	step1([1, 1, 3, 2], [12,  9,  6,  3], sample_c, sample_f, p)

	# Compute the formatting string for challenges
	global _challenge_format
	_challenge_format = "{0:X}"

	return "{0:X}".format(int("111", 2))

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