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
# Feeds a given label and ciphertext to the target, and returns the status code
# Arguments:
#   target     - subprocess: Target to interact with
#   label      - string:     Challenge RSAES-OAEP Label
#   ciphertext - string:     Challenge RSAES-OAP Ciphertext
# Return:
#   integer: The response status code from the target
_interaction_count = 0 # Global challenge/interaction count
def interact(target, ciphertext):
	target.stdin.write(ciphertext + "\n")
	target.stdin.flush()
	global _interaction_count
	_interaction_count = _interaction_count + 1
	dt = int(target.stdout.readline().strip(), 10)
	m  = int(target.stdout.readline().strip(), 16)
	return dt, m

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
# Generates multiplication table under gf 2^8 (Rijndael's Finite Field)
# Return:
#   [[integer]]: A 2 dimensional lookup table for 8 bit gf 2^8 multiplication
def generate_mul_table():
	table = [[]]
	for i in range(0b11111111):
		for j in range(0b11111111):
			table[i][j] = gf28_mul(i, j)
	return table

################################################################################
# Performs the attack
# Arguments:
#   target      - subprocess: Target to interact with
# Returns:
#   string: Extracted material from the target, in this case a key in
#           hexadecimal representation
def attack(target):

	# Compute the formatting string for challenges
	global _challenge_format
	_challenge_format = "{0:X}"

	return "{0:X}".format(int(01234567, 2))

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
	config_path = sys.argv[2]

	# Produce a sub-process representing the attack target.
	target = subprocess.Popen(args=[server_path],
	                          stdout=subprocess.PIPE,
	                          stdin=subprocess.PIPE)

	# Execute the attack
	start = time.time()
	m = attack(target, config_path)
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