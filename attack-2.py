import sys, subprocess, random, math, hashlib
from montgomery import *

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
# Reads in the configuration for the attack from a given file.
# Arguments:
#   path -  string: Path to configuration file
# Returns:
#   4-tuple of strings: RSA Modulus, RSA Public Exponent, RSAES_OAEP Label and
#   RSAES-OAEP Ciphertext as in the config file
def read_config(path):
	config_file = open(path)
	N = config_file.readline()[:-1] # Remove newline characters
	e = config_file.readline()[:-1]
	config_file.close() # I remembered to close my file this time!
	print "=" * 80
	print "Read in the following values from Config File:"
	print "          RSA Modulus: " + centre_trunc_string(57, N)
	print "  RSA Public Exponent: " + centre_trunc_string(57, e)
	print "=" * 80 + "\n"
	return N, e

################################################################################
# Converts the hexadecimal string form of the config file into regular
# integer representation.
# Arguments:
#   N_str - string: Hexadecimal string of RSA Modulus
#   e_str - string: Hexadecimal string of RSA Public Exponent
#   l_str - string: Octal string of RSAES_OAEP Label
#   c_str - string: Octal string of RSAES-OAEP Ciphertext
# Returns:
#   4-tuple of integers: RSA Modulus, RSA Public Exponent, RSAES_OAEP Label and
#   RSAES-OAEP Ciphertext converted into integer form
def convert_config(N_str, e_str):
	N = int(N_str, 16)  # RSA Modulus
	e = int(e_str, 16)  # RSA Public Exponent
	print "=" * 80
	print "Converted the following values from Config File:"
	print "          RSA Modulus: " + centre_trunc_string(57, str(N))
	print "  RSA Public Exponent: " + centre_trunc_string(57, str(e))
	print "=" * 80 + "\n"
	return N, e

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
# Generates random messages
# Arguments:
#   N           - integer: Messages will be between 0 and N-1 (inclusive)
#   sample_size - integer: Number of messages to generate
# Return:
#   [integer]: A list of randomly generated sample messages in integer form
def generate_messages(N, sample_size):
	rng = random.SystemRandom()
	samples = []
	for i in range(sample_size):
		m = rng.getrandbits(N.bit_length())
		while m >= N:
			m = rng.getrandbits(N.bit_length())
		samples.append(m)
	return samples


################################################################################
# Gets the timings from the oracle for all the given messages
# Arguments:
#   target   - subprocess: Target to interact with
#   messages - [integer]:  List of all messages to get timnigs of
# Return:
#   [integer] A list of timings in an order corresponding to the list of given
#             messages. Timings are number of clock cycles and may contain
#             experimental noise.
def get_timings(target, messages):
	dts = []
	for m in messages:
		dt, ms = interact(target, "{0:X}".format(m))
		dts.append(dt)
	return dts

################################################################################
# Determines whether or not the next iteration's calculations require a
# reduction or not.
# Arguments:
#   m    - [integer]: List of messages in plain integer form
#   t    - [integer]: List of messages timings
#   ms   - [integer]: List of messages in montgomery form
#   mts  - [integer]: List of m_temp in montgomery form
#   N    - integer:   Public RSA Modulus
#   R    - integer:   Montgomery Form Parameter
#   Ni   - integer:   Modular Inverse of N
# Returns:
#   3-tuple of [[integer]]: mts_, M, F (where M[n] and F[n] correspond to M[n+1]
#                           as in Reference 1. For reference:
#       mts_[0] Set of results of (m_temp)^2
#       mts_[1] Set of results of (m_temp * m)^2
#       M[0]    Set of messages s.t. (m_temp * m)^2 is done with a reduction
#       M[1]    Set of messages s.t. (m_temp * m)^2 is done without a reduction
#       M[2]    Set of messages s.t. (m_temp)^2 is done with a reduction
#       M[3]    Set of messages s.t. (m_temp)^2 is done without a reduction
#       F[n]    Sets of timing data corresponding to M[n]
def internal_oracle(m, t, ms, mts, N, R, Ni):
	if not (len(m) == len(t) and len(t) == len(ms) and len(ms) == len(mts)):
		raise ValueError("m, t, ms and mts should be the same length")

	mts_ = [[], []]
	M = [[], [], [], []]
	F = [[], [], [], []]

	for i in range(len(mts)):
		# Oracle 1 from Reference 1
		o1, _   = mont_mul(mts[i], ms[i], N, R, Ni)
		o1, o1b = mont_mul(o1, o1, N, R, Ni)
		if o1b:
			M[0].append(m[i])
			F[0].append(t[i])
		else:
			M[1].append(m[i])
			F[1].append(t[i])

		# Oracle 2 from Reference 1
		o2, o2b = mont_mul(mts[i], mts[i], N, R, Ni)
		if o2b:
			M[2].append(m[i])
			F[2].append(t[i])
		else:
			M[3].append(m[i])
			F[3].append(t[i])

		# Keep track of calculation for next m_temp (optimisation)
		mts_[0].append(o2)
		mts_[1].append(o1)

	return mts_, M, F

################################################################################
# Performs the attack
# Arguments:
#   target      - subprocess: Target to interact with
#   config_path - string:     Path to configuration file
# Returns:
#   string: Extracted material from the target
def attack(target, config_path):
	N_s, e_s = read_config(config_path)
	N_i, e_i = convert_config(N_s, e_s)

	# Compute the formatting string for challenges
	global _challenge_format
	_challenge_format = "{0:0" + str(len(N_s)) + "X}"

	# Generate Initial Key Parameters
	key          = "1"
	max_key_size = 256
	found_key    = False

	# Generate Initial Montgomery Parameters
	N        = N_i
	R        = mont_findR(N)
	_, _, Ni = xgcd(R, N)

	# Generate Sample Messages and get timings
	# messages   = generate_messages(N, 2000)
	ms   = [7437547582898201166504790977009610016749607629859363723369068181167009518876199364654610230480145538179909148502618573185612444121691839267565803294923702420005740938330614081786981007239523341371497003489375266303038180338735276899083164028033783243467202599597567762300353895115906651794955198976961277782,
	        28322960429222631649519165870154768807551969381586638880015921551868899479825915114670445913524003181840626189062434078298169148285240351148854593202066887026127177236564723164830250463764344731177585826562788177010357956222963602960797909232584786281688554448416696221018039806357035293662240436721652725740]
	ms_m = [mont_convert(m, N, R) for m in ms]
	ts   = get_timings(target, ms)

	while not found_key and len(key) <= max_key_size:
		m_temp            = [mont_mul(m, m, N, R, Ni)[0] for m in ms_m]
		m_temp_next, M, F = internal_oracle(ms, ts, ms_m, m_temp, N, R, Ni)


	# print "M1"
	# print M1
	# print "M2"
	# print M2
	# print "M3"
	# print M3
	# print "M4"
	# print M4

	return "the message is memes"

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
	m = attack(target, config_path)

	version_warning()
	global _interaction_count
	print "Extracted Material: " + str(m)
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
	if not sys.version_info[:3] == (2,6,6) and \
	   not sys.version_info[:3] == (2,7,5):
		print "!" * 80
		print "!!!!" + " " * 13 + \
		      "WARNING, RUNNING ON UNTESTED VERSION OF PYTHON" + \
		      " " * 13 + "!!!!"
		print "!!!!" + " There could be untested behaviour, thus " + \
		      "it is recommended you run with " + "!" * 4
		print "!!!!" + " " * 10 + \
		      "Python 2.6.6/2.7.5 or compatible for optimum results" + \
		      " " * 10 + "!!!!"
		print "!" * 80

################################################################################
# Catch for when running standalone
if __name__ == "__main__":
	main()