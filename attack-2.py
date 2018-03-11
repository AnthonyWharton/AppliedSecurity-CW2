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
# Analyses the timings
def analyse_timings(F, threshold):
	F_mu = []
	for i in range(4):
		if len(F[i]) != 0:
			F_mu.append(float(sum(F[i])) / len(F[i]))
		else:
			e = "Not enough samples, M" + str(i+1) + " had no elements"
			raise RuntimeError(e)


	diff1 = abs(F_mu[0] - F_mu[1])
	diff2 = abs(F_mu[2] - F_mu[3])
	k1_lt = F_mu[0] > F_mu[1]
	k1_eq = abs(1.0 - F_mu[2] / F_mu[3]) < threshold
	k0_lt = F_mu[2] > F_mu[3]
	k0_eq = abs(1.0 - F_mu[0] / F_mu[1]) < threshold

	if diff1 > diff2 and k1_lt and k1_eq:
		return 1
	if diff2 > diff1 and k0_lt and k0_eq:
		return 0

	e = "Timings were not as expected:\n"
	e += "abs(mu(F1) - mu(F2)"
	e += " > " if diff1 > diff2 else " < "
	e += "abs(mu(F3) - mu(F4))\n"
	e += "mu(F1) = " + "{0:6.2F}".format(F_mu[0]) + " | "
	e += "    mu(F1) > mu(F2)\n" if k1_lt else "NOT mu(F1) > mu(F2)\n"
	e += "mu(F2) = " + "{0:6.2F}".format(F_mu[1]) + " | "
	e += "    mu(F3) = mu(F4)\n" if k1_eq else "NOT mu(F3) = mu(F4)\n"
	e += "mu(F3) = " + "{0:6.2F}".format(F_mu[2]) + " | "
	e += "    mu(F3) > mu(F4)\n" if k0_lt else "NOT mu(F3) > mu(F4)\n"
	e += "mu(F4) = " + "{0:6.2F}".format(F_mu[3]) + " | "
	e += "    mu(F1) = mu(F2)\n" if k0_eq else "NOT mu(F1) = mu(F2)\n"
	raise RuntimeError(e)

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
	max_key_size = 16384
	found_key    = False

	# Generate Initial Montgomery Parameters
	N        = N_i
	R        = mont_findR(N)
	_, _, Ni = xgcd(R, N)

	# Generate Sample Messages and get timings
	ms   = generate_messages(N, 1500)
	ms_m = [mont_convert(m, N, R) for m in ms]
	ts   = get_timings(target, ms)

	# Generate first m_temp and go into main attack loop
	m_temp  = [mont_mul(m, m, N, R, Ni)[0] for m in ms_m]
	m_temp_ = []
	while not found_key and len(key) <= max_key_size:
		m_temp_next, M, F = internal_oracle(ms, ts, ms_m, m_temp, N, R, Ni)
		bit               = analyse_timings(F, 0.001)
		m_temp            = m_temp_next[bit]

		key += str(bit)
		print "[" + str(len(key)).rjust(3) \
		      + "] Found bit " + str(bit) + ", Key So Far: " + key

	return "the key is \"memes\""

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