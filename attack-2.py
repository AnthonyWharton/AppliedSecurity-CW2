import sys, subprocess, random
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
# Gets the decrypted messages and timings from the oracle for all the given
# ciphertexts.
# Arguments:
#   target      - subprocess: Target to interact with
#   ciphertexts - [integer]:  List of all messages to get timings of
# Return:
#   2-tuple of [integer] A pair of list of message and timings respectively,
#                        in an order corresponding to the list of given
#                        messages. Timings are number of clock cycles and may
#                        contain experimental noise.
def multi_interact(target, ciphertexts):
	dts = []
	pts = []
	global _challenge_format
	for m in ciphertexts:
		dt, pt = interact(target, _challenge_format.format(m))
		dts.append(dt)
		pts.append(pt)
	return dts, pts

################################################################################
# Generates random ciphertexts
# Arguments:
#   N           - integer: Ciphertexts will be between 0 and N-1 (inclusive)
#   sample_size - integer: Number of ciphertexts to generate
# Return:
#   [integer]: A list of randomly generated sample ciphertexts in integer form
def generate_ciphertexts(N, sample_size):
	rng = random.SystemRandom()
	samples = []
	for i in range(sample_size):
		c = rng.getrandbits(N.bit_length())
		while c >= N:
			c = rng.getrandbits(N.bit_length())
		samples.append(c)
	return samples

################################################################################
# Determines whether or not the next iteration's calculations require a
# reduction or not.
# Arguments:
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
def internal_oracle(t, ms, mts, N, R, Ni):
	mts_ = [[], []]
	F = [[], [], [], []]

	for i in range(len(mts)):
		# Oracle 1 from Reference 1
		o1, _   = mont_mul(mts[i], ms[i], N, R, Ni)
		o1, o1b = mont_mul(o1, o1, N, R, Ni)
		if o1b:
			F[0].append(t[i])
		else:
			F[1].append(t[i])

		# Oracle 2 from Reference 1
		o2, o2b = mont_mul(mts[i], mts[i], N, R, Ni)
		if o2b:
			F[2].append(t[i])
		else:
			F[3].append(t[i])

		# Keep track of calculation for next m_temp (optimisation)
		mts_[0].append(o2)
		mts_[1].append(o1)

	return mts_, F

################################################################################
# Analyses the timings
def analyse_timings(F, threshold):
	F_mu = []
	for i in range(4):
		if len(F[i]) != 0:
			F_mu.append(float(sum(F[i])) / len(F[i]))
		else:
			F_mu.append(0)

	diff1 = abs(F_mu[0] - F_mu[1])
	diff2 = abs(F_mu[2] - F_mu[3])
	k1_lt = F_mu[0] > F_mu[1]
	k1_eq = abs(1 - (F_mu[0] / F_mu[1])) < threshold
	k0_lt = F_mu[2] > F_mu[3]
	k0_eq = abs(1 - (F_mu[2] / F_mu[3])) < threshold

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
	# raise RuntimeError(e)
	return -1

################################################################################
# Checks if our key is correct after we append a 0 or 1 to it, as this attack
# cannot work out the last bit.
# Arguments:
#   key - string:    Key in binary string representation
#   cs  - [integer]: List of ciphertexts from target
#   ps  - [integer]: List of plaintexts from target
#   N   - integer:   RSA Public Modulus
#   _b  - internal: do not use
def check_key(key, cs, ps, N, _b="0"):
	d  = int(key + _b, 2)
	solved = False
	for i in range(len(cs)):
		if int(pow(cs[i], d, N)) == ps[i]:
			solved = True
		else:
			solved = False
			break
	if solved:
		return True, key + _b
	elif _b == "0":
		return check_key(key, cs, ps, N, "1")
	else:
		return False, key

################################################################################
# Add ciphertexts to current collection
def add_samples(target, size, N, R, cs, cs_m, ts, ps):
	old_len = len(cs)
	cs.extend(generate_ciphertexts(N, size))
	for i in range(size):
		c = cs[old_len + i]
		cs_m.append(mont_convert(c, N, R))
		t, p = interact(target, _challenge_format.format(c))
		ts.append(t)
		ps.append(p)
	return cs, cs_m, ts, ps

################################################################################
# Performs the attack
# Arguments:
#   target      - subprocess: Target to interact with
#   config_path - string:     Path to configuration file
#   _attempts   - internal, do not specify.
# Returns:
#   string: Extracted material from the target, in this case a key in
#           hexadecimal representation
def attack(target, config_path, _attempts=0):
	N_s, e_s = read_config(config_path)
	N_i, e_i = convert_config(N_s, e_s)

	# Compute the formatting string for challenges
	global _challenge_format
	_challenge_format = "{0:X}"

	# Generate Initial Key Parameters
	key          = "1"
	key_bits_err = [1]
	max_key_size = 16384
	found_key    = False

	# Generate Initial Montgomery Parameters
	N        = N_i
	R        = mont_findR(N)
	_, _, Ni = xgcd(R, N)

	# Generate Sample ciphertexts (messages) and get timings/plaintexts
	ms     = generate_ciphertexts(N, 2000)
	ms_m   = [mont_convert(m, N, R) for m in ms]
	ts, ps = multi_interact(target, ms)

	# Generate first m_temp and go into main attack loop
	m_tmp = [[], [mont_mul(m, m, N, R, Ni)[0] for m in ms_m]]
	while not found_key and len(key) <= max_key_size:
		# Initialise more key_bits_error positions
		while len(key_bits_err) <= len(key)+1:
			key_bits_err.append(1)

		# Step 1, Group messages based on internal oracle
		nxt_m_tmp, F = internal_oracle(ts, ms_m, m_tmp[int(key[-1])], N, R, Ni)

		# Step 2, Analyse the timings
		bit = analyse_timings(F, 0.01)

		# Step 2.5, Check if the timings didn't work out, and error correct
		if bit < 0:
			# Work out how far to backtrack from our array
			pos       = len(key) + 1
			backtrack = min(len(key)-1, sum(key_bits_err[pos-1:pos+1]))
			old_key   = key
			# Backtrack key, with flipped bit
			flip = int(key[-backtrack]) ^ 1
			key  = key[:-backtrack] + str(flip)
			# Add samples
			ms, ms_m, ts, ps = add_samples(target, 250, N, R, ms, ms_m, ts, ps)
			# Regenerate m_tmp
			tmp         = [int(pow(pow(m, int(key, 2), N), 2, N)) for m in ms]
			m_tmp[flip] = [mont_convert(m, N, R) for m in tmp]

			print "[keylen: " + str(len(key)).rjust(3) + "] [samples: " +      \
			      str(len(ms)).rjust(5) + "] Error Detected, rolling back " +  \
			      str(backtrack) + " bits! Key was: " + old_key
			key_bits_err[pos] *= 2
			continue

		key = key + str(bit)
		print "[keylen: " + str(len(key)).rjust(3) + "] [samples: " +          \
		      str(len(ms)).rjust(5) + "] Found bit " + str(bit) +              \
		      ", Key so far: " + key

		# Step 3, Check we haven't got the final key yet, and if not prepare for
		#         next iteration, else we're done here.
		found_key, key = check_key(key, ms, ps, N)
		m_tmp          = nxt_m_tmp

	print "\nFOUND KEY, LENGTH " + str(len(key)) + ", KEY: " + key + "\n"
	return "{0:X}".format(int(key, 2))

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