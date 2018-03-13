import sys, subprocess, math, hashlib, time

# Reference 1:
# Manger, J., 2001, August. A chosen ciphertext attack on RSA optimal asymmetric
# encryption padding (OAEP) as standardized in PKCS# 1 v2. 0. In Annual
# International Cryptology Conference (pp. 230-238). Springer, Berlin,
# Heidelberg.

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
# Helper functions for integer division with floor and ceiling rounding
# Arguments:
#   x - integer: Operand 1
#   y - integer: Operand 2
# Returns:
#   integer: floor(x div y) or ceil(x div y) respectively
def int_div_f(x, y):
	return divmod(x, y)[0]

def int_div_c(x, y):
	q, m = divmod(x, y)
	if m == 0:
		return q
	else:
		return q + 1

################################################################################
# Helper functions for providing xor to capital hexadecimal strings
# Arguments:
#   a - string: Operand 1, a hexadecimal string
#   b - string: Operand 2, a hexadecimal string
# Returns:
#   string: Capital hexadecimal string representation of a ^ b, of length
#   max(len(a), len(b)).
def hex_xor(a, b):
	format_str = "{0:0"+str(max(len(a), len(b)))+"X}"
	return format_str.format(int(a,16) ^ int(b,16))

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
	l = config_file.readline()[:-1]
	c = config_file.readline()[:-1]
	config_file.close() # I remembered to close my file this time!
	print "=" * 80
	print "Read in the following values from Config File:"
	print "          RSA Modulus: " + centre_trunc_string(57, N)
	print "  RSA Public Exponent: " + centre_trunc_string(57, e)
	print "     RSAES-OAEP Label: " + centre_trunc_string(57, l)
	print "RSAES-OAEP Ciphertext: " + centre_trunc_string(57, c)
	print "=" * 80 + "\n"
	return N, e, l, c

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
def convert_config(N_str, e_str, l_str, c_str):
	N = int(N_str, 16)  # RSA Modulus
	e = int(e_str, 16)  # RSA Public Exponent
	l = int(l_str, 16)  # RSAES-OAEP label
	c = int(c_str, 16)  # RSAES-OAEP ciphertext
	print "=" * 80
	print "Converted the following values from Config File:"
	print "          RSA Modulus: " + centre_trunc_string(57, str(N))
	print "  RSA Public Exponent: " + centre_trunc_string(57, str(e))
	print "     RSAES-OAEP Label: " + centre_trunc_string(57, str(l))
	print "RSAES-OAEP Ciphertext: " + centre_trunc_string(57, str(c))
	print "=" * 80 + "\n"
	return N, e, l, c

################################################################################
# Creates a challenge ciphertext using global format string
# Arguments:
#   m - integer: Message to be encrypted in the challenge
#   N - integer: RSA Modulus to encrypt with
#   e - integer: RSA Public Exponent to encrypt with
#   c - integer: The known ciphertext
# Returns:
#   string: Challenge to be sent to the target, formatted by the public
#   _challenge_format string.
_challenge_format = "{}"
def create_challenge(m, N, e, c):
	t = (pow(m, e, N) * c) % N
	global _challenge_format
	return _challenge_format.format(t)

################################################################################
# Feeds a given label and ciphertext to the target, and returns the status code
# Arguments:
#   target     - subprocess: Target to interact with
#   label      - string:     Challenge RSAES-OAEP Label
#   ciphertext - string:     Challenge RSAES-OAP Ciphertext
# Return:
#   integer: The response status code from the target
_interaction_count = 0 # Global challenge/interaction count
def interact(target, label, ciphertext):
	target.stdin.write(label      + "\n")
	target.stdin.write(ciphertext + "\n")
	target.stdin.flush()
	global _interaction_count
	_interaction_count = _interaction_count + 1
	return int(target.stdout.readline().strip())

################################################################################
# Performs Step 1 from the attack in Reference 1
# Arguments:
#   target     - subprocess: Target to interact with
#   N, e, l, c - integer:    Variables as in Reference 1
# Return:
#   integer: f1 as in Reference 1
def step1(target, N, e, l, c):
	f1 = 1
	st = -1

	while st != 1:
		f1 *= 2
		ch = create_challenge(f1, N, e, c)
		st = interact(target, l, ch)

	return f1

################################################################################
# Performs Step 2 from the attack in Reference 1
# Arguments:
#   target            - subprocess: Target to interact with
#   N, e, l, c, f1, B - integer:    Variables as in Reference 1
# Return:
#   integer: f2 as in Reference 1
def step2(target, N, e, l, c, f1, B):
	ft = int_div_f(f1, 2)
	f2 = int_div_f(N + B, B) * ft
	ch = create_challenge(f2, N, e, c)
	st = interact(target, l, ch)

	while st == 1:
		f2 = f2 + ft
		ch = create_challenge(f2, N, e, c)
		st = interact(target, l, ch)

	return f2

################################################################################
# Performs Step 3 from the attack in Reference 1
# Arguments:
#   target            - subprocess: Target to interact with
#   N, e, l, c, f2, B - integer:    Variables as in Reference 1
# Return:
#   integer: Recovered encoded message (m_max) as in Reference 1
def step3(target, N, e, l, c, f2, B):
	m_min = int_div_c(N,     f2)
	m_max = int_div_f(N + B, f2)
	f3 = 0

	while m_min != m_max:
		f_tmp = int_div_f(        2 * B, m_max - m_min)
		i     = int_div_f(f_tmp * m_min, N)
		f3    = int_div_c(        i * N, m_min)
		b     = i * N + B

		ch = create_challenge(int(f3), N, e, c)
		st = interact(target, l, ch)

		if st == 1:# or status == 6:
			m_min = int_div_c(b, f3)
		else:
			m_max = int_div_f(b, f3)

	return m_max

################################################################################
# Runs a step of the attack with nice printing
# Arguments:
#   n    - integer:  The number of the step for the printout
#   f    - function: Function to run for this step
#   args - tuple of arguments for function f
# Return:
#   Result of the function f
def run_step(n, f, args):
	global _interaction_count
	sys.stdout.write("Starting Step " + str(n) + " ... ")
	r = f(*args)
	sys.stdout.write("DONE (" + str(_interaction_count).rjust(4) +
	                 " challenges made so far)\n")
	return r

################################################################################
# MGF1 Mask Generation Function as per RFC 2437 (using SHA1)
# Arguments:
#   Z - string:  A hexadecimal octet string
#   l - integer: Intended length (in octets) of the mask, at most 2^(32*hLen)
# Return:
#   string: A capital hexadecimal string (1 octet = 2 hex characters)
_SHA1_hLen = hashlib.sha1().digest_size
def MGF1(Z, l):
	global _SHA1_hLen
	if l > 2**(32*_SHA1_hLen):
		raise ValueError("mask too long")
	T = ""
	for counter in range(0, int_div_c(l, _SHA1_hLen)):
		C = "{0:08X}".format(counter)
		T = T + hashlib.sha1((Z + C).decode("hex")).hexdigest().upper()
	return T[:l*2]

################################################################################
# EME-OAEP decoding as per RFC 3447 (using SHA1 and MGF1 defined in this file)
# Arguments:
#   em - string: Encoded message in hexadecimal to be decoded
#   l  - string: Label to decode with (defaults to empty string)
# Returns:
#   string: Captialised hexadecimal string of output message
def eme_oeap_decode(em, l=""):
	try:
		global _SHA1_hLen
		hLen       = _SHA1_hLen * 2  # convert to length of hex string
		lHash      = hashlib.sha1(l.decode("hex")).hexdigest().upper()
		Y          = em[      :2     ]
		maskedSeed = em[2     :2+hLen]
		maskedDB   = em[2+hLen:      ]
		seedMask   = MGF1(maskedDB, _SHA1_hLen)
		seed       = hex_xor(maskedSeed, seedMask)
		dbMask     = MGF1(seed, len(maskedDB)/2)
		DB         = hex_xor(maskedDB, dbMask)
		lHash_     = DB[:hLen]
		M          = ""
		for i in range(0, len(DB)-hLen):
			if DB[hLen+i:hLen+i+2] == "01":
				M = DB[hLen+i+2:]
				break
			elif DB[hLen+i:hLen+i+2] != "00":
				raise Exception("decryption error")

	except ValueError: # in case of0 MGF1 failures
		raise Exception("decryption error")
	if M == "":
		raise Exception("decryption error")
	if lHash != lHash_:
		raise Exception("decryption error")
	if Y != "00":
		raise Exception("decryption error")
	return M

################################################################################
# Performs the attack
# Arguments:
#   target      - subprocess: Target to interact with
#   config_path - string:     Path to configuration file
# Returns:
#   string: Extracted material from the target
def attack(target, config_path):
	Ns, es, ls, cs = read_config(config_path)
	Ni, ei, li, ci = convert_config(Ns, es, ls, cs)

	# Compute the formatting string for challenges
	global _challenge_format
	_challenge_format = "{0:0" + str(len(Ns)) + "X}"

	# Calculate B
	k = int(math.ceil(math.log(Ni, 256)))
	B = 2 ** (8*(k-1))

	# Run Attack Steps
	f1 = run_step(1, step1, (target, Ni, ei, ls, ci))
	f2 = run_step(2, step2, (target, Ni, ei, ls, ci, f1, B))
	m  = run_step(3, step3, (target, Ni, ei, ls, ci, f2, B))
	print ""

	return eme_oeap_decode(_challenge_format.format(m), ls)

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
	print "Time Taken: " + str(end-start) + " seconds\n"

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