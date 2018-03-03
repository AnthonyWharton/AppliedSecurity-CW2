import sys, subprocess, math

# Reference 1:
# Manger, J., 2001, August. A chosen ciphertext attack on RSA optimal asymmetric
# encryption padding (OAEP) as standardized in PKCS# 1 v2. 0. In Annual
# International Cryptology Conference (pp. 230-238). Springer, Berlin,
# Heidelberg.

def centre_trunc_string(ln, s):
	if ln % 2 == 0:
		return s[:(ln/2)-3] + " .... " + s[-(ln/2)+2:] if len(s) > ln else s
	else:
		return s[:(ln/2)-2] + " ... "  + s[-(ln/2)+2:] if len(s) > ln else s

################################################################################
# Reads in the configuration for the attack from a given file.
def read_config(path):
	# Read in config file
	config_file = open(path)
	N = config_file.readline()[:-1]
	e = config_file.readline()[:-1]
	l = config_file.readline()[:-1]
	c = config_file.readline()[:-1]
	config_file.close()

	print "=" * 80
	print "Read in the following values from Config File:"
	print "          RSA Modulus: " + centre_trunc_string(57, N)
	print "  RSA Public Exponent: " + centre_trunc_string(57, e)
	print "     RSAES-OAEP Label: " + centre_trunc_string(57, l)
	print "RSAES-OAEP Ciphertext: " + centre_trunc_string(57, c)
	print "=" * 80
	return N, e, l, c

################################################################################
# Converts the hexadecimal string form of the config file into regular
# integer representation.
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
	print "=" * 80
	return N, e, l, c

################################################################################
# Creates a challenge ciphertext
_challenge_format = "{}"
def create_challenge(m, N, e, c=1):
	t = (pow(m, e, N) * c) % N
	return _challenge_format.format(t)

################################################################################
# Helper functions for integer division with floor and ceiling rounding
def int_div_f(x, y):
	return divmod(x, y)[0]

def int_div_c(x, y):
	q, m = divmod(x, y)
	if m == 0:
		return q
	else:
		return q + 1

################################################################################
# Feeds a given label and ciphertext to the target, and returns the status code
_challenge_count = 0
def challenge(target, label, ciphertext):
	target.stdin.write(label      + "\n")
	target.stdin.write(ciphertext + "\n")
	target.stdin.flush()
	global _challenge_count
	_challenge_count = _challenge_count + 1
	return int(target.stdout.readline().strip())

################################################################################
# Performs Step 1 from the attack in Reference 1
def step1(target, N, e, l, c):
	f1 = 1
	st = -1

	while st != 1:
		f1 *= 2
		ch = create_challenge(f1, N, e, c)
		st = challenge(target, l, ch)

	return f1

################################################################################
# Performs Step 2 from the attack in Reference 1
def step2(target, N, e, l, c, f1, B):
	ft = int_div_f(f1, 2)
	f2 = int_div_f(N + B, B) * ft
	ch = create_challenge(f2, N, e, c)
	st = challenge(target, l, ch)

	while st == 1:
		f2 = f2 + ft
		ch = create_challenge(f2, N, e, c)
		st = challenge(target, l, ch)

	return f2

################################################################################
# Performs Step 3 from the attack in Reference 1
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
		st = challenge(target, l, ch)

		if st == 1:# or status == 6:
			m_min = int_div_c(b, f3)
		else:
			m_max = int_div_f(b, f3)

	return f3, m_max

################################################################################
# Runs a step of the attack with nice printing
def run_step(n, f, args):
	sys.stdout.write("Starting Step " + str(n) + " ... ")
	r = f(*args)
	sys.stdout.write("DONE (" + str(_challenge_count).rjust(4) +
	                 " challenges made)\n")
	return r

################################################################################
# Performs the attack
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
	f1        = run_step(1, step1, (target, Ni, ei, ls, ci))
	f2        = run_step(2, step2, (target, Ni, ei, ls, ci, f1, B))
	f3, m_max = run_step(3, step3, (target, Ni, ei, ls, ci, f2, B))

	return "memes"

################################################################################
# Main
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
	print "Extracted Material: " + str(m)
	print "Interactions with Target: " + str(_challenge_count)

def version_warning():
	if sys.version_info[:3] != (2,7,5):
		print "!" * 80
		print "!!!!" + " " * 13 + \
		      "WARNING, RUNNING ON UNTESTED VERSION OF PYTHON" + \
		      " " * 13 + "!!!!"
		print "!!!!" + " There could be untested behaviour, thus it is " + \
		      "recommended you run with " + "!" * 4
		print "!!!!" + " " * 13 + \
		      "Python 2.7.5 or compatible for optimum results." + \
		      " " * 12 + "!!!!"
		print "!" * 80

if __name__ == "__main__":
	main()