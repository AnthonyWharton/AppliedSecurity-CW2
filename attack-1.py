import sys, subprocess, math
from decimal import Decimal

# Reference 1:
# Manger, J., 2001, August. A chosen ciphertext attack on RSA optimal asymmetric
# encryption padding (OAEP) as standardized in PKCS# 1 v2. 0. In Annual
# International Cryptology Conference (pp. 230-238). Springer, Berlin,
# Heidelberg.

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

	print "================================================================"
	print "Read in the following values from Config File:"
	print "          RSA Modulus: " + N
	print "  RSA Public Exponent: " + e
	print "     RSAES-OAEP Label: " + l
	print "RSAES-OAEP Ciphertext: " + c
	print "================================================================"
	return N, e, l, c

################################################################################
# Converts the hexadecimal string form of the config file into regular
# integer representation.
def convert_config(N_str, e_str, l_str, c_str):
	N = int(N_str, 16)  # RSA Modulus
	e = int(e_str, 16)  # RSA Public Exponent
	l = int(l_str, 16)  # RSAES-OAEP label
	c = int(c_str, 16)  # RSAES-OAEP ciphertext
	print "================================================================"
	print "Converted the following values from Config File:"
	print "          RSA Modulus: " + str(N)
	print "  RSA Public Exponent: " + str(e)
	print "     RSAES-OAEP Label: " + str(l)
	print "RSAES-OAEP Ciphertext: " + str(c)
	print "================================================================"
	return N, e, l, c

################################################################################
# Creates a challenge ciphertext
_challenge_format = "{}"
def create_challenge(m, N, e, c=1):
	t = (pow(m, e, N) * c) % N
	return _challenge_format.format(t)

################################################################################
# Feeds a given label and ciphertext to the target, and returns the status code
def interact(target, label, ciphertext):
	target.stdin.write(label      + "\n")
	target.stdin.write(ciphertext + "\n")
	target.stdin.flush()
	return int(target.stdout.readline().strip())

################################################################################
# Performs Step 1 from the attack in Reference 1
def step1(target, N, e, l, c):
	f1 = 1
	status = -1

	while status != 1:
		f1 *= 2
		# challenge is in [0, 2B]
		challenge = create_challenge(f1, N, e, c)
		status = interact(target, l, challenge)

	# f1 is in [B, 2B]
	return f1

################################################################################
# Performs Step 2 from the attack in Reference 1
def step2(target, N, e, l, c, f1, B):
	f2 = int(math.floor(Decimal(N + B) / B) * (f1/2))
	challenge = create_challenge(f2, N, e, c)
	print challenge
	status = interact(target, l, challenge)

	count = 0
	while status == 1:# or status == 6: # TODO, Should we allow 6?
		f2 = f2 + (f1/2)
		challenge = create_challenge(f2, N, e, c)
		status = interact(target, l, challenge)
		count += 1

	print "Status: " + str(status) + ", iters: " + str(count) + " (of " + str(N/B) + ")"
	# f2 is in [N, N+B]
	return f2

################################################################################
# Performs Step 3 from the attack in Reference 1
def step3(target, N, e, l, c, f2, B):
	m_min = Decimal(math.ceil (Decimal(N)     / f2))
	m_max = Decimal(math.floor(Decimal(N + B) / f2))
	f3 = 0

	print "min: " + str(m_min) + "\nmax: " + str(m_max)

	while m_min != m_max:
		print str(int(m_max-m_min))
		f_tmp = Decimal(math.floor((2 * B)         / (m_max - m_min)))
		i     = Decimal(math.floor((f_tmp * m_min) / N))
		f3    = Decimal(math.ceil ((i * N)         /  m_min))
		b     = Decimal(i * N + B)

		challenge = create_challenge(int(f3), N, e, c)
		status    = interact(target, l, challenge)

		if status == 0:
			print "Plaintext found"
			break
		elif status == 1:# or status == 6:
			# print ">= B"
			# print "before min: " + str(int(m_min))
			m_min = Decimal(math.ceil (b / f3))
			# print "after min: " + str(int(m_min))
		else:
			# print "< B"
			# print "before max: " + str(int(m_max))
			m_max = Decimal(math.floor(b / f3))
			# print "after max: " + str(int(m_max))

	print " m_min: " + str(m_min)
	print " m_max: " + str(m_max)
	print "Status: " + str(status)

	t = pow(int(m_max), e, N)
	print "STATUS CODE: " + str(interact(target, l, hex(t).upper()[2:]))

	return f3

################################################################################
# Performs the attack
def attack(target, config_path):
	Ns, es, ls, cs = read_config(config_path)
	Ni, ei, li, ci = convert_config(Ns, es, ls, cs)

	# Calculate the formatting 
	global _challenge_format
	_challenge_format = "{0:0" + str(len(Ns)) + "X}"

	# Calculate B
	k = int(math.ceil(math.log(Ni, 256)))
	B = 2 ** (8*(k-1))

	print "Starting Step 1"
	f1 = step1(target, Ni, ei, ls, ci)
	print "f1: " + str(f1)

	print "Starting Step 2"
	f2 = step2(target, Ni, ei, ls, ci, f1, B)
	print "f2: " + str(f2)

	print "Starting Step 3"
	f3 = step3(target, Ni, ei, ls, ci, f2, B)
	# print "f3: " + str(f3)
	# print " B: " + str(B)

################################################################################
def main():
	# Get the file locations for the "e-commerce server" (target) and public
	# configuration parameters
	server_path = sys.argv[1]
	config_path = sys.argv[2]

	# Produce a sub-process representing the attack target.
	target = subprocess.Popen(args=[server_path],
	                          stdout=subprocess.PIPE,
	                          stdin=subprocess.PIPE)

	# Execute a function representing the attacker.
	attack(target, config_path)

if __name__ == "__main__":
	main()