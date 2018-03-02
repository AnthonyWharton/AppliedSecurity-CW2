import sys, subprocess, math

# Reference 1:
# Manger, J., 2001, August. A chosen ciphertext attack on RSA optimal asymmetric
# encryption padding (OAEP) as standardized in PKCS# 1 v2. 0. In Annual
# International Cryptology Conference (pp. 230-238). Springer, Berlin,
# Heidelberg.

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

# Converts the hexadecimal string form of the config file into regular
# integer representation.
def convert_config(N_str, e_str, l_str, c_str):
	N = int(N_str, 16)  # RSA Modulus
	e = int(e_str, 16)  # RSA Public Exponent
	l = int(l_str, 16)  # RSAES-OAEP label
	c = int(c_str, 16)  # RSAES-OAEP ciphertext

	return N, e, l, c

def create_ciphertext(c):
	return hex(c).upper()[2:]

# Feeds a given label and ciphertext to the target, and returns the status code
def interact(target, label, ciphertext):
	target.stdin.write(label      + "\n")
	target.stdin.write(ciphertext + "\n")
	target.stdin.flush()
	return int(target.stdout.readline().strip())

# Performs Step 1 from the attack in Reference 1
def step1(target, N, e, l, c):
	f1 = 1
	status = 0

	while status != 1:
		f1 *= 2
		# challenge is in [0, 2B]
		challenge = create_ciphertext((pow(f1, e, N) * c) % N)
		status = interact(target, l, challenge)
		print "Status: " + str(status)

	# f1 is in [B, 2B]
	return f1

# Performs Step 2 from the attack in Reference 1
def step2(target, N, e, l, c, f1, B):
	f2 = int(math.floor(float(N + B)/B) * (f1/2))
	challenge = create_ciphertext((pow(f2, e, N) * c) % N)
	status = interact(target, l, challenge)
	print "Status: " + str(status)

	while status == 1:
		f2 = f2 + (f1/2)
		challenge = create_ciphertext((pow(f2, e, N) * c) % N)
		status = interact(target, l, challenge)
		print "Status: " + str(status)

	return f2

# Performs the attack
def attack(target, config_path):
	Ns, es, ls, cs = read_config(config_path)
	Ni, ei, li, ci = convert_config(Ns, es, ls, cs)

	k = int(math.ceil(math.log(Ni, 256)))
	B = 2 ** (8*(k-1))

	f1 = step1(target, Ni, ei, ls, ci)
	f2 = step2(target, Ni, ei, ls, ci, f1, B)

	print f1
	print f2

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