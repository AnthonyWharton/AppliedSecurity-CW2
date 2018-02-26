# Copyright (C) 2017 Daniel Page <csdsp@bristol.ac.uk>
#
# Use of this source code is restricted per the CC BY-NC-ND license, a copy of
# which can be found via http://creativecommons.org (and should be included as
# LICENSE.txt within the associated archive or repository).

import sys, subprocess, time

def read_config(path):
	# Read in config file
	config_file = open(path)
	N = config_file.readline()
	e = config_file.readline()
	l = config_file.readline()
	c = config_file.readline()
	config_file.close()

	print "Read in the following values from Config File:"
	print "          RSA Modulus: " + N[:-1]
	print "  RSA Public Exponent: " + e[:-1]
	print "     RSAES-OAEP Label: " + l[:-1]
	print "RSAES-OAEP Ciphertext: " + c[:-1]

	return N, e, l, c

def convert_config(N_str, e_str, l_str, c_str):
	# Convert numbers
	N = int(N_str, 16)  # RSA Modulus
	e = int(e_str, 16)  # RSA Public Exponent
	l = int(l_str, 16)  # RSAES-OAEP label
	c = int(c_str, 16)  # RSAES-OAEP ciphertext

	return N, e, l, c

def interact(G):
	# Send G to attack target.
	target_in.write("%s\n" % (G));
	target_in.flush()

	# Receive (t, r) from attack target.
	t = int(target_out.readline().strip())
	r = int(target_out.readline().strip())

	return t, r


def attack():
	# Select a hard-coded guess ...

	G = "guess"

	# ... then interact with the attack target.

	(t, r) = interact(G)

	# Print all of the inputs and outputs.

	print "G = %s" % (G)
	print "t = %d" % (t)
	print "r = %d" % (r)

if __name__ == "__main__":
	# Get the file locations for the e-commerce server and public configuration
	server_path = sys.argv[1]
	config_path = sys.argv[2]

	N, e, l, c = read_config(config_path)
	N, e, _, _ = convert_config(N, e, l, c)

	time.sleep(0.001)

	# Produce a sub-process representing the attack target.
	target = subprocess.Popen(args=[server_path],
	                          stdout=subprocess.PIPE,
	                          stdin=subprocess.PIPE)

	# Construct handles to attack target standard input and output.
	target_out = target.stdout
	target_in = target.stdin

	# Execute a function representing the attacker.
	attack()
