SOURCES_C    = $(wildcard *.c)  # Finds all C source files
HEADERS_C    = $(wildcard *.h)  # Finds all C header files

DEBUG = # No debug options by default

.DEFAULT_GOAL = attack

#        target-pattern     prerequisites
attack :        %       : %.c %.h ${SOURCES_C}
	@gcc -Wall -std=gnu99 -O3 ${DEBUG} -o ${@} $(filter %.c, ${^}) -lm -fopenmp
#                                    ^    ^
#                                    |    |
#                                    |    - ${^} is all the pre-req's, space
#                                    |      delimited, and then we filter for
#                                    |      only the %.c files
#                                    - The file name of the target

debug  : clean
	@${MAKE} attack --no-print-directory DEBUG="-g"
	@gdb --args ./attack ./22775.D

clean :
	@rm -f attack

