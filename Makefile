bfed: clean
	cc -Wall -lcrypto bfed.c -o bfed
clean:
	rm -rf bfed
