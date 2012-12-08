bfed: clean
	cc -Wall -lcrypto bfed.c -o bfed
clean:
	rm -f bfed file.enc file.dec
