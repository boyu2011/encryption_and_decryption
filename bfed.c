/*
	bfed -- perform blowfish encryption/decryption

					Bo Yu (boyu2011@gmail.com)
*/

#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <string.h>
#include <unistd.h>

#define MAXLINE 1000

int d_flag = 0;
int e_flag = 0;
int h_flag = 0;
int k_flag = 0;

char g_key [16+1];

void usage ()
{
	printf ( "\nbfed — perform blowfish encryption/decryption\n" );
	printf ( "Usage: bfed [ −deh] −k key\n" );
}

void parse_cmd_opt ( int argc, char ** argv )
{
	int ch;

	while ( ( ch = getopt ( argc, argv, "dehk:" ) ) != -1 )
	{
		switch ( ch )
		{
			case 'd':
				d_flag = 1;
				break;

			case 'e':
				e_flag = 1;
				break;

			case 'h':
				h_flag = 1;
				usage();
				exit(0);

			case 'k':
				k_flag = 1;
				strcpy ( g_key, optarg );
				break;

			default:
				usage();
				exit(0);
		}
	}

	/* only -e or -d can be specified */
	if ( ( d_flag && e_flag ) || ( !d_flag && !e_flag ) )
	{
		usage();
		exit(0);
	}

	if ( !k_flag )
	{
		usage();
		exit(0);
	}

	if ( k_flag && (strlen(g_key)!=16) )
	{
		printf ( "\nKey length should be 16 bytes\n" );
		exit(0);
	}
}

/*
	Encrypt/Decrypt stream.

	if do_encrypt == 1, encrypt
	if do_encrypt == 0, decrypt
*/

int do_crypt(FILE *in, FILE *out, int do_encrypt, char * key)
{
	/* Allow enough space in output buffer for additional block */
	char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
	int inlen, outlen;
   	EVP_CIPHER_CTX ctx;
	/* Bogus key and IV: we'd normally set these from
	* another source.
	*/
	//unsigned char key[] = "0123456789";
	unsigned char iv[] = "12345678";
	/* Don't set key or IV because we will modify the parameters */
	EVP_CIPHER_CTX_init(&ctx);
	/* second para decides which algorithm do you use!!!!! */
	EVP_CipherInit_ex(&ctx, EVP_bf_cbc(), NULL, NULL, NULL, do_encrypt);
	EVP_CIPHER_CTX_set_key_length(&ctx, 16);	/* second para !!!!!!!!! */
	/* We finished modifying parameters so now we can set key and IV */
	EVP_CipherInit_ex(&ctx, NULL, NULL, key, NULL, do_encrypt);

	for(;;)
	{
	   inlen = fread(inbuf, 1, 1024, in);
	   if(inlen <= 0) break;
	   if(!EVP_CipherUpdate(&ctx, outbuf, &outlen, inbuf, inlen))
	   {
		   /* Error */
		   EVP_CIPHER_CTX_cleanup(&ctx);
		   return 0;
	   }
	   fwrite(outbuf, 1, outlen, out);
	}
	if(!EVP_CipherFinal_ex(&ctx, outbuf, &outlen))
	{
	   /* Error */
	   EVP_CIPHER_CTX_cleanup(&ctx);
	   return 0;
	}
	fwrite(outbuf, 1, outlen, out);

	EVP_CIPHER_CTX_cleanup(&ctx);
	return 1;
}

/*
	Program entry.
*/

int main( int argc, char ** argv )
{
	parse_cmd_opt ( argc, argv );

	if ( e_flag )
	{
		/* Encryption */
		do_crypt ( stdin, stdout, 1, g_key );	
	}

	if ( d_flag )
	{
		/* Decryption */
		do_crypt ( stdin, stdout, 0, g_key );
	}

	return 0;
}
