/*
	bfed -- perform blowfish encryption/decryption

					Bo Yu (boyu2011@gmail.com)
*/

#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <string.h>
#include <unistd.h>

/* Commandline argument flags. */
int d_flag = 0;
int e_flag = 0;
int h_flag = 0;
int k_flag = 0;

/* Key string */
char g_key [16];

void usage ()
{
	printf ( "\nbfed — perform blowfish encryption/decryption\n" );
	printf ( "Usage: bfed [ −deh] −k key\n" );
}

/* Parse commandline arguments. */
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

	/* only one, either -e or -d can be specified */
	if ( ( d_flag && e_flag ) || ( !d_flag && !e_flag ) )
	{
		usage();
		exit(0);
	}

	/* key (-k) option should be presented */
	if ( !k_flag )
	{
		usage();
		exit(0);
	}
}

/*
	The Symmetirc Key verification.

	The key should be 128bit ( 16 byte ), and it must be exactly
	16 hexadecimal characters.
*/

int verify_key_string ( char * key_string )
{
	int i = 0;

	if ( strlen(g_key)!=16 )
	{
		printf ( "Key length should be 16 byte.\n" );
		return -1;
	}

	for ( i = 0; i < strlen(g_key); i++ )
	{
		char c = key_string[i];
		if ( !( (c >= '0' && c <= '9') ||
			    (c >= 'a' && c <= 'f') ||
			    (c >= 'A' && c <= 'F') ) )
		{
			printf ( "Key must be exactly 16 hexadecimal characters.\n" );
			return -1;
		}
	}

	return 1;		
}

/*
	Since the key is given on the command-line, bfed presents leaking
	the secret into the process table by manipulating argv.
*/
void erase_cmdline_args ( int argc, char ** argv )
{
	int i = 0;

	for ( i = 1; i < argc; i++ )
	{
		memset ( argv[i], 'x', strlen(argv[i]) );
	}
}

/*
	Encrypt/Decrypt Input/Output Stream.

	if do_encrypt == 1, execute encryption.
	if do_encrypt == 0, execute decryption.
*/

int do_crypt(FILE *in, FILE *out, int do_encrypt, unsigned char * key)
{
	/* Allow enough space in output buffer for additional block */
	unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
	int inlen, outlen;
   	EVP_CIPHER_CTX ctx;
	/* Bogus key and IV: we'd normally set these from
	* another source.
	*/
	unsigned char iv[] = "00000000";
	/* Don't set key or IV because we will modify the parameters */
	EVP_CIPHER_CTX_init(&ctx);
	/* 2nd parameter decides which algorithm do we use!! */
	EVP_CipherInit_ex(&ctx, EVP_bf_cbc(), NULL, NULL, NULL, do_encrypt);
	EVP_CIPHER_CTX_set_key_length(&ctx, 16);
	/* We finished modifying parameters so now we can set key and IV */
	/* 4th parameter is key, 5th parameter is IV */
	EVP_CipherInit_ex(&ctx, NULL, NULL, key, iv, do_encrypt);

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
	/* Initialize the world */
	memset ( g_key, 0x0, sizeof(g_key) );

	parse_cmd_opt ( argc, argv );

	if ( verify_key_string ( g_key ) == -1 )
	{
		usage();
		exit(0);
	}

	/* Prevent the key within the command-line arguemnt from leaking. */
	erase_cmdline_args ( argc, argv );
	
	if ( e_flag )
	{
		/* Encryption */
		do_crypt ( stdin, stdout, 1, (unsigned char *)g_key );	
	}

	if ( d_flag )
	{
		/* Decryption */
		do_crypt ( stdin, stdout, 0, (unsigned char *)g_key );
	}

	return 0;
}
