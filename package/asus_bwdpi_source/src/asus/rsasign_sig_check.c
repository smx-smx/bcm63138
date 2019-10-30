#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <bwdpi_common.h>
#include <bwdpi.h>
/*RSA check*/
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

int check_rsasign(char *fname);

int check_rsasign(char *fname)
{

	RSA *rsa_pkey = NULL;
	EVP_PKEY *pkey = NULL;
	EVP_MD_CTX ctx;
	unsigned char buffer[16*1024];
	size_t len;
	unsigned char *sig = NULL;
	unsigned int siglen;
	struct stat stat_buf;

	FILE * publicKeyFP = NULL;
	FILE * dataFileFP = NULL;
	FILE * sigFileFP = NULL;	

	publicKeyFP = fopen( "/usr/sbin/public_sig.pem", "r" );
	if (publicKeyFP == NULL){
		printf("Open publicKeyFP failure\n");
		goto failed;
	}

	if (!PEM_read_RSA_PUBKEY(publicKeyFP, &rsa_pkey, NULL, NULL)) {
		printf("Error loading RSA public Key File.\n");
		goto failed;
	}

	fclose(publicKeyFP);
	publicKeyFP = NULL;

	pkey = EVP_PKEY_new();
	if(!pkey)
		goto failed;

	if (!EVP_PKEY_assign_RSA(pkey, rsa_pkey)) {
		printf("EVP_PKEY_assign_RSA: failed.\n");
		goto failed;
	}

	sigFileFP = fopen( "/tmp/rsasign.bin", "r" );
	if (sigFileFP == NULL){
		printf("Open sigFileFP failure\n");
		goto failed;
	}

	/* Read the signature */
	if (fstat(fileno(sigFileFP), &stat_buf) == -1) {
		printf("Unable to read signature \n");
		goto failed;
	}

	siglen = stat_buf.st_size;
	sig = (unsigned char *)malloc(siglen);
	if (sig == NULL) {
		printf("Unable to allocated %d bytes for signature\n", siglen);
		goto failed;
	}

	if ((fread(sig, 1, siglen, sigFileFP)) != siglen) {
		printf("Unable to read %d bytes for signature\n", siglen);
		goto failed;
	}
	fclose(sigFileFP);
	sigFileFP = NULL;

	EVP_MD_CTX_init(&ctx);
	if (!EVP_VerifyInit(&ctx, EVP_sha1())) {
		printf("EVP_SignInit: failed.\n");
		goto failed;
	}

	dataFileFP = fopen( fname, "r" );
	if (dataFileFP == NULL){
		printf("Open dataFileFP failure\n");
		goto failed;
	}

	while ((len = fread(buffer, 1, sizeof buffer, dataFileFP)) > 0) {
		if (!EVP_VerifyUpdate(&ctx, buffer, len)) {
			printf("EVP_SignUpdate: failed.\n");
			goto failed;
		}
	}

	if (ferror(dataFileFP)) {
		printf("input file");
		goto failed;
	}
	fclose(dataFileFP);
	dataFileFP = NULL;

	if (!EVP_VerifyFinal(&ctx, sig, siglen, pkey)) {
		printf("EVP_VerifyFinal: failed.\n");
		goto failed;
	}else{
		printf("EVP_VerifyFinal: ok.\n");
	}

	free(sig);
	EVP_PKEY_free(pkey);
	return 1;

failed:
	if(publicKeyFP)
		fclose(publicKeyFP);

	if(dataFileFP)
		fclose(dataFileFP);

	if(sigFileFP)
		fclose(sigFileFP);

	if(pkey)
		EVP_PKEY_free(pkey);

	if(sig)
		free(sig);
	return 0;
}

int
main(int argc, char *argv[])
{
	if(argc!=2)
		return -1;

	printf("rsa fw: %s\n", argv[1]);

	if(check_rsasign(argv[1])) {
		printf("rsasign check sig OK\n");
		nvram_set("bwdpi_rsa_check", "1");
	}
	else
	{
		printf("rsasign check sig Fail\n");
		nvram_set("bwdpi_rsa_check", "0");
	}
	return 0;
}
