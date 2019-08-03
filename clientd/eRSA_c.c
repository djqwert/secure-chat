#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

#include "global_struct.h"
#include "cripto.h"

int recv_cipher(int sk, unsigned char** buffer, int buf_len) {
   int ret;
   /* Memory allocation */
   *buffer = malloc(buf_len);
   if(*buffer == NULL){
      printf("\nError allocating memory\n");
      return 1;
   }
   /* Receiving the buffer content */
   ret = recv(sk, *buffer, buf_len, MSG_WAITALL);
   if(ret < buf_len){
   		printf("ERROR RECEIVING THE BUFFER CONTENT [BUF_LEN = %d]\n", buf_len);
      return 1;
   }
   return 0;
}
int receive_test_message(int sk, unsigned char* key, int key_size, unsigned char* nonce) {

	const EVP_CIPHER* cipher = EVP_aes_256_cbc(); // cipher to be used
	EVP_CIPHER_CTX *ctx; // decryption context

	unsigned char* clear_buf;          // buffer for the plain text
	unsigned char* cphr_buf;      // buffer for the received encrypted text
	
	int cphr_size = 32;      // size of buffer for the received encrypted text
	int clear_size = 16;          // size of the plaintext

	int ret, i;
	
	/* Receiving the ciphertext */
	ret = recv_cipher(sk, &cphr_buf, cphr_size);
	if(ret != 0) {
	  printf("\nError receiving the ciphertext\n");
	  return 1;
	}

	/* Creating the decryption context */
	ctx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(ctx);
	ret = EVP_DecryptInit(ctx, cipher, key, NULL);
	if(ret == 0) {
	  printf("\nError: EVP_DecryptInit returned %d\n", ret);
	  return 1;
	}

	/* Allocating the buffer for the plaintext */
	clear_buf = malloc(cphr_size);
	if(clear_buf == NULL) {
	  printf("\nError allocating the buffer for the plaintext\n");
	  return 1;
	}

	ret = decrypt(ctx, cphr_buf, cphr_size, clear_buf, &clear_size);
	if(ret != 0)
	  return 1;
	EVP_CIPHER_CTX_cleanup(ctx);
	free(ctx);

	printf("Test Message received, size is %d bytes, decrypted size is %d bytes\n", cphr_size, clear_size);
	
	printf("Nonce [%d bytes]\n", clear_size);
	print_bytes(clear_buf, clear_size);
	printf("\n\n");
	
	for(i = 0; i < NONCE_LEN; i++){
		if(clear_buf[i] != nonce[i]){
			printf("ERR - Error in receiving nonce, key confirmation not achieved\n");
			return 1;
		}
	}
	
	printf("INFO - Test Message correctly received\n");
	
	free(clear_buf);
	free(cphr_buf);
	
	return 0;
}

EVP_PKEY* retrieve_pubkey(const char* file_name) {
	FILE* file;
	EVP_PKEY* pubkey;

	file = fopen(file_name, "r");
	if(file == NULL){
	  fprintf(stderr, "Error: cannot read PEM file '%s'\n", file_name);
	  return NULL;
	}

	pubkey = PEM_read_PUBKEY(file, NULL, NULL, NULL);
	fclose(file);
	if(pubkey == NULL){
	  fprintf(stderr, "Error: PEM_read_PUBKEY returned NULL\n");
	  return NULL;
	}

	return pubkey;
}
int RSAE(int sk, unsigned char session_key[SYM_KEY_SIZE]) {

	unsigned char nonce[NONCE_LEN];

	unsigned char* nonceRes;
	int nonceRes_len;

	unsigned char* tpubk_buf; 
	int tpubk_buf_size;

	unsigned char* sgnt_buf;
	int sgnt_buf_size;

	unsigned char* buf_to_verify;

	const char* pubkey_file_name = "./clientd/pubkey.pem";
	EVP_PKEY* pubkey; // client's public key

	// correcting ersa (
	unsigned char* hashed_nonce;
	unsigned int hashed_nonce_size;
	// )

	const EVP_MD* md = EVP_sha256();

	int key_size;
	unsigned char key[EVP_MAX_KEY_LENGTH]; // encryption key
	unsigned char key_nonce[EVP_MAX_KEY_LENGTH + NONCE_LEN]; 

	//int symk_buf_size;		// encrypted symmetric key size
	unsigned char symk_buf[ENCRYPTED_SYM_KEY_SIZE] = {};	// buffer containing the encrypted symmetric key

	RSA* rsa = NULL;
	BIO* keybio;

	unsigned int i;
	int ret;

	RAND_poll();
	RAND_bytes(nonce, NONCE_LEN);

	printf("Nonce [%d bytes]\n", NONCE_LEN);
	print_bytes(nonce, NONCE_LEN);
	printf("\n\n");

	// correcting ersa(
	if(digest_message(nonce, NONCE_LEN, &hashed_nonce, &hashed_nonce_size) != 0){
		printf("ERR - Error in hashing nonce\n");
		return 1;
	}
	printf("Hash nonce [%d bytes]\n", hashed_nonce_size);
	print_bytes(hashed_nonce, hashed_nonce_size);
	printf("\n");
	//)

	ret = send(sk, hashed_nonce, hashed_nonce_size, 0);

	if(ret < NONCE_LEN){
		printf("ERR - Error in sending nonce\n");
		return 1;
	}

	// Receiving the nonce response (tpubk + signed nonce||tpubk)
	ret = recv_buffer(sk, &nonceRes, &nonceRes_len);
	if(ret != 0) {
	  fprintf(stderr, "ERR - Error in receiving the nonce response\n");
	  return 1;
	}

	/*printf("nonceres [%d byte]:\n", nonceRes_len);
	print_bytes(nonceRes, nonceRes_len);
	printf("\n");*/

	// Splitting tpubkey and nonce||tpubk signature
	for(i = 0; i < nonceRes_len; ++i){
		if(
			nonceRes[i] == '-' &&
			nonceRes[i+1] == '-' &&
			nonceRes[i+2] == '-' &&
			nonceRes[i+3] == '-' &&
			nonceRes[i+4] == '-' &&
			nonceRes[i+5] == 'E' &&
			nonceRes[i+6] == 'N' &&
			nonceRes[i+7] == 'D' &&
			nonceRes[i+8] == ' ' &&
			nonceRes[i+9] == 'P' &&
			nonceRes[i+10] == 'U' &&
			nonceRes[i+11] == 'B' &&
			nonceRes[i+12] == 'L' &&
			nonceRes[i+13] == 'I' &&
			nonceRes[i+14] == 'C' &&
			nonceRes[i+15] == ' ' &&
			nonceRes[i+16] == 'K' &&
			nonceRes[i+17] == 'E' &&
			nonceRes[i+18] == 'Y' &&
			nonceRes[i+19] == '-' &&
			nonceRes[i+20] == '-' &&
			nonceRes[i+21] == '-' &&
			nonceRes[i+22] == '-' &&
			nonceRes[i+23] == '-' &&
			nonceRes[i+24] == '\n'
		) break;
	}

	tpubk_buf_size = i + DELIMITER_SIZE;
	tpubk_buf = malloc(tpubk_buf_size);

	for(i = 0; i < tpubk_buf_size; i++){
		tpubk_buf[i] = nonceRes[i];
	}

	sgnt_buf_size = nonceRes_len - tpubk_buf_size;
	sgnt_buf = malloc(sgnt_buf_size);

	for(i = tpubk_buf_size; i < tpubk_buf_size + sgnt_buf_size; i++){
		sgnt_buf[i - tpubk_buf_size] = nonceRes[i];
	}

	// VERIFYING THE SIGNATURE ( ...
	pubkey = retrieve_pubkey(pubkey_file_name);
	if(pubkey == NULL) {
	  fprintf(stderr, "Error: retrieve_pubkey returned NULL\n");
	  return 1;
	}

	// Appending the nonce to the temporary server public key
	buf_to_verify = malloc(tpubk_buf_size + HASH_SIZE + sgnt_buf_size); //

	for(i = 0; i < tpubk_buf_size; ++i){
		buf_to_verify[i] = tpubk_buf[i];
	}

	for(i = 0; i < HASH_SIZE; i++)
		buf_to_verify[tpubk_buf_size + i] = hashed_nonce[i];

	for(i = 0; i < sgnt_buf_size; i++)
		buf_to_verify[tpubk_buf_size + HASH_SIZE + i] = sgnt_buf[i];

	ret = verify(pubkey, md, buf_to_verify, tpubk_buf_size + HASH_SIZE, sgnt_buf, sgnt_buf_size);

	if(ret != 0){
	  	printf("\nERR - Error in verifying signature\n\n");
	  	return 1;
  	}

	printf("\nINFO - Firma verificata\n");

	// [END VERIFYING THE SIGNATURE] )

	// GENERATING THE SIMMETRIC KEY (
	key_size = EVP_CIPHER_key_length(EVP_aes_256_cbc());
	RAND_bytes(key, key_size);

	printf("\nSession key:\n");
	print_bytes(key, key_size);
	printf("\n\n");

	for(i = 0; i < key_size; i++)
		key_nonce[i] = key[i];
	for(i = 0; i < NONCE_LEN; i++)
		key_nonce[key_size + i] = nonce[i];
	// )

	// ENCRYPT SYMMETRIC KEY (
	keybio = BIO_new_mem_buf(tpubk_buf, -1);
	rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
	RSA_public_encrypt(key_size + NONCE_LEN, key_nonce, symk_buf, rsa, RSA_PKCS1_OAEP_PADDING);
	// )

	ret = send(sk, symk_buf, ENCRYPTED_SYM_KEY_SIZE, 0);
	if(ret < ENCRYPTED_SYM_KEY_SIZE){
		printf("\nError sending the encrypted symmetric key\n");
		return 1;
	}
	// )

	memcpy(session_key, key, key_size);

	ret = receive_test_message(sk, key, key_size, nonce);
	if(ret != 0) {
	  printf("\nError receiving the test message to the server.\n");
	  return 1;
	}

	free(tpubk_buf);
	free(sgnt_buf);
	free(buf_to_verify);

	return 0;

}
