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

struct nonceResponse{
	unsigned char nonce[NONCE_LEN];
	EVP_PKEY* tpubkey;
};

int send_msg_and_sgnt(int sk, const unsigned char* buffer, int buf_len){
	int ret;

	// Sending the buffer length
	ret = send(sk, &buf_len, sizeof(buf_len), 0); 
	if(ret < sizeof(buf_len)){
		return 1;
	}

	// Sending the buffer content
	ret = send(sk, buffer, buf_len, 0); 
	if(ret < buf_len){
		return 1;
	}

	return 0;
}

void generateKeys(){
	
	system("openssl genrsa -out tprvkey.pem 3072");
	system("openssl rsa -pubout -in tprvkey.pem -out tpubkey.pem");
	
}
int send_test_message(int sk, unsigned char* key, int key_size, unsigned char* nonce) {
	int size;          // size of the file to be sent

	const EVP_CIPHER* cipher = EVP_aes_256_cbc();
	EVP_CIPHER_CTX* ctx;    // encryption context

	unsigned char* clear_buf;      // buffer to contain the file + the digest
	unsigned char* cphr_buf;   // buffer to contain the ciphertext
	int cphr_size = 32;   // size of the ciphertext
	int block_size;

	int ret;
	size = NONCE_LEN;

	/* Reading the file to be sent */
	clear_buf = malloc(size);
	memcpy(clear_buf, nonce, size);

	/* Creating the encryption context */
	ctx = malloc(sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(ctx);
	ret = EVP_EncryptInit(ctx, cipher, key, NULL);
	if(ret == 0) {
	  printf("\nError: EVP_EncryptInit returned %d\n", ret);
	  return 1;
	}

	/* Allocating the buffer for the ciphertext */
	block_size = EVP_CIPHER_block_size(cipher);
	cphr_size = size + block_size;
	cphr_buf = malloc(cphr_size);
	if(cphr_buf == NULL) {
	  printf("\nError allocating the ciphertext buffer\n");
	  return 1;
	}

	ret = encrypt(ctx, clear_buf, size, cphr_buf, &cphr_size);
	if(ret != 0)
	  return 1;
	EVP_CIPHER_CTX_cleanup(ctx);
	free(ctx);

	/* Sending the ciphertext */
	ret = send_buffer(sk, cphr_buf, cphr_size);
	if(ret != 0) {
	  printf("\nError transmitting the ciphertext\n ");
	  return 1;
	}
	
	printf("\nTest message sent to the server, size is %d bytes, encrypted size is %d bytes\n", size, cphr_size);

	free(clear_buf);
	free(cphr_buf);

	return 0;
}
int digest_message(const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len){
	EVP_MD_CTX *mdctx;

	if((mdctx = EVP_MD_CTX_create()) == NULL){
	  fprintf(stderr, "ERR - Error in creating MD context\n");
	  return 1;
	}

	if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)){
	  fprintf(stderr, "ERR - Error in initializating MD context\n");
	  return 1;
	}

	if(1 != EVP_DigestUpdate(mdctx, message, message_len)){
	  fprintf(stderr, "ERR - Error in updating MD context\n");
	  return 1;
	}

	if((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL){
	  fprintf(stderr, "ERR - Error in allocating memory for the digest\n");
	  return 1;
	}

	if(1 != EVP_DigestFinal_ex(mdctx, *digest, digest_len)){
	  fprintf(stderr, "ERR - Error in concluding hashing operation\n");
	  return 1;
	}

	EVP_MD_CTX_destroy(mdctx);
	return 0;
}
int RSAE(int sk, unsigned char session_key[SYM_KEY_SIZE]) {

	FILE* file;      // pointer to the file to be sent
	int msg_size;          // size of the file to be sent
	
	unsigned char* clear_buf_to_sign; // buffer containing the tpubkey and the nonce that will be signed
	unsigned char* clear_buf_to_send; // buffer containing the tpubkey and the signature
	unsigned char* clear_buf; // buffer containing the tpubkey
	
	unsigned char nonce[NONCE_LEN];
	unsigned char hashed_nonce[HASH_SIZE];
	
	unsigned char* my_hashed_nonce;
	unsigned int my_hashed_nonce_size;
	
	const char* prvkey_file_name = "./serverd/prvkey.pem";
	EVP_PKEY* prvkey; // server's private key
	const char* tprvkey_file_name = "tprvkey.pem";
	EVP_PKEY* tprvkey; // temporary server's private key
	const char* tpubkey_file_name = "tpubkey.pem";
	EVP_PKEY* tpubkey; // temporary server's public key
	
	int tprvk_buf_size;
	unsigned char* tprvk_buf;
	
	unsigned char* sgnt_buf;  // buffer containing the signature
	int sgnt_size;            // size of the signature
	
	const EVP_MD* md = EVP_sha256();
	
	unsigned char enc_sym_key_buf[ENCRYPTED_SYM_KEY_SIZE]={};
	
	unsigned char sym_key[SYM_KEY_SIZE + NONCE_LEN];
	
	RSA* rsa = NULL;
	BIO* keybio;
	
	int ret;
	unsigned int i;
	
	// Receiving nonce
	ret = recv(sk, hashed_nonce, HASH_SIZE, MSG_WAITALL);
	if(ret < NONCE_LEN){
		printf("ERR - Error in receiving nonce\n");
	  	return 1;
	}
	
	generateKeys();
	
	// Retrieve the server's private key
	prvkey = retrieve_prvkey(prvkey_file_name);
	if(prvkey == NULL) {
	  fprintf(stderr, "ERR: retrieve_prvkey [prvkey] returned NULL\n");
	  return 1;
	}
	
	//Retrieve the temporary server's private key
	tprvkey = retrieve_prvkey(tprvkey_file_name);
	if(tprvkey == NULL) {
	  fprintf(stderr, "Error: retrieve_prvkey [tprvkey] returned NULL\n");
	  return 1;
	}
	
	//Retrieve the temporary server's public key
	tpubkey = retrieve_pubkey(tpubkey_file_name);
	if(tpubkey == NULL) {
	  fprintf(stderr, "Error: retrieve_pubkey [tpubkey] returned NULL\n");
	  return 1;
	}
	
	// Open the file to be sent 
	file = fopen("tpubkey.pem", "r");
	if(file == NULL) {
	  fprintf(stderr, "File not found: '%s'\n", "tpubkey.pem");
	  return 1;
	}
	// Retrieve the file size 
	fseek(file, 0, SEEK_END);
	msg_size = ftell(file);
	fseek(file, 0, SEEK_SET);

	clear_buf_to_sign = malloc(msg_size + HASH_SIZE);
	clear_buf = malloc(msg_size);
	ret = fread(clear_buf_to_sign, 1, msg_size, file);
	if(ret < msg_size) {
	  fprintf(stderr, "Error reading the file [1]\n");
	  return 1;
	}
	
	// STORE tprvkey (
	
	// Open the file to be sent 
	file = fopen("tprvkey.pem", "r");
	if(file == NULL) {
	  fprintf(stderr, "File not found: '%s'\n", "tprvkey.pem");
	  return 1;
	}
	// Retrieve the file size 
	fseek(file, 0, SEEK_END);
	tprvk_buf_size = ftell(file);
	fseek(file, 0, SEEK_SET);

	tprvk_buf = malloc(tprvk_buf_size);
	ret = fread(tprvk_buf, 1, tprvk_buf_size, file);
	if(ret < tprvk_buf_size) {
	  fprintf(stderr, "Error reading the file [1]\n");
	  return 1;
	}
	
	// )
	
	for(i = 0; i < msg_size; ++i){
		clear_buf[i] = clear_buf_to_sign[i];
	}
	
	for(i = 0; i < HASH_SIZE; i++)
		clear_buf_to_sign[msg_size + i] = hashed_nonce[i];
	
	fclose(file);

	// Creating the signature 
	sgnt_buf = malloc(EVP_PKEY_size(prvkey));
	ret = sign(prvkey, md, clear_buf_to_sign, msg_size + HASH_SIZE, sgnt_buf, &sgnt_size);
	if(ret != 0)
	  return 1;
	
	// Appending the clear_buf (tpubkey) to the clear_buf_to_sign (signed nonce+tpubkey)
	clear_buf_to_send = malloc(msg_size + sgnt_size);
	for(i = 0; i < msg_size; i++)
		clear_buf_to_send[i] = clear_buf[i];
	for(i = 0; i < sgnt_size; i++)
		clear_buf_to_send[msg_size + i] = sgnt_buf[i];

	ret = send_msg_and_sgnt(sk, clear_buf_to_send, msg_size + sgnt_size);
	if(ret != 0) {
		fprintf(stderr, "ERR - Error transmitting the nonce response\n ");
		return 1;
	}
	// RECEIVING THE ENCRYPTED SYMMETRIC KEY (
	// Memory allocation

	if(enc_sym_key_buf == NULL){
		fprintf(stderr, "Error allocating memory for the encrypted symmetric key\n");
		return 1;
	}

	/* Receiving the buffer content */
	ret = recv(sk, enc_sym_key_buf, ENCRYPTED_SYM_KEY_SIZE, MSG_WAITALL);
	if(ret < ENCRYPTED_SYM_KEY_SIZE){
		fprintf(stderr, "Error in receiving the encrypted symmetric key\n");
		return 1;
	}
	// )
	
	// DECRYPTING ENCRYPTED SYMMETRIC KEY
	keybio = BIO_new_mem_buf(tprvk_buf, -1);
	rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
	RSA_private_decrypt(ENCRYPTED_SYM_KEY_SIZE, enc_sym_key_buf, sym_key, rsa, RSA_PKCS1_OAEP_PADDING);
	
	// )
	
	for(i = 0; i < NONCE_LEN; i++)
		nonce[i] = sym_key[SYM_KEY_SIZE + i];
	
	// correcting ersa(
	if(digest_message(nonce, NONCE_LEN, &my_hashed_nonce, &my_hashed_nonce_size) != 0){
		printf("ERR - Error in hashing nonce\n");
		return 1;
	}
	//)
	
	for(i = 0; i < HASH_SIZE; i++){
		if(my_hashed_nonce[i] != hashed_nonce[i]){
			printf("ERR - Received a not expected nonce, possible impersonation attack\n");
			return 1;
		}
	}
	printf("INFO - Received expected nonce\n");
	memcpy(session_key, sym_key, SYM_KEY_SIZE);
	//printf("CHIAVE COPIATA\n");
	
	ret = send_test_message(sk, sym_key, SYM_KEY_SIZE, nonce);
	if(ret != 0) {
	 printf("Error sending the Test Message file\n");
	 return 1;
	}
	
	system("rm tpubkey.pem");
	system("rm tprvkey.pem");
	
	return 0;
}
