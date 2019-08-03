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

void print_bytes(const unsigned char* buf, int len) {
   int i;
   if (len <= 0)
      return;
   for (i = 0; i < len - 1; i++)
      printf("%02X:", buf[i]);
   printf("%02X", buf[len - 1]);
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
EVP_PKEY* retrieve_prvkey(const char* file_name) {
   FILE* file;
   EVP_PKEY* prvkey;

   file = fopen(file_name, "r");
   if(file == NULL){
      fprintf(stderr, "Error: cannot read PEM file '%s'\n", file_name);
      return NULL;
   }

   prvkey = PEM_read_PrivateKey(file, NULL, NULL, NULL);
   fclose(file);
   if(prvkey == NULL){
      fprintf(stderr, "Error: PEM_read_PrivateKey returned NULL\n");
      return NULL;
   }

   return prvkey;
}

int decrypt(EVP_CIPHER_CTX *ctx, const unsigned char* cphr_buf, int cphr_size, unsigned char* clear_buf, int* clear_size) {
   int nd; /* amount of bytes decrypted at each step */
   int ndtot; /* total amount of decrypted bytes */
   int ct_ptr, msg_ptr; /* pointers to the first free location of the buffers */

   int ret;

   nd = 0;
   ndtot = 0;
   ct_ptr = 0;
   msg_ptr =0;

   /* Single step encryption */
   ret = EVP_OpenUpdate(ctx, clear_buf, &nd, cphr_buf + msg_ptr, cphr_size);
   if(ret == 0){
      fprintf(stderr, "Error: EVP_OpenUpdate returned %d\n", ret);
      return 1;
   }
   ct_ptr += nd;
   ndtot += nd;

   ret = EVP_OpenFinal(ctx, clear_buf + ct_ptr, &nd);
   if(ret == 0){
      fprintf(stderr, "Error: EVP_OpenFinal returned %d\n", ret);
      return 1;
   }
   ndtot += nd;

   *clear_size = ndtot;

   return 0;
}

int encrypt(EVP_CIPHER_CTX *ctx, const unsigned char* clear_buf, const int clear_size, unsigned char* cphr_buf, int* cphr_size) {
   int nc; /* amount of bytes encrypted at each step */
   int nctot; /* total amount of encrypted bytes */
   int ct_ptr; /* pointers to the first free location of the buffers */

   int ret;

   nc = 0;
   nctot = 0;
   ct_ptr = 0;

   /* Single step encryption */
   ret = EVP_SealUpdate(ctx, cphr_buf, &nc, clear_buf, clear_size);  
   if(ret == 0){
      fprintf(stderr, "Error: EVP_SealUpdate returned %d\n", ret);
      return 1;
   }
   ct_ptr += nc;
   nctot += nc;

   ret = EVP_SealFinal(ctx, cphr_buf + ct_ptr, &nc);
   if(ret == 0){
      fprintf(stderr, "Error: EVP_SealFinal returned %d\n", ret);
      return 1;
   }
   nctot += nc;

   *cphr_size = nctot;

   return 0;
}

int send_buffer(int sk, unsigned char* buffer, int buf_len){	// D0N'T SEND LENGTH FIRST
   int ret;

   /* Sending the buffer content */
   ret = send(sk, buffer, buf_len, 0); 
   if(ret < buf_len){
      return 1;
   }

   return 0;
}

int recv_buffer(int sk, unsigned char** buffer, int* buf_len) { // IT REQUIRES LENGTH FIRST
	int ret;

	// Receiving the buffer length
	ret = recv(sk, buf_len, sizeof(*buf_len), MSG_WAITALL);
	if(ret < sizeof(*buf_len)) {
		printf("ERR - Error in receiving the nonce response length\n");
		return 1;
	}

	// Memory allocation
	*buffer = malloc(*buf_len);
	if(*buffer == NULL){
		fprintf(stderr, "ERR - Error allocating memory\n");
		return 1;
	}

	// Receiving the buffer content
	ret = recv(sk, *buffer, *buf_len, MSG_WAITALL);
	if(ret < *buf_len){
	  return 1;
	}

	return 0;
}

int verify(EVP_PKEY *pubkey, const EVP_MD* md, const unsigned char* msg_buf, const int msg_size, const unsigned char* sgnt_buf, int sgnt_size) {

	EVP_MD_CTX* md_ctx;     // signature context
	int ret;

	md_ctx = malloc(sizeof(EVP_MD_CTX));
	EVP_MD_CTX_init(md_ctx);

	ret = EVP_VerifyInit(md_ctx, md);
	if(ret == 0){
	  fprintf(stderr, "Error: EVP_VerifyInit returned %d\n", ret);
	  return 1;
	}

	/* Single step encryption */
	ret = EVP_VerifyUpdate(md_ctx, msg_buf, msg_size);  
	if(ret == 0){
	  fprintf(stderr, "Error: EVP_VerifyUpdate returned %d\n", ret);
	  return 1;
	}

	ret = EVP_VerifyFinal(md_ctx, sgnt_buf, sgnt_size, pubkey);
	if(ret != 1){ // it is 0 if invalid signature, -1 if some other error, 1 if success.
	  fprintf(stderr, "Error: EVP_VerifyFinal returned %d\n", ret);
	  return 1;
	}

	EVP_MD_CTX_cleanup(md_ctx);
	free(md_ctx);

	return 0;
}

int sign(EVP_PKEY *prvkey, const EVP_MD* md, const unsigned char* msg_buf, const int msg_size, unsigned char* sgnt_buf, int* sgnt_size) {

   EVP_MD_CTX* md_ctx;     // signature context
   int ret;

   md_ctx = malloc(sizeof(EVP_MD_CTX));
   EVP_MD_CTX_init(md_ctx);

   ret = EVP_SignInit(md_ctx, md);
   if(ret == 0){
      fprintf(stderr, "Error: EVP_SignInit returned %d\n", ret);
      return 1;
   }

   /* Single step encryption */
   ret = EVP_SignUpdate(md_ctx, msg_buf, msg_size);  
   if(ret == 0){
      fprintf(stderr, "Error: EVP_SignUpdate returned %d\n", ret);
      return 1;
   }

   ret = EVP_SignFinal(md_ctx, sgnt_buf, (unsigned int*)sgnt_size, prvkey);
   if(ret == 0){
      fprintf(stderr, "Error: EVP_SignFinal returned %d\n", ret);
      return 1;
   }

   EVP_MD_CTX_cleanup(md_ctx);
   free(md_ctx);

   return 0;
}

int retrieve_key(const char* file_name, unsigned char* key, int key_size) {
   int ret;
   FILE* file;

   file = fopen(file_name, "r");
   if(file == NULL)
      return 1;

   ret = fread(key, 1, key_size, file);
   fclose(file);
   if(ret < key_size)
      return 1;

   return 0;
}

int retrieve_hash_key(const char* file_name, unsigned char* key, int key_size) {
   int ret;
   FILE* file;

   file = fopen(file_name, "r");
   if(file == NULL)
      return 1;

   ret = fread(key, 1, key_size, file);
   fclose(file);
   if(ret < key_size)
      return 1;

   return 0;
}

unsigned char* myhash(unsigned char* clear_buf, int size, unsigned char* key_hmac, int key_hmac_size){

	const EVP_MD* md = EVP_sha256();
	HMAC_CTX* mdctx;    // authentication context

	int hash_size;         // digest size
	unsigned char* hash_buf;   // buffer to contain the file digest
	int ret;
	static unsigned char hs[HASH_SIZE];

	/* Reading the file to be sent */
	hash_size = EVP_MD_size(md);

	/* Creating the authentication context */
	mdctx = malloc(sizeof(HMAC_CTX));
	HMAC_CTX_init(mdctx);
	ret = HMAC_Init(mdctx, key_hmac, key_hmac_size, md);
	if(ret == 0) {
	  printf("\nError: HMAC_Init returned %d\n", ret);
	  exit(0);
	}

	/* Creating the digest */
	hash_buf = malloc(hash_size);
	if(hash_buf == NULL) {
	  printf("\nError allocating the digest buffer\n");
	  exit(0);
	}
	ret = HMAC_Update(mdctx, clear_buf, size);
	if(ret == 0) {
	  printf("\nError: HMAC_Update returned %d\n", ret);
	  exit(0);
	}
	ret = HMAC_Final(mdctx, hash_buf, (unsigned int*)&hash_size);
	if(ret == 0) {
	  printf("\nError: HMAC_Final returned %d\n", ret);
	  exit(0);
	}
	HMAC_CTX_cleanup(mdctx);
	free(mdctx);
	
	printf("\nHash [%d byte]:\n", hash_size);
	print_bytes(hash_buf, hash_size);
	printf("\n\n");

	memcpy(hs,hash_buf,hash_size);

	free(hash_buf);

	return hs;

}

int buf_dec(unsigned char* cphr_buf, int size, unsigned char* key, int key_size, unsigned char* clear_buf) {

   const EVP_CIPHER* cipher = EVP_aes_256_cbc(); // cipher to be used
   EVP_CIPHER_CTX *ctx; // decryption context

   int cphr_size = size;      // size of buffer for the received encrypted text
   int clear_size;          // size of the plaintext

   int ret;

   /*printf("STO DECIFRANDO CON [%d bytes]:\n", SYM_KEY_SIZE);
   print_bytes(key, SYM_KEY_SIZE);
   printf("\n");*/

   /* Creating the decryption context */
   ctx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
   EVP_CIPHER_CTX_init(ctx);
   ret = EVP_DecryptInit(ctx, cipher, key, NULL);
   if(ret == 0) {
      printf("\nError: EVP_DecryptInit returned %d\n", ret);
      return -1;
   }
   //printf("1\n");
   /* Allocating the buffer for the plaintext */
   //*clear_buf = malloc(cphr_size);
   /*if(clear_buf == NULL) {
      printf("\nError allocating the buffer for the plaintext\n");
      return -1;
   }*/
   //printf("2\n");
   ret = decrypt(ctx, cphr_buf, cphr_size, clear_buf, &clear_size);
   if(ret != 0)
      return -1;
   EVP_CIPHER_CTX_cleanup(ctx);
   free(ctx);
   //printf("3\n");
   return clear_size;
}

int buf_enc(unsigned char* clear_buf, int size, unsigned char* key, int key_size, unsigned char* cphr_buf) {

   const EVP_CIPHER* cipher = EVP_aes_256_cbc();
   EVP_CIPHER_CTX* ctx;    // encryption context

   //unsigned char* cphr_buf;   // buffer to contain the ciphertext
   int cphr_size;
   int block_size;

   int ret;

   /*
   printf("STO CIFRANDO CON [%d bytes]:\n", SYM_KEY_SIZE);
   print_bytes(key, SYM_KEY_SIZE);
   printf("\n");

   printf("MALLOC:\n" );
   */
   /* Creating the encryption context */
   ctx = malloc(sizeof(EVP_CIPHER_CTX));
   EVP_CIPHER_CTX_init(ctx);
   ret = EVP_EncryptInit(ctx, cipher, key, NULL);
   if(ret == 0) {
      printf("\nError: EVP_EncryptInit returned %d\n", ret);
      return -1;
   }

   //printf("BLOCK:\n");
   /* Allocating the buffer for the ciphertext */
   block_size = EVP_CIPHER_block_size(cipher);
   cphr_size = size + block_size;
   //*cphr_buf = malloc(cphr_size);
   /*if(cphr_buf == NULL) {
      printf("\nError allocating the ciphertext buffer\n");
      return -1;
   }*/

   /*printf("ENCRYPT:\n" );
   printf("%d %d\n",size,cphr_size);*/
   ret = encrypt(ctx, clear_buf, size, cphr_buf, &cphr_size);
   if(ret != 0)
      return -1;

   //printf("FREE:\n");
   EVP_CIPHER_CTX_cleanup(ctx);
   free(ctx);

   /* Sending the ciphertext */
   /*printf("cphr_bufssss [%d bytes]:\n", cphr_size);
   print_bytes(cphr_buf, cphr_size);
   printf("\n");*/
   if(ret != 0) {
      printf("\nError transmitting the ciphertext\n ");
      return -1;
   }
   
   return cphr_size;
}

int nonce_compare(unsigned char *a, unsigned char *b, int size) {
    while(size-- > 0) {
        if ( *a != *b ) { return (*a < *b ) ? -1 : 1; }
        a++; b++;
    }
    return 0;
}
