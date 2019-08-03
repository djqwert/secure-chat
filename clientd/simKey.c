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

extern struct user usr;
extern struct server ser;
extern struct other oth;
extern struct msg_struct message;
extern char messaggio[MSG_SIZE];

void sk_send(){

	int nbytes;//, msgLen;
	fd_set readFds;
	FD_ZERO(&readFds);
	struct msg_struct msg;
	
	unsigned char msgbuf[MSG_BUF_SIZE];
	//int msgbuf_size;
	unsigned char enc_msgbuf[192];
	int enc_msgbuf_size;
	//(---
	
	memcpy(msg.messaggio, messaggio, MSG_SIZE);
	msg.time_stamp = (unsigned)time(NULL);
	memcpy(msg.digest, myhash((unsigned char*)messaggio, MSG_SIZE, oth.shared_secret, SECRET_SIZE), HASH_SIZE);
	
	//printf("SIZE OF MSG: %d\n", sizeof(struct msg_struct));
	
	/*printf("\nHash messaggio [%d byte]:\n", HASH_SIZE);
	print_bytes(msg.digest, HASH_SIZE);
	printf("\n");*/
	//---
	memcpy(msg.messaggio, messaggio, MSG_SIZE);
	msg.time_stamp = (unsigned)time(NULL);
	
	/*
	printf("SHARED SECRET:\n");
	print_bytes(oth.shared_secret, SECRET_SIZE);
	printf("\n");
	*/
	memcpy(msgbuf, &msg, MSG_BUF_SIZE);
	if((enc_msgbuf_size = buf_enc(msgbuf, MSG_BUF_SIZE, oth.shared_key, SYM_KEY_SIZE, enc_msgbuf)) < 0){
		printf("ERR - Error in encrypting MSG\n");
		exit(0);
	}
	
	/*printf("Encrypted Message [%d bytes] to send:\n", enc_msgbuf_size);
	print_bytes(enc_msgbuf, enc_msgbuf_size);
	printf("\n");*/
	
	if((nbytes=sendto(usr.socket, enc_msgbuf, enc_msgbuf_size,0,(struct sockaddr*)&oth.clientAddr, sizeof(oth.clientAddr)))<enc_msgbuf_size){
		//errore nell'invio, procedo con la disconnessione
		printf("ERR - Error in sending MESSAGE\n");
		if(nbytes < 0) perror("WRN - Errore nell'invio di dati sul socket UDP");
		else printf("WRN - Errore nell'invio di dati sul socket UDP\n");
		return;
	}
	printf("INFO - Messaggio inviato\n");

	// printf("Messaggio istantaneo inviato\n");
	FD_SET(usr.socket, &usr.fdSet);

}

void sk_rcv(){

	int nbytes, i;
	struct sockaddr_in source;
	int len = sizeof(source);
	//int msgLen;
	struct msg_struct msg;
	
	unsigned char enc_msgbuf[192];
	unsigned char msgbuf[MSG_BUF_SIZE];
	int enc_msgbuf_size = 192;
	int msgbuf_size;

	unsigned char* hashed_msg;

	// RECEIVING AND PRINTIG ENCRYPTED MESSAGE (
	nbytes = recvfrom(usr.socket, enc_msgbuf, enc_msgbuf_size, 0, (struct sockaddr*)&source, (socklen_t*)&len);
	//errore nei dati ricevuti
	if(nbytes < 0) perror("\nERR - Error in receiving encrypted MESSAGE from UDP port\n");
	printf("INFO - Messaggio ricevuto\n");

	/*printf("Encrypted Message [%d bytes] received:\n", enc_msgbuf_size);
	print_bytes(enc_msgbuf, enc_msgbuf_size);
	printf("\n");*/
	// )
	// DECRIPTING AND PRINTING MESSAGE (
	if((msgbuf_size = buf_dec(enc_msgbuf, 192, oth.shared_key, SYM_KEY_SIZE, msgbuf)) < 0){
		printf("ERR - Error in decrypting MESSAGE\n");
		exit(0);
	}
	
	memcpy(&msg, msgbuf, msgbuf_size);
	
	/*
	printf("SHARED SECRET:\n");
	print_bytes(oth.shared_secret, SECRET_SIZE);
	printf("\n");
	*/
	
	hashed_msg = malloc(HASH_SIZE);
	memcpy(hashed_msg, myhash((unsigned char*)msg.messaggio, MSG_SIZE, oth.shared_secret, SECRET_SIZE), HASH_SIZE);
	
	for(i = 0; i < HASH_SIZE; i++){
		if(msg.digest[i] != hashed_msg[i]){
			printf("ERR - Errore nell'integrità del messaggio\n");
			return;
		}
	}
	
	//printf("INFO - Integrity check succeded\n");
	
	if(message.time_stamp < msg.time_stamp){
		memcpy(&message, &msg, sizeof(struct msg_struct));
	}else{
		printf("Tentativo di violazione di sicurezza individuato. Sistema abortito.\n");
		exit(1);
	}

	printf("Messaggio da %s:\n%s\n", oth.nome, msg.messaggio); fflush(stdout);
	memset(messaggio, '\0', MSG_LEN);
	free(hashed_msg);
	FD_CLR(usr.socket, &usr.fdSet);
}
