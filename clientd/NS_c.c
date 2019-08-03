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

int ns_send(){
	struct sockaddr_in source;
	int nbytes, i, len = sizeof(source);
	struct richiesta ric;
	struct M1 m1;
	struct M2 m2;
	struct M4 m4;
	struct M5 m5;

	//unsigned char m3buf[M3_SIZE];
	//unsigned char enc_m3buf[ENCRYPTED_M3_SIZE];
	int enc_m3buf_size = ENCRYPTED_M3_SIZE;

	unsigned char m2buf[M2_SIZE];
	unsigned char enc_m2buf[ENCRYPTED_M2_SIZE];
	int m2buf_size;

	unsigned char enc_m4buf[ENCRYPTED_M4_SIZE];
	unsigned char m4buf[M4_SIZE];
	int enc_m4buf_size = ENCRYPTED_M4_SIZE;
	int m4buf_size;

	unsigned char m5buf[M5_SIZE];
	unsigned char enc_m5buf[ENCRYPTED_M5_SIZE];
	int enc_m5buf_size = ENCRYPTED_M5_SIZE;
	//int m5buf_size;

	// Needham Schroeder Protocol (

	//inizializzazione oggetto Richiesta
	ric.tipo = key_exchange_req;
	//invio richiesta
	if((nbytes = send(ser.socket, (void*)&ric, sizeof(ric), 0)) < sizeof(ric)){
		printf("ERR - It was not possible to launch Needham Schroeder Protocol\n");
		if(nbytes < 0) perror("ERR - Invio dati fallito");
		else printf("ERR - Comunicazione col server interrotta\n");
		exit(0);
	}

	memcpy(m1.nome_a, usr.nome, NAME_LEN);

	memcpy(m1.nome_b, oth.nome, NAME_LEN);

	RAND_poll();
	RAND_bytes(m1.nonce, NONCE_LEN);

	/*for(i = 0; i < NAME_LEN; i++)
		printf("%c", m1.nome_a[i]);
	printf("\n");

	for(i = 0; i < NAME_LEN; i++)
		printf("%c", m1.nome_b[i]);
	printf("\n");*/

	/*printf("m1.nonce [%d bytes]:\n", NONCE_LEN);
	print_bytes(m1.nonce, NONCE_LEN);
	printf("\n");*/

	// )
	if((nbytes = send(ser.socket, (void*)&m1, sizeof(struct M1), 0)) < sizeof(struct M1)){
		printf("ERR - It was not possible to launch Needham Schroeder Protocol [SENDING M1]\n");
		if(nbytes < 0) perror("ERR - Invio dati fallito");
		else printf("ERR - Comunicazione col server interrotta\n");
		exit(0);
	}
	printf("INFO - Inviato M1 a S\n");
	// RECEIVING ENCRYPTED M2 (
	if((nbytes = recv(ser.socket, enc_m2buf, ENCRYPTED_M2_SIZE, 0)) < ENCRYPTED_M2_SIZE){
		printf("ERR - It was not possible to launch Needham Schroeder Protocol [RECEIVING] M2]\n");
		if(nbytes < 0) perror("ERR - Ricezione dati fallita");
		else printf("ERR - Comunicazione col server interrotta\n");
		exit(0);
	}
	printf("INFO - Ricevuto M2 da S\n");
	// )

	// ( DECIPHER AND PRINT M2
	/*printf("cphr_bufssss M2 [%d bytes] fuoti:\n", ENCRYPTED_M2_SIZE);
	print_bytes(enc_m2buf, ENCRYPTED_M2_SIZE);
	printf("\n");*/

	if((m2buf_size = buf_dec(enc_m2buf, ENCRYPTED_M2_SIZE, ser.session_key, SYM_KEY_SIZE, m2buf)) < 0){
		printf("ERR - Error in decrypting M2\n");
		exit(0);
	}

	memcpy(&m2, m2buf, m2buf_size);

	/*printf("\nM2 [%d bytes]:\n", m2buf_size);

	printf("M2 NONCE [%d bytes]:\n", NONCE_LEN);
	print_bytes(m2.nonce, NONCE_LEN);
	printf("\n");*/
	
	/*
	printf("\nM2 SHARED KEY [%d byte]:\n", SYM_KEY_SIZE);
	print_bytes(m2.shared_key, SYM_KEY_SIZE);
	printf("\n\n");
	*/
	
	memcpy(oth.shared_key, m2.shared_key, SYM_KEY_SIZE);
	memcpy(oth.shared_secret, m2.shared_secret, SECRET_SIZE);

	/*printf("\nM2 nome b: ");
	for(i = 0; i < NAME_LEN; i++)
		printf("%c", m2.nome_b[i]);
	printf("\n");

	printf("M2.ENCRYPTED M3 [%d bytes]:\n", enc_m3buf_size);
	print_bytes(m2.encrypted_m3, enc_m3buf_size);
	printf("\n");*/
	// )

	// COMPARE NONCE
	if(nonce_compare(m2.nonce, m1.nonce, NONCE_LEN) != 0){
		printf("ERR - Not fresh nonce\n");
		exit(0);
	}
	// )

	// SEND ENCRYPTED M3 TO B PARTY
	if((nbytes=sendto(usr.socket, m2.encrypted_m3, enc_m3buf_size,0,(struct sockaddr*)&oth.clientAddr, sizeof(oth.clientAddr)))<enc_m3buf_size){
		//errore nell'invio, procedo con la disconnessione
		printf("ERR - Error in sending Encrypted M3 to B party\n");
		if(nbytes < 0) perror("WRN - Errore nell'invio di dati sul socket UDP");
		else printf("WRN - Errore nell'invio di dati sul socket UDP\n");
		return 1;
	}
	printf("INFO - Inviato M3 a B\n");
	//)
	// RECEIVING AND PRINTIG ENCRYPTED M4 (
	nbytes = recvfrom(usr.socket, enc_m4buf, enc_m4buf_size, 0, (struct sockaddr*)&source, (socklen_t*)&len);
	if(nbytes < 0) perror("\nERR - Error in receiving encrypted M3 from UDP port\n");
	printf("INFO - Ricevuto M4 da B\n");

	/*printf("M4 [%d bytes]:\n", enc_m4buf_size);
	print_bytes(enc_m4buf, enc_m4buf_size);
	printf("\n");*/
	// )
	// DECRIPTING AND PRINTING M4 (
	if((m4buf_size = buf_dec(enc_m4buf, ENCRYPTED_M4_SIZE, oth.shared_key, SYM_KEY_SIZE, m4buf)) < 0){
		printf("ERR - Error in decrypting M4\n");
		exit(0);
	}

	/*printf("M4 NONCE [%d bytes]:\n", m4buf_size);
	print_bytes(m4buf, NONCE_LEN);
	printf("\n");*/
	// )
	// MODIFY M4 NONCE AND STORE IN M5 (
	memcpy(&m4, m4buf, m4buf_size);
	for(i = 0; i < NONCE_LEN; i++){
		m5.nonce[i] = m4.nonce[i]^0xff;
	}
	// )

	/*printf("M5 NONCE [%d bytes]:\n", NONCE_LEN);
	print_bytes(m5.nonce, NONCE_LEN);
	printf("\n");*/

	// ENCRYPTING M5 (
	memcpy(m5buf, &m5, M5_SIZE);
	if((enc_m5buf_size = buf_enc(m5buf, M5_SIZE, oth.shared_key, SYM_KEY_SIZE, enc_m5buf)) < 0){ 
		printf("ERR - Error in encrypting M5\n");
		exit(0);
	}
	/*printf("cphr_bufssss M5 [%d bytes] fuoti:\n", enc_m5buf_size);
	print_bytes(enc_m5buf, enc_m5buf_size);
	printf("\n");*/
	// )
	// SENDING M5 (
	if((nbytes=sendto(usr.socket, enc_m5buf, enc_m5buf_size,0,(struct sockaddr*)&oth.clientAddr, sizeof(oth.clientAddr)))<enc_m5buf_size){
		//errore nell'invio, procedo con la disconnessione
		printf("ERR - Error in sending Encrypted M5 to B party\n");
		if(nbytes < 0) perror("WRN - Errore nell'invio di dati sul socket UDP");
		else printf("WRN - Errore nell'invio di dati sul socket UDP\n");
		return 1;
	}
	printf("INFO - Inviato M5 a B\n");
	// )
	return 0;
}

int ns_rcv(){
	struct sockaddr_in source;
	int nbytes, len = sizeof(source), i;
	struct M3 m3;
	struct M4 m4;
	struct M5 m5;
	
	unsigned char m3buf[M3_SIZE];
	int m3buf_size;
	unsigned char enc_m3buf[ENCRYPTED_M3_SIZE];
	int enc_m3buf_size = ENCRYPTED_M3_SIZE;
	
	unsigned char m4buf[M4_SIZE];
	//int m4buf_size;
	unsigned char enc_m4buf[ENCRYPTED_M4_SIZE];
	int enc_m4buf_size;
	
	unsigned char enc_m5buf[ENCRYPTED_M5_SIZE];
	int enc_m5buf_size = ENCRYPTED_M5_SIZE;
	unsigned char m5buf[M5_SIZE];
	int m5buf_size;
	
	// RECEIVING M3 (
	nbytes = recvfrom(usr.socket, enc_m3buf, enc_m3buf_size, 0, (struct sockaddr*)&source, (socklen_t*)&len);
	if(nbytes < 0) perror("\nERR - Error in receiving encrypted M3 from UDP port\n");
	printf("\nINFO - Ricevuto M3 da A\n");
	
	/*printf("M2.ENCRYPTED M3 [%d bytes]:\n", enc_m3buf_size);
	print_bytes(enc_m3buf, enc_m3buf_size);
	printf("\n");*/
	// )
	// DECRYPTING M3 (
	if((m3buf_size = buf_dec(enc_m3buf, ENCRYPTED_M3_SIZE, ser.session_key, SYM_KEY_SIZE, m3buf)) < 0){
		printf("ERR - Error in decryptingg M3\n");
		exit(0);
	}
	// )
	// PRINTING M3 (
	memcpy(&m3, m3buf, m3buf_size);
	
	printf("\nM3 SHARED KEY [%d byte]:\n", SYM_KEY_SIZE);
	print_bytes(m3.shared_key, SYM_KEY_SIZE);
	printf("\n\n");

	/*printf("\nM3 nome b: ");
	for(i = 0; i < NAME_LEN; i++)
		printf("%c", m3.nome_a[i]);
	printf("\n");*/
	// )
	// STORING SHARED KEY
	memcpy(oth.shared_key, m3.shared_key, SYM_KEY_SIZE);
	memcpy(oth.shared_secret, m3.shared_secret, SECRET_SIZE);
	// )
	
	RAND_poll();
	RAND_bytes(m4.nonce, NONCE_LEN);
	/*printf("M4 NONCE -[%d bytes]:\n", NONCE_LEN);
	print_bytes(m4.nonce, NONCE_LEN);
	printf("\n");*/
	
	memcpy(m4buf, &m4, M4_SIZE);
	if((enc_m4buf_size = buf_enc(m4buf, M4_SIZE, oth.shared_key, SYM_KEY_SIZE, enc_m4buf)) < 0){
		printf("ERR - Error in encrypting M4\n");
		exit(0);
	}
	/*printf("cphr_bufssss M4 [%d bytes] fuoti:\n", enc_m4buf_size);
	print_bytes(enc_m4buf, enc_m4buf_size);
	printf("\n");
	
	printf("DOVREI MANDARE M4\n");*/
	if((nbytes=sendto(usr.socket, enc_m4buf, enc_m4buf_size,0,(struct sockaddr*)&oth.clientAddr, sizeof(oth.clientAddr)))<enc_m4buf_size){
		//errore nell'invio, procedo con la disconnessione
		printf("ERR - Error in sending Encrypted M3 to B party\n");
		if(nbytes < 0) perror("WRN - Errore nell'invio di dati sul socket UDP");
		else printf("WRN - Errore nell'invio di dati sul socket UDP\n");
		return 1;
	}
	printf("INFO - Inviato M4 a A\n");
	
	// RECEIVING AND PRINTIG ENCRYPTED M5 (
	//printf("DOVREI RICEVERE M5\n");
	nbytes = recvfrom(usr.socket, enc_m5buf, enc_m5buf_size, 0, (struct sockaddr*)&source, (socklen_t*)&len);
	//errore nei dati ricevuti
	if(nbytes < 0) perror("\nERR - Error in receiving encrypted M5 from UDP port\n");
	printf("INFO - Ricevuto M5 da A\n");
	
	/*printf("M5 [%d bytes]:\n", enc_m5buf_size);
	print_bytes(enc_m5buf, enc_m5buf_size);
	printf("\n");*/
	// )
	
	// DECRIPTING AND PRINTING M5 (
	if((m5buf_size = buf_dec(enc_m5buf, ENCRYPTED_M5_SIZE, oth.shared_key, SYM_KEY_SIZE, m5buf)) < 0){
		printf("ERR - Error in decrypting M5\n");
		exit(0);
	}
	
	/*printf("M5 NONCE [%d bytes]:\n", m5buf_size);
	print_bytes(m5buf, NONCE_LEN);
	printf("\n");*/
	// )
	// CHECK NONCE (
	memcpy(&m5, m5buf, m5buf_size);
	for(i = 0; i < NONCE_LEN; i++){
		m5.nonce[i] = m5.nonce[i]^0xff;
	}
	/*printf("M5 NONCE [%d bytes]:\n", m5buf_size);
	print_bytes(m5.nonce, NONCE_LEN);
	printf("\n");*/
	if(nonce_compare(m4.nonce, m5.nonce, NONCE_LEN) != 0){
		printf("ERR - Nonce not fresh\n");
	}
	printf("INFO - Nonce verified, Everything is okay... Thanks Needham and Schroeder\n");
	// )
	return 0;
}
