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

#include "./serverd/global_struct.h"
#include "./serverd/cripto.h"
#include "./serverd/eRSA_s.h"
#define HASH_SIZE 32

struct user{
	int sockDes;
	char nome[NAME_LEN];
	char indirizzo[ADD_LEN];
	port portaTCP;
	port portaUDP;
	struct sockaddr_in clientAddr;
	int online;
	struct user* other;
	struct user* next;
	unsigned char password[HASH_SIZE];
	unsigned char salt[PASS_LEN];
	unsigned char session_key[SYM_KEY_SIZE];
};
struct server{
	//char indirizzo[ADD_LEN];
	port porta;
	struct  sockaddr_in serverAddr;
	int listener;
	fd_set fdSet;
	int fdMax;
	struct user* listaUtenti;
};

int quit = 0;
int sockAttuale;
int ines = 0;
struct server ser;

void userInit(struct user* u){
	if(u == 0) return;
	u->nome[0] = '\0';
	inet_ntop(AF_INET, &u->clientAddr.sin_addr.s_addr, u->indirizzo, ADD_LEN);
	u->portaTCP = ntohs(u->clientAddr.sin_port);
	u->portaUDP = 0;
	u->online = 1;
	u->other = 0;
	u->next = 0;
}

void manageWrongRequest(int sock);
struct user* cercaUtentePerNome(char* nome);

void NS(int sock){

	int nbytes;
	
	struct M1 m1;
	struct M2 m2;
	struct M3 m3;
	
	unsigned char key_b[SYM_KEY_SIZE];
	unsigned char key_a[SYM_KEY_SIZE];

	unsigned char m2buf[M2_SIZE];
	unsigned char enc_m2buf[ENCRYPTED_M2_SIZE];
	int enc_m2buf_size;
	
	unsigned char m3buf[M3_SIZE];
	unsigned char enc_m3buf[ENCRYPTED_M3_SIZE];
	int enc_m3buf_size;
	
	/*printf("INFO - Starting Needham Schroeder Protocol\n");
	printf("SIZE OF M1: %d\n", sizeof(struct M1));
	printf("SIZE OF M2: %d\n", sizeof(struct M2));
	printf("SIZE OF M3: %d\n", sizeof(struct M3));
	printf("SIZE OF M4: %d\n", sizeof(struct M4));
	printf("SIZE OF M5: %d\n", sizeof(struct M5));*/

	if((nbytes = recv(sock, &m1, sizeof(struct M1), 0)) < sizeof(struct M1)){

		if(nbytes < 0){
			printf("WRN - Error in starttin Needham Schroeder Protocol/n");
			perror("");
		}
	
		//in caso di formato di richiesta non valido (nbytes < sizeof(ric) ma > 0) stampo un warning
		if(nbytes > 0) printf("WRN - Errore nel formato della richiesta ricevuta dal socket %d\n", sock);
	
		//gestione dell'errore o della disconnessione
		manageWrongRequest(sock);
	}

	printf("INFO - Ricevuto M1 da A\n");

	
	/*for(i = 0; i < NAME_LEN; i++)
		printf("%c", m1.nome_a[i]);
	printf("\n");

	for(i = 0; i < NAME_LEN; i++)
		printf("%c", m1.nome_b[i]);
	printf("\n");
	
	//printf("m1.nonce [%d bytes]:\n", NONCE_LEN);
	print_bytes(m1.nonce, NONCE_LEN);
	printf("\n");*/
	
	// SETTING UP M3 (
	m3.time_stamp = m2.time_stamp = (unsigned)time(NULL);
	RAND_bytes(m3.shared_key, SYM_KEY_SIZE);
	RAND_bytes(m3.shared_secret, SECRET_SIZE);
	memcpy(m3.nome_a, m1.nome_a, NAME_LEN);
	/*printf("\nM3:\n");
	for(i = 0; i < NAME_LEN; i++)
		printf("%c", m3.nome_a[i]);
	printf("\n");*/
	
	/*printf("m3.shared_key [%d bytes]:\n", SYM_KEY_SIZE);
	print_bytes(m3.shared_key, SYM_KEY_SIZE);
	printf("\n");*/
	
	memcpy(key_b, cercaUtentePerNome(m1.nome_b)->session_key, SYM_KEY_SIZE);
	memcpy(key_a, cercaUtentePerNome(m1.nome_a)->session_key, SYM_KEY_SIZE);
	
	printf("\nChiave A_S [%d byte]:\n", SYM_KEY_SIZE);
	print_bytes(key_a, SYM_KEY_SIZE);
	printf("\n");
	
	printf("\nChiave B_S [%d byte]:\n", SYM_KEY_SIZE);
	print_bytes(key_b, SYM_KEY_SIZE);
	printf("\n\n");
	
	memcpy(m3buf, &m3, M3_SIZE);
	
	if((enc_m3buf_size = buf_enc(m3buf, M3_SIZE, key_b, SYM_KEY_SIZE, enc_m3buf)) < 0){
		printf("ERR - Error in encrypting M3\n");
		exit(0);
	}

	/*printf("cphr_bufssss M3 [%d bytes] fuoti:\n", enc_m3buf_size);
	print_bytes(enc_m3buf, enc_m3buf_size);
	printf("\n");*/
	
	//SETTING M2
	//printf("\nM2:\n");
	memcpy(m2.nonce, m1.nonce, NONCE_LEN);
	memcpy(m2.shared_key, m3.shared_key, SYM_KEY_SIZE);
	memcpy(m2.shared_secret, m3.shared_secret, SECRET_SIZE);
	memcpy(m2.nome_b, m1.nome_b, NAME_LEN);
	memcpy(m2.encrypted_m3, enc_m3buf, enc_m3buf_size);
	
	/*printf("M2 NONCE [%d bytes]:\n", NONCE_LEN);
	print_bytes(m2.nonce, NONCE_LEN);
	printf("\n");*/
	
	/*printf("m2 SHARED KEY [%d bytes]:\n", SYM_KEY_SIZE);
	print_bytes(m2.shared_key, SYM_KEY_SIZE);
	printf("\n");*/

	/*printf("\nM2 nome b: ");
	for(i = 0; i < NAME_LEN; i++)
		printf("%c", m2.nome_b[i]);
	printf("\n");*/
	
	/*printf("M2.ENCRYPTED M3 [%d bytes]:\n", enc_m3buf_size);
	print_bytes(m2.encrypted_m3, enc_m3buf_size);
	printf("(-1)\n");
	printf("\n");

	printf("(0)\n");*/

	memcpy(m2buf, &m2, M2_SIZE);

	//printf("(1)\n");
	
	if((enc_m2buf_size = buf_enc(m2buf, M2_SIZE, key_a, SYM_KEY_SIZE, enc_m2buf)) < 0){
		printf("ERR - Error in encrypting M2\n");
		exit(0);
	}

	//printf("(2)\n");

	/*printf("cphr_bufssss M2 [%d bytes] fuoti:\n", enc_m2buf_size);
	print_bytes(enc_m2buf, enc_m2buf_size);
	printf("\n");*/

	//printf("(3)\n");
	
	// Sending the buffer content
	printf("INFO - Invio M2 a A\n");
	if((nbytes = send(sock, enc_m2buf, enc_m2buf_size, 0)) < enc_m2buf_size){
		printf("ERR - Error in sending encrypted M2\n");
		if(nbytes < 0) perror("WRN - Errore nell'invio di un messaggio");
		else printf("WRN - Invio di un messaggio non completato correttamente\n");
		return;
	}
	//)

	printf("INFO - Elaborazione terminata\n");
		
}

int digest(struct user* u, unsigned char* clear_buf, int size){

	int key_hmac_size; // cryptographic key size
	unsigned char* key_hmac; // cryptographic key

	const EVP_MD* md = EVP_sha256();
	const EVP_CIPHER* cipher = EVP_aes_128_cbc();
	HMAC_CTX* mdctx;    // authentication context

	int hash_size, i;         // digest size
	unsigned char* hash_buf;   // buffer to contain the file digest
	int ret;

	unsigned char salt[PASS_LEN];
	RAND_poll();
	RAND_bytes(salt, size);
	memcpy(u->salt, (unsigned char*)salt, PASS_LEN);

	for(i = 0; i < PASS_LEN; i++){
		clear_buf[i] += salt[i];
	}

	/* Retrieve the keys */
	key_hmac_size = EVP_CIPHER_key_length(cipher); // same strength of the confidentiality service
	key_hmac = malloc(key_hmac_size);
	ret = retrieve_hash_key("key_hmac", key_hmac, key_hmac_size);
	if(ret != 0) {
	  printf("\nError retrieving the HMAC key\n");
	  return 1;
	}

	/* Reading the file to be sent */
	hash_size = EVP_MD_size(md);

	/* Creating the authentication context */
	mdctx = malloc(sizeof(HMAC_CTX));
	HMAC_CTX_init(mdctx);
	ret = HMAC_Init(mdctx, key_hmac, key_hmac_size, md);
	if(ret == 0) {
	  printf("\nError: HMAC_Init returned %d\n", ret);
	  return 1;
	}

	/* Creating the digest */
	hash_buf = malloc(hash_size);
	if(hash_buf == NULL) {
	  printf("\nError allocating the digest buffer\n");
	  return 1;
	}
	ret = HMAC_Update(mdctx, clear_buf, size);
	if(ret == 0) {
	  printf("\nError: HMAC_Update returned %d\n", ret);
	  return 1;
	}
	ret = HMAC_Final(mdctx, hash_buf, (unsigned int*)&hash_size);
	if(ret == 0) {
	  printf("\nError: HMAC_Final returned %d\n", ret);
	  return 1;
	}
	HMAC_CTX_cleanup(mdctx);
	free(mdctx);
	/*printf("HASH_BUF [%d byte]:\n", hash_size);
	print_bytes(hash_buf, hash_size);
	printf("\n");*/
	
	memcpy(u->password, (unsigned char*)hash_buf, HASH_SIZE);
	
	printf("\nHASH [%d byte]:\n", HASH_SIZE);
	print_bytes(hash_buf, hash_size);
	printf("\n");
	
	free(hash_buf);
	free(key_hmac);

	return 0;

}

int serverInit(struct server* s, port porta){
	int yes = 1;
	s->porta = porta;
	s->serverAddr.sin_family = AF_INET;
	//inet_pton(AF_INET, "127.0.0.1", &s->serverAddr.sin_addr.s_addr);
	s->serverAddr.sin_addr.s_addr = INADDR_ANY; 
	s->serverAddr.sin_port = htons(s->porta);
	
	if((s->listener = socket(AF_INET, SOCK_STREAM, 0)) == -1){
		perror("Errore durante la creazione del server d'ascolto");
		return -1;
	}

	if(setsockopt(s->listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1){
		perror("ERR - Errore durante l'inizializzazione del socket di ascolto");
		return -1;
	}
	printf("INFO - Il socket di ascolto è stato creato\n");
	printf("INFO - L'identificatore de socket di ascolto è: %d\n", s->listener);
	
	//bind su socket di ascolto
	if(bind(s->listener, (struct sockaddr*)&s->serverAddr, sizeof(s->serverAddr)) == -1){
		perror("ERR -  Errore nell'operazione di binding del socket di ascolto");
		return -1;
	}
	
	//listen su socket di ascolto
	if(listen(s->listener, Q_LENGTH) == -1){
		perror("ERR -  Errore nell'operazione di listening sul socket di ascolto");
		return -1;
	}
	printf("INFO - Server in ascolto sul socket: %d\n", s->listener);
	
	//inizializzazione del set di descrittori di file
	FD_ZERO(&s->fdSet);
	FD_SET(s->listener, &s->fdSet);
	s->fdMax = s->listener;
	
	//inizializzazione della lista utenti
	s->listaUtenti = 0;
	
	printf("INFO - Inizializzazione del server completata correttamente\n");
	//printf("Porta: %d\n", s->porta);
	
	return 0;
}
void aggiungiUtente(struct user* u){
	//aggiunge un utente alla lista utenti
	
	if(u == 0) return;
	u->next = ser.listaUtenti;
	ser.listaUtenti = u;
}

struct user* cercaUtentePerNome(char* nome){
	//cerca un utente per nome nella lista utenti e restituisce un puntatore all'elemento trovato
	
	struct user* u = ser.listaUtenti;
	
	while(u != 0){
		if(strcmp(u->nome, nome) == 0) break;
		
		u = u->next;
	}
	
	return u;
}

struct user* cercaUtentePerSocket(int s){
	//cerca un utente per socket di connessione nella lista utenti e restituisce un puntatore all'elemento trovato
	
	struct user* u = ser.listaUtenti;
	
	while(u != 0){
		if(u->sockDes == s) 
			break;
		u = u->next;
	}
	
	return u;
}

void rimuoviUtente(struct user* u){
	//rimuove un utente dalla lista utenti
	
	struct user* p, * q;
	
	if(u == 0) return;
	
	if(ser.listaUtenti != 0){
		if(u == ser.listaUtenti){
			//rimozione del primo elemento della lista
			ser.listaUtenti = u->next;
		}
		else{
			//rimozione di un elemento nel corpo della lista
		
			p = ser.listaUtenti;
			q = p->next;
		
			while(q != 0){
				if(u == q) break; //trovato
				
				//passo al successivo
				p = p->next;
				q = q->next;
			}
			
			//se q è nullo l'elemento non era nella lista quindi non c'è niente da rimuovere
			//se q non è nullo punta all'elemento da rimuovere: rimuovo
			if(q != 0) p->next = q->next;
		}
	}
	
	//se c'era un elemento da rimuovere è stato rimosso; in ogni caso dealloco la memoria
	memset(u, 0, sizeof(struct user));
	free(u);
}

int checkInput(int argc, char* argv[]){
	//controlla la correttezza dei dati in ingresso
	
	int ret = 0;
	int porta;
	int i;
	//formato degli argomenti non corretto
	if(argc != 2) ret = -1;
	else{
		//formato della porta non corretto
		for(i = 0; i < strlen(argv[1]); i++){
			if(argv[1][i] < '0' || argv[1][i] > '9'){
				ret = - 1;
				break;
			}
		}
		
		if(ret == 0){
			porta = atoi(argv[1]);
			//valore della porta non valido
			if(porta < 0 || porta > MAX_PORT) ret = -1;
		}
	}
	
	if(ret == -1) printf("ERR - Errore nei dati di ingresso\nIl formato corretto è il seguente:\n<Port>\nDove <Port> è l'identificatore di una porta valida\n");

	return ret;
}

int getMaxFd(fd_set fdSet, int limit){
	//restituisce il valore del descrittore di file di indice più alto settato in un fd_set
	
	int i;
	
	for(i = limit - 1; i >= 0; i--) if(FD_ISSET(i, &fdSet)) return i;
	return -1;
}

int checkNullCharacterExists(char* s, int len){
	//controlla che in un array di caratteri ci sia il carattere nullo.. restituisce -1 se non è così
	
	int i;
	
	for(i = 0; i < len; i++) if(s[i] == '\0') return 0;
	
	return -1;
}

void manageWrongRequest(int sock){
	//gestisce una richiesta errata (o una disconnessione)
	struct user* utenteDisconnesso;

	utenteDisconnesso = cercaUtentePerSocket(sock);
		
	if(utenteDisconnesso != NULL && utenteDisconnesso->online){
		utenteDisconnesso->other = 0;
		utenteDisconnesso->online = 0;
		printf("INFO - %s è offline\n", utenteDisconnesso->nome);
	}

	//chiusura socket
	if(close(sock) == -1){
		printf("WRN - Errore nella chiusura del socket %d\n", sock);
		perror("");
	}
	else printf("INFO - Connessione sul socket %d terminata\n", sock);
	
	//rimozione utente
	if(quit == 0){
		rimuoviUtente(utenteDisconnesso);
		printf("INFO - Rimuovo l'utente\n");
	}
	
	//aggiornamento strutture dati
	FD_CLR(sock, &ser.fdSet);
	if(sock == ser.fdMax) ser.fdMax = getMaxFd(ser.fdSet, sock);
	quit = 0;
}

void sendRegResponse(struct richiesta ric, int sock){
	//invia una risposta a una richiesta di registrazione
	
	struct risposta ris;
	int nbytes;
	unsigned char session_key[SYM_KEY_SIZE];
	struct user* u;
	
	//stampo un messaggio per indicare l'inizio di un'elaborazione
	printf("INFO - Elaborazione della risposta ad una richiesta di registrazione sul socket %d\n", sock);
	
	//controllo che un utente malevolo non abbia inviato una stringa senza carattere nullo finale
	if(checkNullCharacterExists(ric.nome, NAME_LEN) == -1){
		// condizione di errore
		printf("WRN - Richiesta errata sul socket %d; la connessione col socket verrà interrotta\n", sock);
		manageWrongRequest(sock);
		return;
	}
	
	printf("\n");
	RSAE(sock, session_key); printf("\n");
	/*printf("Session key [SERVER]:\n");
	print_bytes(session_key, SYM_KEY_SIZE);
	printf("\n");*/
	
	ris.tipo = registration_res;
	if(cercaUtentePerNome(ric.nome) == 0){
		//assegnamento nome, porta e stato
		if((u = malloc(sizeof(struct user))) == 0){
			//se l'allocazione fallisce stampo un warning e vado avanti
			perror("WRN - Errore nell'allocazione della memoria dinamica");
		}
		userInit(u);
		u->sockDes = sock;
		strcpy(u->nome, ric.nome);
		printf("INFO - %s si è registrato\n", u->nome);
		u->portaUDP = ntohs(ric.porta);
		memcpy(u->session_key, session_key, SYM_KEY_SIZE);
		
		// set to 0 session_key
		//memset(session_key, '0', SYM_KEY_SIZE);
	
		printf("INFO - %s ha porta %d\n", u->nome, u->portaUDP);
		aggiungiUtente(u);
		ris.esito = 0;
	}
	else ris.esito = -1; //nome già preso
	//invio risposta
	if((nbytes = send(sock, (void*)&ris, sizeof(ris), 0)) < sizeof(ris)){
		if(nbytes < 0) perror("WRN - Errore nell'invio di un messaggio");
		else printf("WRN - Invio di un messaggio non completato correttamente\n");
	}
	
	//paaass
	//stampo un messaggio per indicare la fine dell'elaborazione
	printf("INFO - Elaborazione terminata\n");
}

void sendWhoResponse(int sock){
	//invia i nomi e gli stati degli utenti connessi
	
	struct risposta ris;
	int nbytes;
	struct user* u = ser.listaUtenti;
	
	//stampo un messaggio per indicare l'inizio di un'elaborazione
	printf("INFO - Elaborazione della risposta ad una richiesta di tipo \"who\" sul socket %d\n", sock);
	
	ris.tipo = who_res;
	ris.esito = 1; //viene annullato quando si arriva all'ultimo utente della lista
	
	
	while(u != 0){

		//preparazione oggetto risposta
		strcpy(ris.nome, u->nome);
		ris.online = u->online;
	
		//aggiorno il puntatore in modo che punti al prossimo utente registrato della lista
		u = u->next;
		
		//utenti finiti: annullamento esito
		if(u == 0) ris.esito = 0;
		
		//invio risposta
		if((nbytes = send(sock, (void*)&ris, sizeof(ris), 0)) < sizeof(ris)){
			if(nbytes < 0) perror("WRN - Errore nell'invio di un messaggio");
			else printf("WRN - Invio di un messaggio non completato correttamente\n");
			return;
		}
	}
	
	//stampo un messaggio per indicare la fine dell'elaborazione
	printf("INFO - Elaborazione terminata\n");
}
int getPassword(struct richiesta ric, int sock){

	struct user* u;
	u = cercaUtentePerSocket(sock);

	const EVP_CIPHER* cipher = EVP_aes_256_cbc(); // cipher to be used
	EVP_CIPHER_CTX *ctx; // decryption context

	unsigned char* clear_buf;          // buffer for the plain text
	int cphr_size = ENCRYPTED_PASSWORD_LEN;      // size of buffer for the received encrypted text
	int clear_size;          // size of the plaintext

	int ret;
	/* Receiving the ciphertext */
	printf("\nPassword cifrata ricevuta:\n");
	print_bytes(ric.encrypted_password, cphr_size);
	printf("\n\n");

	/* Creating the decryption context */
	ctx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(ctx);
	ret = EVP_DecryptInit(ctx, cipher, u->session_key, NULL);
	if(ret == 0) {
	  printf("\nError: EVP_DecryptInit returned %d\n", ret);
	  return 1;
	}
	
	/* Allocating the buffer for the plaintext */
	clear_buf = malloc(ENCRYPTED_PASSWORD_LEN);
	if(clear_buf == NULL) {
	  printf("\nError allocating the buffer for the plaintext\n");
	  return 1;
	}
	
	ret = decrypt(ctx, ric.encrypted_password, ENCRYPTED_PASSWORD_LEN, clear_buf, &clear_size);
	if(ret != 0)
	  return 1;
	  
	EVP_CIPHER_CTX_cleanup(ctx);
	free(ctx);
	
	//memcpy(u->password, clear_buf, PASS_LEN);
	printf("INFO - L'utente %s ha scelto la password %s\n", u->nome, clear_buf);
	u->online = 1;
	
	digest(u, clear_buf, PASS_LEN);
	
	free(clear_buf);

	printf("\nINFO - Registrazione completata\n");
	
	return 0;

}
int passcmp(struct user* u, unsigned char* cphr_buf, unsigned char* key){

	unsigned char* pass = u->password;
	unsigned char* salt = u->salt;

	const EVP_CIPHER* cipher = EVP_aes_256_cbc(); // cipher to be used
	EVP_CIPHER_CTX *ctx; // decryption context

	unsigned char* clear_buf;          // buffer for the plain text
	int cphr_size = ENCRYPTED_PASSWORD_LEN;      // size of buffer for the received encrypted text
	int clear_size;          // size of the plaintext
	
	unsigned char to_cmp[HASH_SIZE];
	
	int ret, i;
	/* Receiving the ciphertext */
	
	printf("Password cifrata ricevuta:\n");
	print_bytes(cphr_buf, cphr_size);
	printf("\n\n");
	
	/* Creating the decryption context */
	ctx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(ctx);
	ret = EVP_DecryptInit(ctx, cipher, key, NULL);
	if(ret == 0) {
	  printf("\nError: EVP_DecryptInit returned %d\n", ret);
	  return 1;
	}
	
	/* Allocating the buffer for the plaintext */
	clear_buf = malloc(ENCRYPTED_PASSWORD_LEN);
	if(clear_buf == NULL) {
	  printf("\nError allocating the buffer for the plaintext\n");
	  return 1;
	}
	
	ret = decrypt(ctx, cphr_buf, ENCRYPTED_PASSWORD_LEN, clear_buf, &clear_size);
	if(ret != 0)
	  return 1;
	  
	EVP_CIPHER_CTX_cleanup(ctx);
	free(ctx);

	printf("\nRecovered password: %s\n", clear_buf);
	printf("\n");

	for(i = 0; i < PASS_LEN; i++){
		clear_buf[i] += salt[i];
	}

	memcpy(to_cmp, myhash(clear_buf, PASS_LEN), HASH_SIZE);
	printf("\n");

	for(i = 0; i< HASH_SIZE; i++){
		if(to_cmp[i] != pass[i]){
			printf("WRN - Password sbagliata\n");
			return 1;
		}
	}
	
	free(clear_buf);
	
	return 0;

}

void manageCheckRequest(struct richiesta ric, int sock){
	struct risposta ris;
	struct user* u;
	int nbytes;

	if(checkNullCharacterExists(ric.nome, NAME_LEN) == -1){
		// condizione di errore
		printf("WRN - Richiesta errata sul socket %d; la connessione col socket verrà interrotta\n", sock);
		manageWrongRequest(sock);
		return;
	}
	u = cercaUtentePerNome(ric.nome);
	
	//controllo se l'utente contattato esiste
	if(u == 0){
		//l'utente contattato non esiste
		printf("INFO - L'utente contattato non esiste: send annullata\n");
		ris.codice = utente_inesistente;
		ines = 1;
	}else{
		if( u->online == 0){
			ris.codice = utente_offline;
		}
		else
			ris.codice = utente_ok;
	}
	
	ris.tipo = check_res;
	//invio la risposta
	if((nbytes = send(sock, (void*)&ris, sizeof(ris), 0)) < sizeof(ris)){
		if(nbytes < 0) perror("WRN - Errore nell'invio di un messaggio");
		else printf("WRN - Invio di un messaggio non completato correttamente\n");
		return;
	}

}

void manageLogin(struct richiesta ric, int sock){
	struct risposta ris;
	struct user* u;
	int nbytes;
	unsigned char session_key[SYM_KEY_SIZE];
	unsigned char enc_password[ENCRYPTED_PASSWORD_LEN];
	
	u = cercaUtentePerNome(ric.nome);
	
	//controllo se l'utente contattato esiste
	if(u == 0){
		//l'utente contattato non esiste
		printf("INFO - L'utente selezionato non esiste: login annullata\n");
		ris.codice = utente_inesistente;
		ines = 1;
	} else {
	
		if(u->online){
			printf("INFO - L'utente selezionato non è già online: login annullata\n");
			ris.codice = utente_online;
		} else ris.codice = utente_ok;
	
	}
	ris.tipo = check_res;
	//invio la risposta
	if((nbytes = send(sock, (void*)&ris, sizeof(ris), 0)) < sizeof(ris)){
		if(nbytes < 0) perror("WRN - Errore nell'invio di un messaggio");
		else printf("WRN - Invio di un messaggio non completato correttamente\n");
		return;
	}
	if(ris.codice == utente_ok){	// aspetto password

		// scambio chiavi

		printf("\n");
		RSAE(sock, session_key); printf("\n");
		/*printf("Session key [SERVER]:\n");
		print_bytes(session_key, SYM_KEY_SIZE);
		printf("\n");*/
		//memcpy(u->session_key, session_key, SYM_KEY_SIZE);

		if((nbytes = recv(sock, &enc_password, ENCRYPTED_PASSWORD_LEN, 0)) < ENCRYPTED_PASSWORD_LEN){
		
			//in caso di errore (nbytes < 0) stampo un warning
			if(nbytes < 0){
				printf("WRN - Errore nella ricezione di dati dal socket %d", sock);
				perror("");
			}
		
			//in caso di formato di richiesta non valido (nbytes < sizeof(ric) ma > 0) stampo un warning
			if(nbytes > 0) printf("WRN - Errore nel formato della richiesta ricevuta dal socket %d\n", sock);
		
			//gestione dell'errore o della disconnessione
			printf("ERR - Errore nella ricezione della lunghezza della password\n");
			manageWrongRequest(sock);
			
		} else {
		
			ris.codice = utente_ok;
			
			/*printf("PASSWORD UTENTE:\n");
			print_bytes(u->password, HASH_SIZE);
			printf("\n");*/
			
			if(!passcmp(u, enc_password, session_key)){
				//printf("INFO - Password Corretta!\n");
				ris.tipo = correct_password;
				
				u->sockDes = sock;
				inet_ntop(AF_INET, &u->clientAddr.sin_addr.s_addr, u->indirizzo, ADD_LEN);
				u->portaTCP = ntohs(u->clientAddr.sin_port);
				printf("INFO - %s ha effettuato il login\n", u->nome);
				u->portaUDP = ntohs(ric.porta);
				printf("INFO - %s ha porta %d\n", u->nome, u->portaUDP);
				memcpy(u->session_key, session_key, SYM_KEY_SIZE);
				u->online = 1;
			
			}else{

				printf("INFO - Password non corretta!\n");
				ris.tipo = wrong_password;
			
			}
			
			if((nbytes = send(sock, (void*)&ris, sizeof(ris), 0)) < sizeof(ris)){
				if(nbytes < 0) perror("WRN - Errore nell'invio di un messaggio");
				else printf("WRN - Invio di un messaggio non completato correttamente\n");
				return;
			}

			printf("INFO - Elaborazione terminata\n");
			
		}
	
	}
}

void manageSendRequest(struct richiesta ric, int sock){
	struct user* mittente, *destinatario;
	struct risposta ris;
	int nbytes;
	
	//stampo un messaggio per indicare l'inizio di un'elaborazione
	//printf("INFO [01] - Elaborazione della risposta ad una richiesta di tipo \"send\" sul socket %d\n", sock);
	
	//controllo che un utente malevolo non abbia inviato una stringa senza carattere nullo finale
	if(checkNullCharacterExists(ric.nome, NAME_LEN) == -1){
		// condizione di errore
		printf("WRN [01] - Richiesta errata sul socket %d; la connessione col socket verrà interrotta\n", sock);
		manageWrongRequest(sock);
		return;
	}
	mittente = cercaUtentePerSocket(sock);
	if(mittente == 0)
		printf("Struttura MITTENTE è NULL\n");

	if(mittente->online == 0){
		// condizione di errore
		printf("L'utente risulta sloggato!\n");
		printf("WRN [02] - Richiesta errata sul socket %d; la connessione col socket verrà interrotta\n", sock);
		/*manageWrongRequest(sock);
		return;*/
	}
	destinatario = cercaUtentePerNome(ric.nome);

	//printf("INFO [02] - %s contatta %s\n", mittente->nome, ric.nome);
	printf("INFO - %s vuole contattare %s\n", mittente->nome, ric.nome);
	
	//controllo se l'utente contattato esiste
	if(destinatario == 0){
		//l'utente contattato non esiste
		printf("INFO - L'utente contattato non esiste: send annullata\n");
		ris.esito = -1;
		ris.codice = utente_inesistente;
		ines = 1;
	}
	else{
		if(destinatario->online == 0) {
			//l'utente contattato esiste ma è offline
			//nel caso in cui un utente tenta di contattare se stesso gli risulterà che lui stesso è offline
			printf("INFO - L'utente contattato è offline: i messaggi verranno inviati alla sua riconnessione\n");
			ris.esito = -1;
			ris.codice = utente_offline;
		}
		else{
			//l'utente sfidato esiste ed è disponibile: la richiesta di send gli viene inoltrata
			mittente->other = destinatario;
		
			//preparo l'oggetto risposta con le informazioni del destinatario
			ris.tipo = send_req;
			strcpy(ris.nome, mittente->nome);
			strcpy(ris.indirizzo, mittente->indirizzo);
			ris.portaUDP = htons(mittente->portaUDP);	// QUI
			//printf("%d %d\n", mittente->portaUDP, ris.portaUDP);
			//inoltro la richiesta
			if((nbytes = send(destinatario->sockDes, (void*)&ris, sizeof(ris), 0)) < sizeof(ris)){
				if(nbytes < 0) perror("WRN - Errore nell'invio di un messaggio");
				else printf("WRN - Invio di un messaggio non completato correttamente\n");
				printf("INFO - L'utente contattato non è raggiungibile: send annullata\n");
				ris.esito = -1;
				ris.codice = utente_offline;
			}
			else{
				//invio richiesta riuscito.. quando arriverà la risposta questa verrà inoltrata al mittente
				ris.esito = 0;
				//printf("INFO - %s è in attesa di risposta\n", mittente->nome);
				//printf("INFO - Si attende la risposta di %s\n", destinatario->nome);
			}
		}
	}
	if(ris.esito == -1){
		ris.tipo = send_res;
		//invio la risposta
		if(ris.codice == utente_offline) printf("ris codice utente_offline\n");
		if((nbytes = send(sock, (void*)&ris, sizeof(ris), 0)) < sizeof(ris)){
			if(nbytes < 0) perror("WRN - Errore nell'invio di un messaggio");
			else printf("WRN - Invio di un messaggio non completato correttamente\n");
			return;
		}
		mittente->other = 0;
	}
	
	//stampo un messaggio per indicare la fine dell'elaborazione
	//printf("INFO - Elaborazione terminata\n");
}

void manageSendAnswer(struct richiesta ric, int sock){
	//gestisce una risposta a una richiesta di connessione
	
	struct user* mittente, *destinatario;
	struct risposta ris;
	int nbytes;
	
	//stampo un messaggio per indicare l'inizio di un'elaborazione
	//printf("INFO - Elaborazione di una richiesta di invio messaggio sul socket %d\n", sock);
	
	//controllo che un utente malevolo non abbia inviato una stringa senza carattere nullo finale
	if(checkNullCharacterExists(ric.nome, NAME_LEN) == -1){
		// condizione di errore
		printf("WRN - Richiesta errata sul socket %d; la connessione col socket verrà interrotta\n", sock);
		manageWrongRequest(sock);
		return;
	}
	
	destinatario = cercaUtentePerSocket(sock);
	mittente = cercaUtentePerNome(ric.nome);
	
	ris.tipo = send_res;
	
	//controllo che il mittente esista e che abbia effettivamente messaggiato il destinatario
	if(mittente == 0 || (mittente != 0 && mittente->other != destinatario)){
		//il mittente non esiste o non ha contattato, probabilmente ha annullato la richiesta o si è disconnesso dal server
		//gestisco la situazione ignorando semplicemente la richiesta
		
		printf("INFO - La richiesta di accettazione è obsoleta, pertanto verrà ignorata\n");
		
		//stampo un messaggio per indicare la fine dell'elaborazione
		printf("INFO - Elaborazione terminata\n");
		
		return;
	}
	
	//gestione della risposta al mittente
	//accettazione
	//printf("INFO - %s accetta il messaggio di %s\n", destinatario->nome, mittente->nome);
	ris.esito = 0;
	strcpy(ris.indirizzo, destinatario->indirizzo);
	ris.portaUDP = htons(destinatario->portaUDP);
	//printf("%d\n", destinatario->portaUDP);
	destinatario->other = mittente;
	
	//invio la risposta
	if((nbytes = send(mittente->sockDes, (void*)&ris, sizeof(ris), 0)) < sizeof(ris)){
		if(nbytes < 0) perror("WRN - Errore nell'invio di un messaggio");
		else printf("WRN - Invio di un messaggio non completato correttamente\n");
		return;
	}
	
	//stampo un messaggio per indicare la fine dell'elaborazione
	//printf("INFO - Elaborazione terminata\n");
}

void manageQuitRequest(int sock){
	struct user* utenteQuit;
	struct risposta ris;
	int nbytes;

	printf("INFO - Elaborazione di una richiesta di quit sul socket %d\n", sock);

	utenteQuit = cercaUtentePerSocket(sock);

	ris.tipo = quit_res;

	if(utenteQuit != NULL){
		utenteQuit->online = 0;
		utenteQuit->sockDes = 0;
		memset(utenteQuit->session_key, '0' , SYM_KEY_SIZE);
	}

	if((nbytes = send(sock, (void*)&ris, sizeof(ris), 0)) < sizeof(ris)){
		if(nbytes < 0) perror("WRN - Errore nell'invio di un messaggio");
		else printf("WRN - Invio di un messaggio non completato correttamente\n");
	}
	
	//stampo un messaggio per indicare la fine dell'elaborazione
	printf("INFO - Elaborazione terminata\n");
}

void manageDeregisterRequest(int sock){
	//gestisce una risposta a una richiesta di disconnessione
	
	struct user* utenteDeregistrato;
	struct risposta ris;
	int nbytes;
	
	//stampo un messaggio per indicare l'inizio di un'elaborazione
	printf("INFO - Elaborazione di una richiesta di deregistrazione sul socket %d\n", sock);
	
	utenteDeregistrato = cercaUtentePerSocket(sock);
	
	ris.tipo = deregister_res;
			
	//confermo l'accettazione della richiesta all'utente che vuole disconnettersi
	if((nbytes = send(utenteDeregistrato->sockDes, (void*)&ris, sizeof(ris), 0)) < sizeof(ris)){
		if(nbytes < 0) perror("WRN - Errore nell'invio di un messaggio");
		else printf("WRN - Invio di un messaggio non completato correttamente\n");
	}
	printf("INFO - %s ha deciso di eliminare l'account\n", utenteDeregistrato->nome);
	rimuoviUtente(utenteDeregistrato);
	
	//aggiornamento strutture dati
	//FD_CLR(sock, &ser.fdSet);
	//if(sock == ser.fdMax) ser.fdMax = getMaxFd(ser.fdSet, sock);
		

	//stampo un messaggio per indicare la fine dell'elaborazione
	printf("INFO - Elaborazione terminata\n");
}
void manageLogOutRequest(int sock){
	//gestisce una risposta a una richiesta di disconnessione
	
	struct user* u;
	struct risposta ris;
	int nbytes;
	
	//stampo un messaggio per indicare l'inizio di un'elaborazione
	printf("INFO - Elaborazione di una richiesta di Logout sul socket %d\n", sock);
	
	u = cercaUtentePerSocket(sock);
	
	ris.tipo = logout_req;
	
	u->online = 0;
		
	//confermo l'accettazione della richiesta all'utente che vuole effettuare il logout
	if((nbytes = send(u->sockDes, (void*)&ris, sizeof(ris), 0)) < sizeof(ris)){
		if(nbytes < 0) perror("WRN - Errore nell'invio di un messaggio");
		else printf("WRN - Invio di un messaggio non completato correttamente\n");
	}
	printf("INFO - %s ha effettuato il logout\n", u->nome);

	u->sockDes = 0;
	memset(u->session_key, '0' , SYM_KEY_SIZE);
	
	//aggiornamento strutture dati
	//FD_CLR(sock, &ser.fdSet);
	//if(sock == ser.fdMax) ser.fdMax = getMaxFd(ser.fdSet, sock);
		

	//stampo un messaggio per indicare la fine dell'elaborazione
	printf("INFO - Elaborazione terminata\n");
}
int main(int argc, char* argv[]){
	struct user* usr;	
	fd_set readFds;
	int nbytes, size, i;
	struct richiesta ric;
	
	//controllo i dati in ingresso
	if(checkInput(argc, argv) == -1) exit(0);
	
	//inizializzo il server
	if(serverInit(&ser, (port)atoi(argv[1])) == -1) exit(0);
	
	for(;;){
		//esecuzione select
		readFds = ser.fdSet;
		if(select(ser.fdMax + 1, &readFds, NULL, NULL, NULL) == -1){
			perror("ERR - Errore nella ricerca di descrittori pronti alla lettura");
			exit(0);
		}
		
		//controllo dei descrittori per vedere quali socket sono pronti
		for(i = 0; i <= ser.fdMax; i++){
			//controllo il descrittore i
			if(FD_ISSET(i, &readFds)){
				//il socket i è pronto
				
				//controllo se il socket pronto è quello di ascolto
				if(i == ser.listener){
					//se listener è pronto allora un nuovo client tenta di connettersi: creazione della nuova connessione
					printf("INFO - Un nuovo client tenta di connettersi\n");
					
					//allocazione di un nuovo oggetto User
					if((usr = malloc(sizeof(struct user))) == 0){
						//se l'allocazione fallisce stampo un warning e vado avanti
						perror("WRN - Errore nell'allocazione della memoria dinamica");
						continue;
					}
					
					//creazione di un nuovo socket di comunicazione
					size = sizeof(usr->clientAddr);
					if((usr->sockDes = accept(ser.listener, (struct sockaddr*)&usr->clientAddr, (socklen_t*)&size)) == -1){
						//se l'accettazione della nuova connessione fallisce stampo un warning e vado avanti
						perror("WRN - Errore nella creazione del socket di comunicazione");
						continue;
					}
					
					//aggiornamento strutture dati
					userInit(usr);
					//aggiungiUtente(usr);
					FD_SET(usr->sockDes, &ser.fdSet);
					if(usr->sockDes > ser.fdMax) ser.fdMax = usr->sockDes;
					
					printf("INFO - Connessione stabilita con il client di indirizzo %s (porta %d) sul socket %d\n", usr->indirizzo, usr->portaTCP, usr->sockDes);
				}
				else{
					//nuovi dati da un client: gestione richiesta
					
					//prelevo i dati
					if((nbytes = recv(i, &ric, sizeof(ric), 0)) < sizeof(ric)){
						//se sono stati inviati 0 bytes: client disconnesso
						//altrimenti: errore di ricezione
						//chiudo il socket che ha causato l'errore o che si è disconnesso, rimuovo l'utente associato e vado avanti
						
						//in caso di errore (nbytes < 0) stampo un warning
						if(nbytes < 0){
							printf("WRN - Errore nella ricezione di dati dal socket %d", i);
							perror("");
						}
						
						//in caso di formato di richiesta non valido (nbytes < sizeof(ric) ma > 0) stampo un warning
						if(nbytes > 0) printf("WRN - Errore nel formato della richiesta ricevuta dal socket %d\n", i);
						
						//gestione dell'errore o della disconnessione
						manageWrongRequest(i);
					}
					else{
						//messaggio ricevuto correttamente: gestione richiesta
						
						switch(ric.tipo){
							case registration_req:
								sendRegResponse(ric, i);
								break;
							
							case who_req:
								sendWhoResponse(i);
								break;

							case accept_req:
								manageSendAnswer(ric, i);
								break;

							case send_req:
								manageSendRequest(ric, i);
								break;
							
							case deregister_req:
								manageDeregisterRequest(i);
								break;
							case quit_req:
								quit = 1;
								manageQuitRequest(i);
								break;
							case check_req:
								manageCheckRequest(ric, i);
								break;
							case pass_req:
								if(getPassword(ric, i) != 0){
									printf("ERR - Error in receiving encrypted password\nProgram will be terminated\n");
									manageWrongRequest(i);
								}
								break;
							case log_req:
								manageLogin(ric, i);
								break;
							case logout_req:
								manageLogOutRequest(i);
								break;
							case key_exchange_req:
								NS(i);
								break;
							default: ;
								printf("WRN - Richiesta non valida dal socket %d; il socket verrà chiuso\n", i);
								manageWrongRequest(i);
						}
					}
				}
			}
		}
	}
}
