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

#include "./clientd/global_struct.h"
#include "./clientd/cripto.h"
#include "./clientd/NS_c.h"
#include "./clientd/eRSA_c.h"
#include "./clientd/simKey.h"

char messaggio[150];
char tbuf[NAME_LEN];
unsigned char tpass[PASS_LEN];
int continua = 0;
int numeroMessaggi;
int binded = 0;
port porta;
struct user usr;
struct server ser;
struct other oth;
struct msg_struct message;

int userInit(struct user* u, port porta){
	//inizializza un oggetto User
	
	if((u->socket = socket(AF_INET, SOCK_DGRAM, 0)) == -1 ){
		perror("ERR - Creazione socket UDP non riuscita");
		return -1;
	}
	
	u->fdMax = u->socket;
	
	u->clientAddr.sin_family = AF_INET;
	u->clientAddr.sin_addr.s_addr = INADDR_ANY;
	u->clientAddr.sin_port = htons(porta);
	inet_ntop(AF_INET, &u->clientAddr.sin_addr.s_addr, u->indirizzo, ADD_LEN);
	u->portaUDP = porta;
	u->online = 0;
	u->quit = 0;
	u->printShell = 1;
	
	return 0;
}
int serverInit(struct server * s, char* indirizzo, port porta){
	//inizializza l'oggetto Server
	
	//creazione socket
	if((s->socket = socket(AF_INET, SOCK_STREAM, 0)) == -1 ){
		perror("ERR - Creazione socket TCP non riuscita");
		return -1;
	}
	
	//assegnamento indirizzo
	strcpy(s->indirizzo, indirizzo);
	s->porta = porta;
	memset(&s->serverAddr, 0, sizeof(s->serverAddr));
	s->serverAddr.sin_family = AF_INET;
	s->serverAddr.sin_port = htons(s->porta);
	inet_pton(AF_INET, s->indirizzo, &s->serverAddr.sin_addr.s_addr); //abbiamo già testato nella checkInput che non da errore
	
	return 0;
}

int sendRegRequest(){
	//invia una richiesta di registrazione
	
	struct richiesta ric;
	struct risposta ris;
	int nbytes;
	
	//inizializzazione oggetto Richiesta
	ric.tipo = registration_req;
	strcpy(ric.nome, usr.nome);
	ric.porta = htons(usr.portaUDP);
	
	//invio richiesta
	if((nbytes = send(ser.socket, (void*)&ric, sizeof(ric), 0)) < sizeof(ric)){
		if(nbytes < 0) perror("ERR - Invio dati fallito");
		else printf("ERR - Invio dati non completato correttamente\n");
		exit(0);
	}
	
	RSAE(ser.socket, ser.session_key);
	/*printf("Session key [CLIENT]:\n");
	print_bytes(ser.session_key, SYM_KEY_SIZE);
	printf("\n");*/
	
	//ricezione risposta
	do{
		if((nbytes = recv(ser.socket, (void*)&ris, sizeof(ris), 0)) < sizeof(ris)){
			if(nbytes < 0) perror("ERR - Ricezione dati fallita");
			else printf("ERR - Comunicazione col server interrotta\n");
			exit(0);
		}
			else if(ris.tipo == messaggio_res){
				printf("%s (msg Offline) >\n%s\n", ris.nome, ris.messaggio);
			}
	} while(ris.tipo != registration_res);
	return ris.esito;
}

int checkInput(int argc, char* argv[]){
	//controlla la correttezza dei dati in ingresso
	
	int ret = 0;
	int porta;
	int indirizzo;
	int i;
	
	//formato degli argomenti non corretto
	if(argc != 4) ret = -1;
	else{
		//formato della porta non corretto
		for(i = 0; i < strlen(argv[1]); i++){
			if(argv[1][i] < '0' || argv[1][i] > '9'){
				ret = -1;
				break;
			}
		}
		
		if(ret == 0){
			porta = atoi(argv[1]);
			//valore della porta non valido
			if(porta < 0 || porta > MAX_PORT) ret = -1;
		}
		
		for(i = 0; i < strlen(argv[3]); i++){
			if(argv[3][i] < '0' || argv[3][i] > '9'){
				ret = -1;
				break;
			}
		}
		
		if(ret == 0){
			porta = atoi(argv[3]);
			//valore della porta non valido
			if(porta < 0 || porta > MAX_PORT) ret = -1;
		}

		//formato dell'indirizzo non corretto
		if(inet_pton(AF_INET, argv[2], &indirizzo) == -1) ret = -1;
	}
	
	if(ret == -1) printf("ERR - Errore nei dati di ingresso\nIl formato corretto è il seguente: <Porta Host> <IP Host> <Porta Server>\n");
	
	return ret;
}

int flushInputStream(){
	//esegue il flush del buffer di ingresso e restituisce -1 se questo non era vuoto
	//se viene chiamata dopo un'operazione di input e restituisce -1 vuol dire che c'è un errore	
	
	int ret = 0;
	char c;
	
	do{
		scanf("%c", &c);
		if(c != '\n' && c != ' ') ret = -1;
	} while(c != '\n');
	
	ungetc(c, stdin);
		
	return ret;
}

int checkArgumentExists(){
	//preleva il prossimo carattere dall'input stream e verifica che non sia un new line
	//ripete il prelievo se trova spazi
	
	char c;
	
	do{
		scanf("%c", &c);
		if(c == '\n') return -1;
	} while(c == ' ');
	
	ungetc(c, stdin);
	
	return 0;
}

//registrazione utente
int getOtherName(){
	//esegue l'input del nome dell'avversario con cui si desidera messaggiare
	
	char formatStr[FORMAT_STR_LEN];
	int ret;
	
	sprintf(formatStr, "%%%ds", NAME_LEN - 1);
	scanf(formatStr, oth.nome);
	
	ret = 1; //flushInputStream();
	
	return ret;
}

int getUserName(int set){
	//esegue l'input del nome utente
	char formatStr[FORMAT_STR_LEN];
	int ret;
	
	sprintf(formatStr, "%%%ds", NAME_LEN - 1);
	if(set == 1) scanf(formatStr, usr.nome);
	else scanf(formatStr, tbuf);
	ret = flushInputStream();
	if(set && ret == -1){
		strcpy(usr.nome,"");
	}
	
	return ret;
}

int getPassword(int set){
	//esegue l'input del nome utente
	
	char formatStr[PASS_LEN];
	int ret;
	
	sprintf(formatStr, "%%%ds", PASS_LEN - 1);
	if(!set) scanf(formatStr, tpass);
	
	fflush(stdout);
	memset(formatStr, 0, PASS_LEN);
	ret = flushInputStream();
	
	return ret;
}
int getUserPort(){
	//esegue l'input della porta di comunicazione UDP
	
	int value, ret = 0;
	
	if(scanf("%d", &value) == 0) ret = -1;
	if(flushInputStream() == -1) ret = -1;
	
	if(ret == 0){
		if(value < 0 || value > MAX_PORT) return -1;
	
		usr.portaUDP = (port)value;
		usr.clientAddr.sin_port = htons(usr.portaUDP);
	}
	
	return ret;
}
int sendPassword(){
	struct richiesta ric;
	int nbytes;

	const EVP_CIPHER* cipher = EVP_aes_256_cbc();
	EVP_CIPHER_CTX* ctx;    // encryption context

	unsigned char* clear_buf;      // buffer to contain the file + the digest
	unsigned char* cphr_buf;   // buffer to contain the ciphertext
	int cphr_size;   // size of the ciphertext
	int block_size;

	int size = PASS_LEN;	

	int ret;
	clear_buf = (unsigned char*)tpass;
	
	/* Creating the encryption context */
	ctx = malloc(sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(ctx);
	ret = EVP_EncryptInit(ctx, cipher, ser.session_key, NULL);
	if(ret == 0) {
	  printf("\nError: EVP_EncryptInit returned %d\n", ret);
	  return 1;
	}

	/* Allocating the buffer for the ciphertext */
	block_size = EVP_CIPHER_block_size(cipher);
	cphr_size = size + block_size;

	//printf("CIPHER SIZE: %d\n", cphr_size);
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

	printf("\nPassword cifrata [%d byte]:\n", cphr_size);
	print_bytes(cphr_buf, cphr_size);
	printf("\n");
	//inizializzazione oggetto Richiesta
	memcpy(ric.encrypted_password, cphr_buf, cphr_size);
	ric.porta = htons(usr.portaUDP);
	ric.tipo = pass_req;
	memset(tpass, 0, PASS_LEN);
	
	//invio richiesta
	if((nbytes = send(ser.socket, (void*)&ric, sizeof(ric), 0)) < sizeof(ric)){
		if(nbytes < 0) perror("ERR - Invio dati fallito");
		else printf("ERR - Comunicazione col server interrotta\n");
		exit(0);
	}

	free(cphr_buf);

	return 0;
	
}

void registraUtente(){
	
	//printf("Inserisci la porta UDP di ascolto: ");
	//while(getUserPort() == -1) printf("Il dato inserito non è un numero di porta valido\n Inserisci un numero corretto: ");
	//associo la porta al socket udp dell'utente
	
	//i dati sono stati prelevati, li invio al server
	while(sendRegRequest() == -1){
		printf("Registrazione non riuscita: nome utente già esistente\n");
		
		//input nome
		printf("Inserisci un altro nome: ");
		while(getUserName(1) == -1) printf("Il nome può contenere al più %d caratteri e non può contenere spazi\nInserisci nuovamente il tuo nome: ", NAME_LEN - 1);
	}
	
	printf("Inserisci password: ");
	while(getPassword(0) == -1){
		printf("La password può contenere al più %d caratteri e non può contenere spazi\nInserisci nuovamente la tua password: ", PASS_LEN - 1);
	}
	
	if(sendPassword() != 0)
		printf("ERR - Error in sending encrypted password\n");
	usr.online = 1;
	printf("\nRegistrazione avvenuta con successo\n");
}

void printHelp(){	/* MODIFICATO */
	printf("Sono disonibili i seguenti comandi: \n");
	printf("!help --> mostra l'elenco dei comandi disponibili\n");
	if(usr.online == 0)
		printf("!register <username> --> registra il client presso il server\n");
	if(usr.online == 1){
		printf("!logout --> scollega il client dal server\n");
		printf("!deregister --> cancella il client dal server\n");
	}
	if(usr.online == 0)
		printf("!login <username> --> esegue il login dell'utente <username>\n");
	if(usr.online == 1){
		printf("!who --> mostra l'elenco degli utenti disponibili\n");
		printf("!send <username> --> invia un messaggio ad un altro utente\n");
	}
	printf("!quit --> disconnette il client dal server e chiude l'applicazione\n\n");
}

void execWho(){
	//esegue il comando who
	
	struct richiesta ric;
	struct risposta ris;
	int nbytes;
	
	//inizializzazione oggetto Richiesta
	ric.tipo = who_req;
	
	//invio richiesta
	if((nbytes = send(ser.socket, (void*)&ric, sizeof(ric), 0)) < sizeof(ric)){
		if(nbytes < 0) perror("ERR - Invio dati fallito");
		else printf("ERR - Comunicazione col server interrotta\n");
		exit(0);
	}
	
	printf("Client connessi al server:\n");
	
	//ricezione risposta
	do{
		if((nbytes = recv(ser.socket, (void*)&ris, sizeof(ris), 0)) < sizeof(ris)){
			if(nbytes < 0) perror("ERR - Ricezione dati fallita");
			else printf("ERR - Comunicazione col server interrotta\n");
			exit(0);
		}
		printf("%s %s\n", ris.nome, ris.online == 1? "(online)": "(offline)");
		
	} while((ris.tipo != who_res) || (ris.tipo == who_res && ris.esito == 1)); //esito = 1 significa che ci sono ancora dati	
}
void execLogOut(){
	//esegue il comando who
	
	struct richiesta ric;
	struct risposta ris;
	int nbytes;
	
	//inizializzazione oggetto Richiesta
	ric.tipo = logout_req;
	
	//invio richiesta
	if((nbytes = send(ser.socket, (void*)&ric, sizeof(ric), 0)) < sizeof(ric)){
		if(nbytes < 0) perror("ERR - Invio dati fallito");
		else printf("ERR - Comunicazione col server interrotta\n");
		exit(0);
	}
	
	if((nbytes = recv(ser.socket, (void*)&ris, sizeof(ris), 0)) < sizeof(ris)){
		if(nbytes < 0) perror("ERR - Ricezione dati fallita");
		else printf("ERR - Comunicazione col server interrotta\n");
		exit(0);
	}
	printf("INFO - Utente disconnesso con successo\n");
	usr.online = 0;
	strcpy(usr.nome, "");
	memset(ser.session_key, '0' , SYM_KEY_SIZE);
	FD_CLR(usr.socket, &usr.fdSet);
	
}
void execSend(){
	// esegue il comando !connect
	
	struct richiesta ric;
	int nbytes;
	
	//inizializzazione oggetto Richiesta
	ric.tipo = send_req;
	strcpy(ric.nome, oth.nome);
	//invio richiesta
	if((nbytes = send(ser.socket, (void*)&ric, sizeof(ric), 0)) < sizeof(ric)){
		if(nbytes < 0) perror("ERR - Invio dati fallito");
		else printf("ERR - Comunicazione col server interrotta\n");
		exit(0);
	}
	
	
}

void initUdpReceiver(){
	//mostra all'utente una richiesta di send e ne invia la risposta al server
	
	struct risposta ris;
	struct richiesta ric;
	int nbytes;
	
	//flushInputStream();
	
	//ricezione dati dal server richiesta
	if((nbytes = recv(ser.socket, (void*)&ris, sizeof(ris), 0)) < sizeof(ris)){
		if(nbytes < 0) perror("\nERR - Ricezione dati fallita");
		else printf("\nERR - Comunicazione col server interrotta\n");
		exit(0);
	}
	
	//se non ho ricevuto una richiesta di send ignoro la richiesta
	if(ris.tipo != send_res){
		//ignoro risposte che non attendo
		//non ristampo il carattere di shell per rendere la ricezione del messaggio inatteso trasparente all'utente
		usr.printShell = 0;
		return;
	}
	
	//copio i dati nella struttura che raccoglie le informazioni sull'avversario
	strcpy(oth.nome, ris.nome);
	strcpy(oth.indirizzo, ris.indirizzo);
	oth.portaUDP = ntohs(ris.portaUDP);
	memset(&oth.clientAddr, 0, sizeof(oth.clientAddr));
	oth.clientAddr.sin_port = ris.portaUDP;
	oth.clientAddr.sin_family = AF_INET;
	if(inet_pton(AF_INET, oth.indirizzo, &oth.clientAddr.sin_addr.s_addr) == -1){
		perror("ERR - Errore nei dati ricevuti\n");
		exit(0);
	}

	ric.tipo = accept_req;
	strcpy(ric.nome, oth.nome);
		
	//invio richiesta
	if((nbytes = send(ser.socket, (void*)&ric, sizeof(ric), 0)) < sizeof(ric)){
		if(nbytes < 0) perror("ERR - Invio dati fallito");
		else printf("ERR - Comunicazione col server interrotta\n");
		exit(0);
	}
	FD_SET(usr.socket, &usr.fdSet);
}

void initUdpSender(){
	//elabora la risposta ad una richiesta di send precedentemente inviata
	
	struct risposta ris;
	int nbytes;
	
	//flushInputStream();
	//ricezione risposta
	if((nbytes = recv(ser.socket, (void*)&ris, sizeof(ris), 0)) < sizeof(ris)){
		if(nbytes < 0) perror("\nERR - Ricezione dati fallita");
		else printf("\nERR - Comunicazione col server interrotta\n");
		exit(0);
	}
	//verifico di aver ricevuto la risposta che attendevo, altrimenti ignoro
	if(ris.tipo != send_res){
		//ignoro risposte che non attendo
		//non ristampo il carattere di shell per rendere la ricezione del messaggio inatteso trasparente all'utente
		usr.printShell = 0;
		return;
	}

	//elaborazione risposta
	if(ris.esito == -1){
		switch(ris.codice){
			case utente_inesistente:
				printf("Nome Utente inesistente\n");
				break;
			case utente_offline:
				printf("L'utente %s è offline, il messaggio verrà inviato alla sua riconnessione\n", oth.nome);
				continua = 0;
				break;
			default:
				printf("ERR - Errore nei dati ricevuti\n");
				exit(0);
		}
	}
	else{
		//esito positivo
		continua = 1;
		//copio i dati nella struttura che raccoglie le informazioni sul destinatario
		strcpy(oth.indirizzo, ris.indirizzo);
		oth.portaUDP = ntohs(ris.portaUDP);
		memset(&oth.clientAddr, 0, sizeof(oth.clientAddr));
		oth.clientAddr.sin_port = ris.portaUDP;
		oth.clientAddr.sin_family = AF_INET;
		if(inet_pton(AF_INET, oth.indirizzo, &oth.clientAddr.sin_addr.s_addr) == -1){
			perror("ERR - Errore nei dati ricevuti\n");
			exit(0);
		}
	}
}
int controlloEsistenza(){
	struct richiesta ric;
	struct risposta ris;
	int nbytes, ret;
	
	//inizializzazione oggetto Richiesta
	ric.tipo = check_req;
	strcpy(ric.nome, oth.nome);
	//invio richiesta
	if((nbytes = send(ser.socket, (void*)&ric, sizeof(ric), 0)) < sizeof(ric)){
		if(nbytes < 0) perror("ERR - Invio dati fallito");
		else printf("ERR - Comunicazione col server interrotta\n");
		exit(0);
	}

	if((nbytes = recv(ser.socket, (void*)&ris, sizeof(ris), 0)) < sizeof(ris)){
		if(nbytes < 0) perror("\nERR - Ricezione dati fallita");
		else printf("\nERR - Comunicazione col server interrotta\n");
		exit(0);
	} 
	if(ris.codice == utente_inesistente){
		ret = -1;
		printf("L'utente selezionato non esiste\n");
	}
	else{
		if(ris.codice == utente_offline){
			ret = -2;
			printf("L'utente selezionato è offline\n");
		}
		else{
			if(ris.codice == utente_ok)
				ret = 1;
			else
				printf("ERR - Stato non previsto\n");
			
		}
	}
	return ret;

} 

void execQuit(){
	struct richiesta ric;
	struct risposta ris;
	int nbytes;

	ric.tipo = quit_req;

	if((nbytes = send(ser.socket, (void*)&ric, sizeof(ric), 0)) < sizeof(ric)){
		if(nbytes < 0) perror("ERR - Invio dati fallito");
		else printf("ERR - Comunicazione col server interrotta\n");
		exit(0);
	}

	//ricezione risposta
	do{
		if((nbytes = recv(ser.socket, (void*)&ris, sizeof(ris), 0)) < sizeof(ris)){
			if(nbytes < 0) perror("ERR - Ricezione dati fallita");
			else printf("ERR - Comunicazione col server interrotta\n");
			exit(0);
		}
	} while(ris.tipo != quit_res); 

	memset(ser.session_key, '0' , SYM_KEY_SIZE);

}
void execDeregister(){
	struct richiesta ric;
	struct risposta ris;
	int nbytes;
	
	//inizializzazione oggetto Richiesta
	ric.tipo = deregister_req;
	strcpy(ric.nome, usr.nome);
	//invio richiesta
	if((nbytes = send(ser.socket, (void*)&ric, sizeof(ric), 0)) < sizeof(ric)){
		if(nbytes < 0) perror("ERR - Invio dati fallito");
		else printf("ERR - Comunicazione col server interrotta\n");
		exit(0);
	}

	//ricezione risposta
	do{
		if((nbytes = recv(ser.socket, (void*)&ris, sizeof(ris), 0)) < sizeof(ris)){
			if(nbytes < 0) perror("ERR - Ricezione dati fallita");
			else printf("ERR - Comunicazione col server interrotta\n");
			exit(0);
		}
	} while(ris.tipo != deregister_res);

	printf("INFO - Account eliminato\n");

	usr.online = 0;
	strcpy(usr.nome, "");
	memset(ser.session_key, '0' , SYM_KEY_SIZE);
	FD_CLR(usr.socket, &usr.fdSet);
}

void getMessage(){
	char buffer[150], c;
	int b = 0, m = 0;
	memset(messaggio, '\0', 150);
	memset(buffer, '\0', 150);
	while (( c = getchar()) != EOF && c != '\n');
	printf("Inserisci il tuo messaggio (MAX 150 caratteri):\n");	
	while(1){	// Prende in ingresso il testo e il punto.
		fgets(buffer, 150, stdin);
		//printf("strlen buf: %d\n",strlen(buffer));
		b += strlen(buffer);
		if(strcmp(buffer, ".\n") == 0) 
			break;
		m += b;
		if(m <= 150){
			strcat(messaggio, buffer);
			//printf("strlen mex: %d\n",strlen(messaggio));
			memset(buffer, '\0', 150);
			b = 0;
		}else{
			printf("\nIl messaggio è più lungo di 150 caratteri. Riscrivilo dall'inizio.\n");
			memset(messaggio, '\0', 150);
			m = 0; b = 0;
		}
	}
}

void sendMessage(){

	ns_send();
	sk_send();

	FD_SET(usr.socket, &usr.fdSet);

}

void recvMessage(){

	ns_rcv();
	sk_rcv();
	
	FD_CLR(usr.socket, &usr.fdSet);
}

unsigned char* encryptPassword(unsigned char* clear_buf){ 
	
	const EVP_CIPHER* cipher = EVP_aes_256_cbc();
	EVP_CIPHER_CTX* ctx;    // encryption context

	unsigned char* cphr_buf;   // buffer to contain the ciphertext
	int cphr_size;   // size of the ciphertext
	int block_size;
	int size = PASS_LEN;	
	int ret;
	
	/* Creating the encryption context */
	ctx = malloc(sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(ctx);
	ret = EVP_EncryptInit(ctx, cipher, ser.session_key, NULL);
	if(ret == 0) {
	  printf("\nError: EVP_EncryptInit returned %d\n", ret);
	  exit(0);
	}

	/* Allocating the buffer for the ciphertext */
	block_size = EVP_CIPHER_block_size(cipher);
	cphr_size = size + block_size;

	//printf("CIPHER SIZE: %d\n", cphr_size);
	cphr_buf = malloc(cphr_size);
	//static unsigned char cphr_buf[cphr_size];
	
	if(cphr_buf == NULL) {
	  printf("\nError allocating the ciphertext buffer\n");
	  exit(0);
	}

	ret = encrypt(ctx, clear_buf, size, cphr_buf, &cphr_size);
	if(ret != 0)
		exit(0);
	
	EVP_CIPHER_CTX_cleanup(ctx);
	free(ctx);

	printf("\nPassword cifrata [%d byte]:\n", cphr_size);
	print_bytes(cphr_buf, cphr_size);
	printf("\n\n");
	
	//memset(tpass, 0, PASS_LEN);
	
	return cphr_buf;

}

void execLogin(){

	struct richiesta ric;
	struct risposta ris;
	int nbytes;
	unsigned char tmp_encrypted_pass[ENCRYPTED_PASSWORD_LEN];
	
	//inizializzazione oggetto Richiesta
	ric.tipo = log_req;
	ric.porta = htons(usr.portaUDP);
	strcpy(ric.nome, tbuf);
	//invio richiesta
	if((nbytes = send(ser.socket, (void*)&ric, sizeof(ric), 0)) < sizeof(ric)){
		if(nbytes < 0) perror("ERR - Invio dati fallito");
		else printf("ERR - Comunicazione col server interrotta\n");
		exit(0);
	}
	
	if((nbytes = recv(ser.socket, (void*)&ris, sizeof(ris), 0)) < sizeof(ris)){
		if(nbytes < 0) perror("ERR - Ricezione dati fallita");
		else printf("ERR - Comunicazione col server interrotta\n");
		exit(0);
	}

	if(ris.tipo == check_res && ris.codice == utente_inesistente){
		printf("INFO - Utente inesistente\n");
		return;
	} else{

		if(ris.tipo == check_res && ris.codice == utente_online){
		
			printf("Impossibile effettuare il login, utente già online\n");
		
		} else{

			//scambio le chiavi(
			RSAE(ser.socket, ser.session_key);
			/*printf("Session key [CLIENT]:\n");
			print_bytes(ser.session_key, SYM_KEY_SIZE);
			printf("\n");*/
			//)
		
			printf("> Inserire la password: ");
			getPassword(0);
			
			memcpy(tmp_encrypted_pass, encryptPassword((unsigned char *) tpass), ENCRYPTED_PASSWORD_LEN);
			
			if((nbytes = send(ser.socket, (void*)&tmp_encrypted_pass, ENCRYPTED_PASSWORD_LEN, 0)) < ENCRYPTED_PASSWORD_LEN){
				if(nbytes < 0) perror("ERR - Invio dati fallito");
				else printf("ERR - Comunicazione col server interrotta\n");
				exit(0);
			}
			memset(tpass, 0, PASS_LEN);
			// print_ris(ris);
			if((nbytes = recv(ser.socket, (void*)&ris, sizeof(ris), 0)) < sizeof(ris)){
				printf("1\n");
				if(nbytes < 0) perror("ERR - Ricezione dati fallita");
				else printf("ERR - Comunicazione col server interrotta\n");
				exit(0);
			}
			if(ris.codice == utente_ok && ris.tipo == correct_password){
				printf("INFO - Autenticazione completata\n");

				if(binded == 0){
					while(bind(usr.socket, (struct sockaddr*)&usr.clientAddr, sizeof(usr.clientAddr)) == -1){
						printf("La porta scelta in precedenza non è disponibile\n");
						printf("Inserisci un altro numero di porta: ");
						while(getUserPort() == -1) 
							printf("Il dato inserito non è un numero di porta valido\n Inserisci un numero corretto: ");
					}
				}
				
				binded = 1;
				usr.online = 1;
				strcpy(usr.nome, tbuf);
				strcpy(tbuf, "");
			
			} else{
				if(ris.codice == utente_ok && ris.tipo == wrong_password){
					printf("INFO - Password errata\n");
				}
			}
		}
			
	}
	//printf("execLogin terminata\n");
}
void interpretCommand(char* cmd){
	//interpreta il comando cmd e chiama la funzione ad esso associata
	
	if(strcmp(cmd, "!help") == 0){
		if(flushInputStream() == -1){
			printf("Comando non valido, per una lista dei comandi disponibili digita il comando !help\n");
			return;
		}
		printHelp();
		return;
	}
	if(strcmp(cmd, "!who") == 0){
		if(flushInputStream() == -1){
			printf("Comando non valido, per una lista dei comandi disponibili digita il comando !help\n");
			return;
		}
		execWho();
		return;
	}
	if(strcmp(cmd, "!send") == 0){
			if(checkArgumentExists() == -1) 
				printf("Il comando !send richiede un argomento\n");
			else{
				if(getOtherName() == -1){
					printf("Il nome può contenere al più 31 caratteri e non deve contenere spazi\n");
					return;
				}
				if(!strcmp(oth.nome, usr.nome)){
					printf("Non è possibile mandare un messaggio a se stessi\n");
					return;
				}
				if(controlloEsistenza() == 1){
						usr.sending = 1;
						getMessage();
						execSend();
				} else return;
			}
		
		return;
	}
	if(usr.online && strcmp(cmd, "!deregister") == 0){
		if(flushInputStream() == -1){
			printf("Comando non valido, per una lista dei comandi disponibili digita il comando !help\n");
			return;
		}
		execDeregister();
		return;
	}
	if(strcmp(cmd, "!login") == 0){
		if(usr.online == 1) 
			printf("Il comando !login è utilizzabile solo se non si è gia connessi presso il Server\n");
		else{
		if(usr.online == 1) 
			printf("Il comando !register è utilizzabile solo dopo un comando !deregister o !quit\n");
			else{
				if(checkArgumentExists() == -1) 
					printf("Il comando !login richiede un argomento\n");
				else{
					if(getUserName(0) == -1) 
						printf("Il nome può contenere al più 31 caratteri e non deve contenere spazi\n");
					else 
						execLogin();
				}
			}
		}
		return;
	}
	if(strcmp(cmd, "!logout") == 0){
		if(!usr.online){
			printf("Il comando è disponibile soltanto una volta connessi\n");
			return;
		}
		if(flushInputStream() == -1){
			printf("Comando non valido, per una lista dei comandi disponibili digita il comando !help\n");
			return;
		}
		execLogOut();
		return;
	}
	if(strcmp(cmd, "!register") == 0){
		if(usr.online == 1) 
			printf("Il comando !register è utilizzabile solo dopo un comando !deregister o !quit\n");
		else{
			if(checkArgumentExists() == -1) 
				printf("Il comando !connect richiede un argomento\n");
			else{
				if(getUserName(1) == -1) 
					printf("Il nome può contenere al più 31 caratteri e non deve contenere spazi\n");
				registraUtente();
			}
		}
		return;
	}
	if(strcmp(cmd, "!quit") == 0){
		if(flushInputStream() == -1){
			printf("Comando non valido, per una lista dei comandi disponibili digita il comando !help\n");
			return;
		}
		usr.quit = 1;
		execQuit();
		return;
	}
	
	flushInputStream();
	printf("Comando non valido, per una lista dei comandi disponibili digita il comando !help\n");
}

void waitForData(){
	//attende l'input di un comando
	
	char cmd[CMD_LEN];
	char formatStr[FORMAT_STR_LEN];
	fd_set readFds;
	int i, numDes;
	
	sprintf(formatStr, "%%%ds", CMD_LEN - 1);
	
	//stampa il carattere che segnala all'utente che può inserire un comando
	if(usr.printShell == 1 && usr.sending == 0 && usr.receiving ==0){
				printf("%s> ", usr.nome);
				fflush(stdout);
	}
	//usr.printShell = 1;
	
	//esecuzione select
	readFds = usr.fdSet;
	if((numDes = select(usr.fdMax + 1, &readFds, NULL, NULL, NULL)) == -1){
		perror("ERR - Errore nella ricerca di descrittori pronti alla lettura");
		exit(0);
	}

	//controllo dei descrittori per vedere quali socket sono pronti
	for(i = 0; i <= usr.fdMax; i++){
		//controllo il descrittore i
		
		if(FD_ISSET(i, &readFds) && i == (int)STDIN){
			//attendo l'ingresso del comando
			scanf(formatStr, cmd);
			if(strlen(cmd) >= CMD_LEN - 1){
				//nessun comando ha questa lunghezza
				printf("Comando non valido, per una lista dei comandi disponibili digita il comando !help\n\n");
				flushInputStream();
				return;
			}
	
			//interpretazione del comando
			interpretCommand(cmd);
		}
		
		if(FD_ISSET(i, &readFds) && i == ser.socket){
			switch(usr.sending){
				case 1:
					initUdpSender();
					if(continua == 1)
						sendMessage();
					usr.sending=0;
					break;
				default:
					//richiesta di connessione
					initUdpReceiver();
					usr.receiving = 1;
					break;
			}
		}
		if(FD_ISSET(i, &readFds) && i == usr.socket){
			//messaggio dall'avversario
			
			recvMessage();
			usr.receiving = 0;
		}
	}
}

int main(int argc, char* argv[]){
	
	//controllo dei dati in ingresso
	if(checkInput(argc, argv) == -1) exit(0);
	
	//parte tcp
	porta = (port)atoi(argv[1]);

	//inizializzazione oggetto Server
	if(serverInit(&ser, argv[2], (port)atoi(argv[3])) == -1) exit(0);
	
	//inizializzazione oggetto user
	if(userInit(&usr, (port)atoi(argv[1]))== -1) exit(0);

	if(binded == 0){
		while(bind(usr.socket, (struct sockaddr*)&usr.clientAddr, sizeof(usr.clientAddr)) == -1){
			printf("La porta scelta non è disponibile\n");
			printf("Inserisci un altro numero di porta: ");
			while(getUserPort() == -1) printf("Il dato inserito non è un numero di porta valido\nInserisci un numero corretto: ");
		}
	}
	binded = 1;
	
	//connessione al server		
	if(connect(ser.socket, (struct sockaddr*)&ser.serverAddr, sizeof(ser.serverAddr)) == -1){
		perror("ERR - Impossibile connettersi al server");
		exit(0);
	}
	
	printf("Connesso al server di indirizzo %s (porta %d)\nRicezione messaggi istantanei su porta %s\n\n", ser.indirizzo, ser.porta, argv[1]);
	
	//stampa lista comandi
	printHelp();
	memset(&message,0,sizeof(message));
	message.time_stamp = (unsigned)time(NULL);	// Aggiorno la struttura con il timestamp di accesso 
	
	//preparazione set descrittori
	FD_ZERO(&usr.fdSet);
	FD_SET((int)STDIN, &usr.fdSet); //abilito la ricezione di dati dallo standard input
	FD_SET(ser.socket, &usr.fdSet); //abilito la ricezione di dati dal server
	usr.fdMax = (int)STDIN;
	if(ser.socket > usr.fdMax) usr.fdMax = ser.socket;
	if(usr.socket > usr.fdMax) usr.fdMax = usr.socket;
	
	//attesa dati
	for(;;){
		waitForData();
		if(usr.quit == 1) break;
	}
	
	//operazioni di chiusura
	if(close(usr.socket) == -1){
		perror("ERR - Errore nella chiusura del socket UDP");
		exit(0);
	}
	if(close(ser.socket) == -1){
		perror("ERR - Errore nella chiusura del socket TCP");
		exit(0);
	}
	
	printf("\nArrivederci!\n");
	
	return 0;
}
