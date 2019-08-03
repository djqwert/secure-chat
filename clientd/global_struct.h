#define M1_SIZE 80
#define M2_SIZE 196
#define M3_SIZE 84
#define M4_SIZE 16
#define M5_SIZE 16
#define ENCRYPTED_M2_SIZE 208
#define ENCRYPTED_M3_SIZE 96
#define ENCRYPTED_M4_SIZE 32
#define ENCRYPTED_M5_SIZE 32

#define ADD_LEN 16
#define NAME_LEN 32
#define Q_LENGTH 50
#define FORMAT_STR_LEN 5
#define MAX_PORT ((1<<16) - 1)
#define CMD_LEN 16
#define COMB_LEN 4
#define STDIN 0
#define MSG_LEN 50
#define PASS_LEN 64
#define ENCRYPTED_PASSWORD_LEN 80

#define NONCE_LEN 16
#define DELIMITER_SIZE 25
#define ENCRYPTED_SYM_KEY_SIZE 384
#define SYM_KEY_SIZE 32
#define SECRET_SIZE 16
#define HASH_SIZE 32
#define MSG_SIZE 150
#define MSG_BUF_SIZE 188
#define END_MSG_SIZE 192

typedef unsigned short int port;

/* NASCONDERE struct user E struct server, SE COMPILARE SERVER */
struct user{
	int socket;
	char nome[NAME_LEN];
	char indirizzo[ADD_LEN];
	port portaUDP;
	struct sockaddr_in clientAddr;
	int online;
	int sending;
	int receiving;
	int quit;
	int printShell;
	//per l'i/o multiplexing
	fd_set fdSet;
	int fdMax;
};

struct server{
	int socket;
	char indirizzo[ADD_LEN];
	port porta;
	struct sockaddr_in serverAddr;
	// ( SYMMETRIC SESSION KEY
	unsigned char session_key[SYM_KEY_SIZE];
	// )
};

enum req_type{
	registration_req,
	who_req,
	send_req,
	deregister_req,
	accept_req,
	sendOff_req,
	quit_req,
	check_req,
	pass_req,
	log_req,
	logout_req,
	key_exchange_req
};

enum res_type{
	registration_res,
	who_res,
	send_res,
	deregister_res,
	accept_res,
	sendOff_res,
	quit_res,
	msgOff_res,
	messaggio_res,
	check_res,
	correct_password,
	wrong_password
};

struct richiesta{
	enum req_type tipo;
	char nome[NAME_LEN];//significativo se tipo = registration_req oppure tipo = connect_req o sendOffReq
	char indirizzo[ADD_LEN];//significativo se tipo=connect_req
	char messaggio[1024]; //significativo se tipo=sendOff_req
	unsigned char encrypted_password[ENCRYPTED_PASSWORD_LEN]; //significativo se tipo = pass_req
	port porta;//significativo se tipo = registration_req oppure tipo = connect_req
};

//per le richieste di tipo connect, specifica il motivo per cui una richiesta viene rifiutata
enum res_code{utente_inesistente, utente_offline, utente_ok, utente_online};

struct risposta{
	int esito; 	//0 se una richiesta viene accettata, -1 altrimenti; significativo per richieste di registrazione e connessione
				//per richieste who 1 se ci sono altri dati da leggere, 0 altrimenti
	enum res_type tipo;
	
	//significativi per richieste who
	char nome[NAME_LEN];
	int online;
	
	//significativi per richieste connect
	enum res_code codice;
	char indirizzo[ADD_LEN];
	port portaUDP;
	
	int numMessaggi;
	char messaggio[1024];
};

struct other{
	char nome[NAME_LEN];
	char indirizzo[ADD_LEN];
	unsigned char shared_key[SYM_KEY_SIZE];
	unsigned char shared_secret[SECRET_SIZE];
	port portaUDP;
	struct sockaddr_in clientAddr;
};

// Structures for Needham Schroeder Protocol (
struct M1{
	// PARTY A
	char nome_a[NAME_LEN];
	// PARTY B
	char nome_b[NAME_LEN];
	unsigned char nonce[NONCE_LEN];
};
struct M2{
	unsigned char nonce[NONCE_LEN];
	// PARTY B
	char nome_b[NAME_LEN];
	unsigned char shared_key[SYM_KEY_SIZE];
	unsigned char shared_secret[SECRET_SIZE];
	unsigned char encrypted_m3[ENCRYPTED_M3_SIZE];
	unsigned time_stamp;
};
struct M3{
	// PARTY A
	char nome_a[NAME_LEN];
	unsigned time_stamp;
	unsigned char shared_key[SYM_KEY_SIZE];
	unsigned char shared_secret[SECRET_SIZE];
};
struct M4{
	unsigned char nonce[NONCE_LEN];
};
struct M5{
	unsigned char nonce[NONCE_LEN];
};
// )
struct msg_struct{
	unsigned time_stamp;
	unsigned char digest[HASH_SIZE];
	char messaggio[150];
};
