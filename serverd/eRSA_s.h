int recv_cipher(int sk, unsigned char** buffer, int buf_len);
int send_msg_and_sgnt(int sk, const unsigned char* buffer, int buf_len);
void generateKeys();
int receive_test_message(int sk, unsigned char* key, int key_size);
int RSAE(int sk, unsigned char session_key[SYM_KEY_SIZE]);