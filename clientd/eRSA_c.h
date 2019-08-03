int send_test_message(int sk, unsigned char* key, int key_size);
void initp();
int RSAE(int sk, unsigned char session_key[SYM_KEY_SIZE]);