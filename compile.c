#include<stdlib.h>
int main(){
	system("gcc -Wall -c ./clientd/cripto.c");
	system("gcc -Wall -c ./clientd/eRSA_c.c");
	system("gcc -Wall -c ./clientd/NS_c.c");
	system("gcc -Wall -c ./clientd/simKey.c");
	system("gcc -Wall -o client client.c cripto.o eRSA_c.o NS_c.o simKey.o -lcrypto");
	system("gcc -Wall -c ./serverd/cripto.c");
	system("gcc -Wall -c ./serverd/eRSA_s.c");
	system("gcc -Wall -o server server.c cripto.o eRSA_s.o -lcrypto");
	system("rm *.o");
	return 0;
}
