/* This file carries all functions declaration and structure definations */
#define MAX_THREADS 50
#define MAX_URL_LENGTH 200
#define MAX_PORT_NUMBER 65536
#define TIMEOUT 3

unsigned int ports[] = {
	7, 18, 20, 21, 22, 23, 25, 29, 37, 42, 43, 49, 53, 69, 70, 79, 103, 108, 109, 110, 115, 118, 119, 137, 139, 143,
	150, 156, 161, 179, 190, 194, 197, 389, 396, 443, 444, 445, 458, 546, 547, 563, 569, 1080, 1433, 1434, 3306, 3389
};

struct thread_opts {
	char host[INET_ADDRSTRLEN];
	unsigned int port, timeout, thread_id, start, end;
};

int scan_error(const char *s, int sock);

void *portWorker(void *thread_args);

int portScanner(const char * host, unsigned int *port, unsigned int timeout, unsigned int *start, unsigned int *end);

char* getServiceName(unsigned int *port);