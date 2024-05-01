#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/fcntl.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

#include "validateWebServer.h"

/**
 * Function to create a socket
*/
short socketCreate(void) {
	short hSocket;// 2-byte data type
	// Usage socket(domain, type, protocol) AF_INET = IPv4 Internet Protocols, 
	// SOCK_STREAM is 2 way connection-based byte stream
	// protocol is 0 if a single protocol exists for a type
	hSocket = socket(AF_INET, SOCK_STREAM, 0); 
	// == 0 if exist
	if(hSocket == -1){
		printf("\nSocket creation failed\n");
		abort();
	}
	return hSocket;
}

/**
 * Function to connect to a socket
*/
int socketConnect(int hSocket, const char * host, int serverPort) {
	int iRetval = -1;

	// This struct has all information which is required to connect to target
	struct sockaddr_in address = { 0 };

	// Fill sockaddr_in struct.
	address.sin_family = AF_INET;               	// ipv4 family of addresses
	address.sin_addr.s_addr = inet_addr(host);		/* inet_addr() converts string of host IP to int */
	address.sin_port = htons(serverPort);			// port to connect to
  
	iRetval = connect(hSocket, (struct sockaddr *)&address, sizeof(struct sockaddr_in));
	return iRetval;
}

/**
 * Verify web server at port 80
*/
int checkWebServerAt80(const char * host) {
	int sockfd = socketCreate();			// create socket

	int connect_result = socketConnect(sockfd, host, 80);

	close(sockfd);
	return connect_result;
}

/*
 * This function is a core of this port scanner. It scans a port specified in port parameter.
 * That parameter can be changed after passing to process second port to scan. Most important
 * part of this function is we are setting socket on non blocking and waiting if we got a 
 * permission to write on socket.
 */
int portScanner(const char* host, unsigned int *port, unsigned int timeout, unsigned int *start, unsigned int *end)
{
	// This struct is used in select(). It contains timeout information.
	struct timeval tv;
	fd_set write_fds;
	socklen_t so_error_len;
	// The socket descriptor, error status and yes.
	int sd, so_error = 1, yes = 1;
	int writePerm;

	// Wait until start flag is not enabled by main process
	while(!*start) {
		sleep(2);	/* Wait for 2 seconds */
	}

	// Process until end flag is not set by main process
	while(!*end) {
		// Wait for 2 seconds till port is 0
		while(*port == 0) {
			sleep(2);
		}

		tv.tv_sec = timeout;    // Seconds to timeout
		tv.tv_usec = 0;     	// Microseconds to timeout

		FD_ZERO(&write_fds);
		so_error_len = sizeof(so_error);

		// Create a socket
		sd = socketCreate();
		
		// Set port as reuseable. So we may not use up all available ports.
		setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
		// Trying timeout stuff
		setsockopt(sd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

		// Make our socket non-blocking. Program will not stop until connection is made.
		fcntl(sd, F_SETFL, O_NONBLOCK);

		// Now connect() function will always returns -1 as we are in non-blocking flag.
		if (socketConnect(sd, host, *port) < 0) {
			switch (errno) {
				case EWOULDBLOCK:	/* Processing going on */
				case EINPROGRESS:	/* Connection in progress */
					break;
				default:
					return scan_error("Encountered error in connect()", sd);
			}
		}
            
		FD_SET(sd, &write_fds);
		
		// Waiting for time when we can write on socket or timeout occurs
		if ((writePerm = select(sd + 1, NULL, &write_fds, NULL, &tv)) == -1) {
            return scan_error("Encountered error in select()", sd);
        }

		// If we got permission to write
		if (writePerm && getsockopt(sd, SOL_SOCKET, SO_ERROR, &so_error, &so_error_len) <= 0) {
            if (so_error == 0 && *port != 0) {
				printf("   %d %s OPEN\n", *port, getServiceName(port));
			}
        }
		// Set port to 0. So we do not process one port again and again
		*port = 0;
	}

    //Close the socket.
	close(sd);
	return (so_error == 0);
}

/*
 * A worker function or thread function that will run beside main. This will be responsible
 * for scanning ports passed by main function to a thread.
 */
void *portWorker(void *thread_opts) {
	// Create pointer to struct which carries all options passed by main
	struct thread_opts *opts;
    int status;

	opts = thread_opts;
	// Call to worker thread for performing the actual work
	status = portScanner(opts->host, &opts->port, opts->timeout, &opts->start, &opts->end);

	pthread_exit(NULL);				// Exit current thread
}

/**
 * Remove protocol i.e. either http or https from the url
*/
char *get_domain(char *url) {
  char *domain = malloc(sizeof(char) * 64); 
  if (sscanf(url, "http://%[^/]", domain) == 1) {
    return domain;
  } else if (sscanf(url, "https://%[^/]", domain) == 1) {
    return domain;
  } else {
    return NULL; // Not a valid http or https URL
  }
}

int main(int argc, char *argv[])
{
	char url[MAX_URL_LENGTH];

	FILE *fp = fopen("webpages.txt", "r");
    if (fp == NULL) {
        perror("Error opening file");
        return 1;
    }

    while (fgets(url, MAX_URL_LENGTH, fp) != NULL) {
        // Strip newline if present
        url[strcspn(url, "\n")] = '\0';

		printf("URL ->>>> %s\n", url);
        
		// Extract domain from URL
        char *domain = get_domain(url);
		if (domain) {
			printf("DOMAIN ->>>> %s\n", domain);
  		} else {
   		 	printf("Invalid URL format\n");
			continue;
  		}

		// Check domain existence
		struct hostent *host = gethostbyname(domain);
		if (host == NULL) {
			printf("Domain does not exist\n\n");
			continue;
		} else {
			printf("Domain exists\n");
		}

		char ipaddr[MAX_URL_LENGTH];
		// Copy to struct with typecasting
		strcpy(ipaddr , inet_ntoa(*( (struct in_addr *)host->h_addr_list[0])));
		printf("Scanning IP %s\n", ipaddr);

        int isWebServerRunningAt80 = checkWebServerAt80(ipaddr);
        if (isWebServerRunningAt80 == -1) {
            printf("Web server not running at port 80\n");
        } else {
            printf("Web server running at port 80\n");
        }

		int thread_id;
		pthread_t threads[MAX_THREADS];
		struct thread_opts opts[MAX_THREADS];
		
		// Create threads that will not do anything until we set opts[thread_id].start = 1
		for (thread_id = 0; thread_id < MAX_THREADS; thread_id++) {
			opts[thread_id].start = 0;			/* Placeholder, we are only creating threads here */
			opts[thread_id].end = 0;			/* threads will check this variable if they should exit or not */
			opts[thread_id].port = 0;			/* Placeholder, we are only creating threads here */
			opts[thread_id].timeout = TIMEOUT;
			opts[thread_id].thread_id = thread_id;			/* Assign each thread a ID */
			strncpy(opts[thread_id].host, ipaddr, (size_t) INET_ADDRSTRLEN);	/* Set target host */

			/* Create threads */
			if (pthread_create(&threads[thread_id], NULL, portWorker, (void *) &opts[thread_id])) {
				#ifdef DEBUGING
				perror("pthread_create() error");	/* Print error in thread creation */
				#endif
				return EXIT_FAILURE;
			}
		}

		thread_id = 0;	
		printf("Other open ports:\n");

		/* Iterate through all threads */
		for (int thread_id = 0; thread_id < MAX_THREADS; thread_id++) {
			if (opts[thread_id].port == 0) {
				opts[thread_id].port = ports[thread_id];		/* giving port to each thread to scan */
				opts[thread_id].start = 1;						/* Switch red light to green so threads can run */
			}
		}

		sleep(TIMEOUT + TIMEOUT); 			/* ensure all threads had done their work */
		printf("Port scanning complete\n\n");
		free(domain); 
	}

	sleep(2); 
}

char* getServiceName(unsigned int *port) {
	switch(*port) {
		case 20:
			return "FTP";
		case 21:
			return "FTP";
		case 22:
			return "SSH";
		case 23:
			return "Telnet";
		case 25:
			return "SMTP";
		case 53:
			return "DNS";
		case 139:
			return "NetBIOS";
		case 445:
			return "SMB";
		case 1433:
			return "SQL";
		case 1434:
			return "SQL";
		case 3306:
			return "SQL";
		case 3389:
			return "RDP";
		case 80:
			return "HTTP";
		case 443:
			return "HTTPS";
		default:
			return "";
	}
}

/*
 * Close socket and print some information if debugging.
 */
int scan_error(const char *s, int sock)
{
	#ifdef DEBUGING
	perror(s);
	#endif
	if (sock)
		close(sock);
	return 0;
}