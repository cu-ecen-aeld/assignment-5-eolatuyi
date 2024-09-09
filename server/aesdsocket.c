#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <netinet/tcp.h>

#define MAX_PACKET_SIZE 1024  // Define the maximum packet size

int sockfd = -1;
volatile sig_atomic_t keep_running = 1;

void handle_signal(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        syslog(LOG_INFO, "Caught signal, exiting");
        keep_running = 0;
        if (sockfd != -1) {
            close(sockfd);
        }
    }
}

void cleanup() {
    if (sockfd != -1) {
        close(sockfd);
    }
    syslog(LOG_INFO, "Deleting file /var/tmp/aesdsocketdata");
    if (remove("/var/tmp/aesdsocketdata") == 0) {
        syslog(LOG_INFO, "Successfully deleted file /var/tmp/aesdsocketdata");
    } else {
        syslog(LOG_ERR, "Error deleting file /var/tmp/aesdsocketdata: %m");
    }
    closelog();
}

void daemonize() {
    pid_t pid;

    // Fork the process
    pid = fork();

    if (pid < 0) {
        syslog(LOG_ERR, "Error forking process: %m");
        exit(EXIT_FAILURE);
    }

    if (pid > 0) {
        // Parent process, exit
        exit(EXIT_SUCCESS);
    }

    // Create a new session
    if (setsid() < 0) {
        syslog(LOG_ERR, "Error creating new session: %m");
        exit(EXIT_FAILURE);
    }

    // Fork again to ensure the daemon cannot acquire a terminal
    pid = fork();

    if (pid < 0) {
        syslog(LOG_ERR, "Error forking process: %m");
        exit(EXIT_FAILURE);
    }

    if (pid > 0) {
        // Parent process, exit
        exit(EXIT_SUCCESS);
    }

    // Change working directory to the root
    if (chdir("/") < 0) {
        syslog(LOG_ERR, "Error changing directory to /: %m");
        exit(EXIT_FAILURE);
    }

    // Close standard file descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    // Redirect standard file descriptors to /dev/null
    open("/dev/null", O_RDONLY); // stdin
    open("/dev/null", O_RDWR);   // stdout
    open("/dev/null", O_RDWR);   // stderr
}

void* handle_client(void* arg) {
    int newsockfd = *(int*)arg;
    free(arg);
    char buffer[MAX_PACKET_SIZE];
    ssize_t n;

    // Get client IP address
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    if (getpeername(newsockfd, (struct sockaddr *)&client_addr, &client_len) == -1) {
        syslog(LOG_ERR, "Error getting client address: %m");
        close(newsockfd);
        pthread_exit(NULL);
    }
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
    syslog(LOG_INFO, "Accepted connection from %s", client_ip);

    // Open file for appending
    FILE *file = fopen("/var/tmp/aesdsocketdata", "a+");
    if (file == NULL) {
        syslog(LOG_ERR, "Error opening file: %m");
        close(newsockfd);
        pthread_exit(NULL);
    }

    // Read data from client and append to file
    while (keep_running && (n = recv(newsockfd, buffer, MAX_PACKET_SIZE - 1, 0)) > 0) {
        buffer[n] = '\0';  // Ensure null-terminated string
	syslog(LOG_INFO, "bytes_read from client: %ld; ",n);	
	
	// Append data to the file
        if (fputs(buffer, file) == EOF) {
            syslog(LOG_ERR, "Failed to write to file");
            break;
        }

        // Check if the buffer contains a newline character
        if (strchr(buffer, '\n') != NULL) {
            fflush(file); // Ensure data is written to disk
	    syslog(LOG_INFO, "written to disk: %s ", buffer);
	    
	    // Send the full content of the file to the client
            fseek(file, 0, SEEK_SET); // Rewind the file to the beginning
            char file_buffer[MAX_PACKET_SIZE];
            size_t bytes_read;
            
	    bytes_read = fread(file_buffer, 1, MAX_PACKET_SIZE, file);
	    syslog(LOG_INFO, "bytes_read: %ld bytes", bytes_read);
	    while (bytes_read > 0){
                size_t total_sent = 0;
		syslog(LOG_INFO, "bytes_read: %ld; total_sent: %ld bytes", bytes_read, total_sent);
                while (total_sent < bytes_read) {
                    ssize_t bytes_sent = send(newsockfd, file_buffer + total_sent, bytes_read - total_sent, 0);
                    if (bytes_sent < 0) {
                        syslog(LOG_ERR, "Failed to send file content");
                        break;
                    }
                    total_sent += bytes_sent;
		    syslog(LOG_INFO, "bytes_read: %ld; total_sent: %ld bytes", bytes_read, total_sent);
                }
                if (total_sent < bytes_read) {
                    break; // Exit the loop if there was an error sending data
                }
		bytes_read = fread(file_buffer, 1, MAX_PACKET_SIZE, file);
            }
            syslog(LOG_INFO, "Loop bytes_read: %ld bytes", bytes_read);
	    break; // Exit the loop after sending the file content
        }
	
        syslog(LOG_DEBUG, "Received data: %s", buffer);
    }

    if (n == -1) {
        syslog(LOG_ERR, "Error reading from socket: %m");
    } else if (n == 0) {
        // Client sent FIN
        syslog(LOG_DEBUG, "Client sent FIN, half-closed connection from %s", client_ip);
    }

    fclose(file);

    syslog(LOG_DEBUG, "Data received from client and written to file");

    // Log closing connection
    syslog(LOG_INFO, "Closed connection from %s", client_ip);

    // Close client socket
    close(newsockfd);
    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    int daemon_mode = 0;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;

    // Parse command-line arguments
    int opt;
    while ((opt = getopt(argc, argv, "d")) != -1) {
        switch (opt) {
            case 'd':
                daemon_mode = 1;
                break;
            default:
                fprintf(stderr, "Usage: %s [-d]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    openlog("stream_socket", LOG_PID, LOG_USER);

    // Register signal handlers
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        syslog(LOG_ERR, "Error creating socket: %m");
        closelog();
        return -1;
    }

    // Set SO_REUSEADDR option
    int optval = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) == -1) {
        syslog(LOG_ERR, "Error setting SO_REUSEADDR: %m");
        close(sockfd);
        closelog();
        return -1;
    }

    // Set keepalive options
    int keepalive = 1;
    int keepidle = 1;    // Start keepalive after 1 second of inactivity
    int keepinterval = 1; // Send keepalive probes every 1 second
    int keepcount = 1;    // Number of unacknowledged probes before considering the connection dead

    if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive)) == -1) {
        syslog(LOG_ERR, "Error setting SO_KEEPALIVE: %m");
        close(sockfd);
        closelog();
        return -1;
    }

    if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle)) == -1) {
        syslog(LOG_ERR, "Error setting TCP_KEEPIDLE: %m");
        close(sockfd);
        closelog();
        return -1;
    }

    if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPINTVL, &keepinterval, sizeof(keepinterval)) == -1) {
        syslog(LOG_ERR, "Error setting TCP_KEEPINTVL: %m");
        close(sockfd);
        closelog();
        return -1;
    }

    if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPCNT, &keepcount, sizeof(keepcount)) == -1) {
        syslog(LOG_ERR, "Error setting TCP_KEEPCNT: %m");
        close(sockfd);
        closelog();
        return -1;
    }

    // Initialize server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(9000);

    // Bind socket
    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        syslog(LOG_ERR, "Error binding socket: %m");
        close(sockfd);
        closelog();
        return -1;
    }

    // Daemonize if the -d option was provided
    if (daemon_mode) {
        daemonize();
    }

    // Listen for connections
    if (listen(sockfd, 5) == -1) {
        syslog(LOG_ERR, "Error listening on socket: %m");
        close(sockfd);
        closelog();
        return -1;
    }

    syslog(LOG_DEBUG, "Socket bound to port 9000. Ready for connections...");

    while (keep_running) {
        // Accept incoming connections
        client_len = sizeof(client_addr);
        int* newsockfd_ptr = malloc(sizeof(int));
        if (newsockfd_ptr == NULL) {
            syslog(LOG_ERR, "Error allocating memory for newsockfd: %m");
            continue;
        }
        *newsockfd_ptr = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
        if (*newsockfd_ptr == -1) {
            if (errno == EINTR && !keep_running) {
                // Interrupted by signal, exit gracefully
                free(newsockfd_ptr);
                break;
            }
            syslog(LOG_ERR, "Error accepting connection: %m");
            free(newsockfd_ptr);
            continue;
        }

        pthread_t thread;
        int ret = pthread_create(&thread, NULL, handle_client, newsockfd_ptr);
        if (ret != 0) {
            syslog(LOG_ERR, "Error creating thread: %m");
            close(*newsockfd_ptr);
            free(newsockfd_ptr);
        } else {
            pthread_detach(thread); // Detach the thread to allow it to clean up independently
        }
    }

    cleanup();
    return 0;
}

