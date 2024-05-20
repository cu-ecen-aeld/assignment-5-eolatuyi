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

#define MAX_PACKET_SIZE 1024  // Define the maximum packet size

int sockfd = -1, newsockfd = -1;
volatile sig_atomic_t keep_running = 1;

void handle_signal(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        syslog(LOG_INFO, "Caught signal, exiting");
        keep_running = 0;
        if (sockfd != -1) {
            close(sockfd);
        }
        if (newsockfd != -1) {
            close(newsockfd);
        }
    }
}

void cleanup() {
    if (newsockfd != -1) {
        close(newsockfd);
    }
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

int main(int argc, char *argv[]) {
    int daemon_mode = 0;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;
    char *buffer;
    int n;

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
        newsockfd = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
        if (newsockfd == -1) {
            if (errno == EINTR && !keep_running) {
                // Interrupted by signal, exit gracefully
                break;
            }
            syslog(LOG_ERR, "Error accepting connection: %m");
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
        syslog(LOG_INFO, "Accepted connection from %s", client_ip);

        // Allocate buffer for receiving data
        buffer = (char *)malloc(MAX_PACKET_SIZE);
        if (buffer == NULL) {
            syslog(LOG_ERR, "Error allocating memory: %m");
            close(newsockfd);
            continue;
        }

        // Open file for appending
        FILE *file = fopen("/var/tmp/aesdsocketdata", "a");
        if (file == NULL) {
            syslog(LOG_ERR, "Error opening file: %m");
            free(buffer);
            close(newsockfd);
            continue;
        }

        // Read data from client and append to file
        while ((n = read(newsockfd, buffer, MAX_PACKET_SIZE - 1)) > 0) {
            buffer[n] = '\0';  // Ensure null-terminated string
            printf("Received: %s\n", buffer);
	    fprintf(file, "%s", buffer);
        }

        if (n == -1) {
            syslog(LOG_ERR, "Error reading from socket: %m");
        }

        fclose(file);

        // Read file content and send back to client
        file = fopen("/var/tmp/aesdsocketdata", "r");
        if (file == NULL) {
            syslog(LOG_ERR, "Error opening file for reading: %m");
            free(buffer);
            close(newsockfd);
            continue;
        }


        while (fgets(buffer, MAX_PACKET_SIZE, file) != NULL) {
            n = strlen(buffer);
	    buffer[n]='\n';
            ssize_t bytes_written = write(newsockfd, buffer, n);
            if (bytes_written != n) {
                syslog(LOG_ERR, "Error writing to socket: %m");
                break;
            }
            syslog(LOG_DEBUG, "Sent %d bytes to client",n);	
	}

        if (ferror(file)) {
            syslog(LOG_ERR, "Error reading from file: %m");
        }

        fclose(file);
        free(buffer);
        syslog(LOG_DEBUG, "Data received from client and written to file");

        // Log closing connection
        syslog(LOG_INFO, "Closed connection from %s", client_ip);

        // Close client socket
        close(newsockfd);
        newsockfd = -1;
    }

    cleanup();
    return 0;
}

