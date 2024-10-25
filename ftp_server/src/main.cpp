#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 21
#define BUFFER_SIZE 1024

void handle_client(SSL *ssl) {
    char buffer[BUFFER_SIZE];
    SSL_write(ssl, "220 Welcome to the FTP server.\n", 32);

    while (true) {
        int bytes = SSL_read(ssl, buffer, sizeof(buffer));
        buffer[bytes] = '\0';
        std::cout << "Command: " << buffer << std::endl;

        if (strncmp(buffer, "QUIT", 4) == 0) {
            SSL_write(ssl, "221 Goodbye.\n", 13);
            break;
        }
        // Handle other FTP commands...
    }
}

int main() {
    SSL_library_init();
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());

    // Load certificates and keys
    SSL_CTX_use_certificate_file(ctx, "certs/server-cert.pem", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "certs/server-key.pem", SSL_FILETYPE_PEM);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, 5);
    std::cout << "Server listening on port " << PORT << std::endl;

    while (true) {
        int client_fd = accept(server_fd, nullptr, nullptr);
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);
        SSL_accept(ssl);

        handle_client(ssl);

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    }

    SSL_CTX_free(ctx);
    close(server_fd);
    return 0;
}
