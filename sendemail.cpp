#pragma warning(disable:4996)
#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <WinSock2.h>
#include <vector>

#include "sendemail.hpp"

#define SMTP_HOST "smtp.mail.com"
#define SMTP_PORT 587

SOCKET sock;
char recvbuf[BUFSIZ + 1];
std::vector<std::string> buf;

unsigned const char *mail_username = "";
unsigned const char *mail_password = "";

int main() {
    sendmail(
        "piotrek.m@mail.com",
        "piotrek.m@mail.com",
        "Zbanowalem uzytkownika THC",
        "Jak mogles kurwo powiedziec, ze kiedys mialem lepszy brzuch"
    );
}

static void sendmail_write(const int sock, const char* str, const char* arg) {
    char buf[4096];

    if (arg != NULL)
        snprintf(buf, sizeof(buf), str, arg);
    else
        snprintf(buf, sizeof(buf), str);

    send(sock, buf, strlen(buf), 0);
}

bool read_socket() {
    int bytesRecv = recv(sock, recvbuf, BUFSIZ, 0);

    while (bytesRecv > 0) {
        std::string str(recvbuf, strlen(recvbuf));

        memset(&recvbuf, 0, sizeof(recvbuf));
        buf.push_back(str);

        return true;
    }
    return false;
}

int close_connection(SOCKET sock) {
    closesocket(sock);
    return -1;
}

static int sendmail(const char* from, const char* to, const char* subject, const char* body) {
    sockaddr_in service;
    WSADATA wsaData;
    
    struct hostent* remoteHost;

    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != NO_ERROR) {
        return -1;
    }

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return -2;
    }

    remoteHost = gethostbyname(SMTP_HOST);
    if (remoteHost == NULL) {
        return -3;
    }

    memset(&service, 0, sizeof(service));
    service.sin_family = AF_INET;
    service.sin_addr.s_addr = *(u_long*)remoteHost->h_addr_list[0];
    service.sin_port = htons(SMTP_PORT);

    int connection = connect(sock, (SOCKADDR*)&service, sizeof(service)) == SOCKET_ERROR;
    if (connect == 0) {
        WSACleanup();
        std::cout << 3;
        return EXIT_FAILURE;
    }
    std::string u_b64 = base64_encode(mail_username, strlen((char*)mail_username)) + "\r\n";
    std::string p_b64 = base64_encode(mail_password, strlen((char*)mail_password)) + "\r\n";

    read_socket();
    if (buf[0].substr(0, 3) != "220") {
        std::cout << "Failed to connect to server";
        return close_connection(sock);
    }
    sendmail_write(sock, "EHLO there\r\n", NULL);
    read_socket();
   if (buf[1].substr(0, 3) != "250") {
        std::cout << "Server didn't response to greeting";
        return close_connection(sock);
    }
    sendmail_write(sock, "AUTH LOGIN\r\n", NULL);
    read_socket();
    if (buf[2].substr(0, 3) != "334") {
        std::cout << "Something went wrong";
        return close_connection(sock);
    }
    sendmail_write(sock, u_b64.c_str(), NULL);
    read_socket();
    sendmail_write(sock, p_b64.c_str(), NULL);
    read_socket();
    if (buf[4].substr(0, 3) == "535") {
        std::cout << "Bad credentials";
        return close_connection(sock);
    }
    sendmail_write(sock, "MAIL FROM: %s\r\n", from);
    read_socket();
    if (buf[5].substr(0, 3) != "250") {
        return close_connection(sock);
    }
    sendmail_write(sock, "RCPT TO: %s\r\n", to);
    read_socket();
    if (buf[6].substr(0, 3) != "250") {
        return close_connection(sock);
    }
    sendmail_write(sock, "DATA\r\n", NULL);
    read_socket();
    if (buf[7].substr(0, 3) != "354") {
        return close_connection(sock);
    }
    sendmail_write(sock, "FROM: %s\r\n", from);
    sendmail_write(sock, "TO: %s\r\n", to);
    sendmail_write(sock, "SUBJECT: %s\r\n", subject);
    sendmail_write(sock, "\r\n", NULL);
    sendmail_write(sock, "%s\r\n", body);
    sendmail_write(sock, "\r\n.\r\n", NULL);
    sendmail_write(sock, "QUIT\r\n", NULL);
    read_socket();
    if (buf[8].substr(0, 3) == "250") {
        std::cout << "Mail was successfully delivered";
    }


    closesocket(sock);
    return EXIT_SUCCESS;
}

std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len) {
    static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (in_len--) {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; (i < 4); i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; (j < i + 1); j++)
            ret += base64_chars[char_array_4[j]];

        while ((i++ < 3))
            ret += '=';

    }
    return ret;
}