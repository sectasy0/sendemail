#include<string>
#pragma once
#ifndef A_CPP_INCLUDED
#define A_CPP_INCLUDED

static int sendmail(const char* from, const char* to, const char* subject, const char* body);
static void sendmail_write(const int sock, const char* str, const char* arg);
std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len);

#endif