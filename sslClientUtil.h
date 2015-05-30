/*
 * sslClientUtil.h
 *
 *  Created on: 2015年5月29日
 *      Author: 425-server2
 */

#ifndef SSLCLIENTUTIL_H_
#define SSLCLIENTUTIL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/ossl_typ.h>

//客户端向服务端发送连接请求，发送成功返回0，失败返回-1
int tcpConnect(const char* serverIP, const int port, int *serverSocketfd);

//基于tcp连接的ssl连接，连接成功返回SSL，失败返回NULL
SSL* sslConnect(const char* serverIP, const int port, int *serverSocketfd,
		SSL_CTX *ctx);

#ifdef __cplusplus
}
#endif
		
#endif /* SSLCLIENTUTIL_H_ */
