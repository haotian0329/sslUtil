/*
 * sslServerUtil.h
 *
 *  Created on: 2015年5月29日
 *      Author: 425-server2
 */

#ifndef SSLSERVERUTIL_H_
#define SSLSERVERUTIL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/ossl_typ.h>

//服务端建立对客户端连接请求的监听,成功返回0，失败返回-1
int tcpListen(const char* serverIP, const int port, const int maxConnectNum,
		int *listenFD);

//SSL前期的一系列准备工作,成功返回SSL_CTX类型的指针，失败返回NULL
SSL_CTX* SSL_prepare(const char *clientCertFilePath, const char *pKeyFilePath,
		char *pass);

//接收来自客户端的ssl连接请求，成功返回SSL类型指针，失败返回NULL
SSL* sslAccept(SSL_CTX *ctx, int connectFD);

#ifdef __cplusplus
}
#endif

#endif /* SSLSERVERUTIL_H_ */
