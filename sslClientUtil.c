#include "sslClientUtil.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

/**
 * 功能：客户端向服务端发送连接请求
 * 输入参数：
 * serverIP:服务端IP
 * port:端口号
 * 输出参数：
 * serverSocketfd:服务端的socket描述符
 * 返回标志：
 *  连接失败返回-1
 *  连接成功返回0
 */
int tcpConnect(const char* serverIP, const int port, int *serverSocketfd) {
	/* 创建tcp的socket连接 */
	struct sockaddr_in serverAddr; //声明指向要绑定的服务端socket描述符地址的结构体变量
	*serverSocketfd = socket(AF_INET, SOCK_STREAM, 0); //创建socket描述符
	if ((*serverSocketfd) < 0) {
		perror("server socket");
		return -1;
	}
	/* 初始化服务器端（对方）的地址和端口信息 */
	bzero(&serverAddr, sizeof(serverAddr));
	serverAddr.sin_family = AF_INET; //IPv4 Internet protocols
	serverAddr.sin_port = htons(port); //主机字节序转为网络字节序
	//点分十进制转为网络字节序二进制,并检查IP地址是否有效
	if (inet_aton(serverIP, (struct in_addr *) &serverAddr.sin_addr.s_addr)
			== 0) {
		perror(serverIP);
		return -1;
	}
	/* 连接服务器 */
	if (connect((*serverSocketfd), (struct sockaddr *) &serverAddr,
			sizeof(serverAddr)) != 0) {
		perror("Connect ");
		return -1;
	}
	printf("tcp socket send connect success!\n");
	return 0;
}

/**
 * 显示证书内容
 */
void ShowCerts(SSL * ssl) {
	X509 *cert;
	char *line;
	cert = SSL_get_peer_certificate(ssl);
	if (cert != NULL) {
		printf("数字证书信息:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("证书: %s\n", line);
		free(line);
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("颁发者: %s\n", line);
		free(line);
		X509_free(cert);
	} else
		printf("无证书信息！\n");
}

/**
 * 功能：客户端建立ssl连接
 * 输入参数：
 * serverIP:服务端IP
 * port:端口号
 * 输出参数：
 * serverSocketfd:服务端的socket描述符
 * ctx:SSL Content Text
 * 返回标志：
 *  连接失败返回NULL
 *  连接成功返回SSL类型指针
 */
SSL* sslConnect(const char* serverIP, const int port, int *serverSocketfd,
		SSL_CTX *ctx) {
	SSL *ssl;
	/* SSL 库初始化 */
	SSL_library_init();
	/* 载入所有 SSL 算法 */
	OpenSSL_add_all_algorithms();
	/* 载入所有 SSL 错误消息 */
	SSL_load_error_strings();
	/* 以 SSL V2 和 V3 标准兼容方式产生一个 SSL_CTX ，即 SSL Content Text */
	ctx = SSL_CTX_new(SSLv23_client_method());
	/* 也可以用 SSLv2_server_method() 或 SSLv3_server_method() 单独表示 V2 或 V3标准 */
	if (ctx == NULL) {
		ERR_print_errors_fp(stdout);
		return NULL;
	}
	/* 创建tcp的socket连接 */
	if(tcpConnect(serverIP, port, serverSocketfd)==-1){
		return NULL;
	}
	/* 基于 ctx 产生一个新的 SSL */
	ssl = SSL_new(ctx);
	/* 将链接用户的socket加入到SSL */
	SSL_set_fd(ssl, (*serverSocketfd));
	/* 建立 SSL 连接 */
	if (SSL_connect(ssl) == -1)
		ERR_print_errors_fp(stderr);
	else {
		printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
		ShowCerts(ssl);
	}
	return ssl;
}
