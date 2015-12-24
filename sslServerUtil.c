#include "sslServerUtil.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/**
 * 功能：服务端建立对客户端连接请求的监听
 * 输入参数：
 * serverIP：默认情况为NULL，为INADDR_ANY表示对所有IP监听；也可是对特定的IP
 * port：端口号
 * maxConnectNum：监听最大连接数
 * 输出参数：
 * listenFD：监听套接字描述符
 * 返回标志：
 *  监听失败返回-1
 *  监听成功返回0
 */
int tcpListen(const char* serverIP, const int port, const int maxConnectNum,
		int *listenFD) {
	struct sockaddr_in serverAddr;
	/* 开启一个 socket 监听 */
	if (((*listenFD) = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		return -1;
	}
	/* 初始化监听服务器端的地址和端口信息 */
	bzero(&serverAddr, sizeof(serverAddr));
	serverAddr.sin_family = AF_INET; //IPv4 Internet protocols
	serverAddr.sin_port = htons(port); //服务器端口号
	if (serverIP == NULL) {
		serverAddr.sin_addr.s_addr = htons(INADDR_ANY); //监听所有IP
	} else {
		//点分十进制转为网络字节序二进制,并检查IP地址是否有效
		if (inet_aton(serverIP, (struct in_addr *) &serverAddr.sin_addr.s_addr)
				== 0) {
			close(*listenFD);
			perror(serverIP);
			return -1;
		}
	}
	//端口重用
	int reuse = 1;
	if (setsockopt((*listenFD), SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int))
			< 0) {
		close(*listenFD);
		perror("setsockopt");
		return -1;
	}
	/* 绑定端口信息 */
	if (bind((*listenFD), (struct sockaddr *) &serverAddr,
			sizeof(struct sockaddr)) == -1) {
		close(*listenFD);
		perror("bind");
		return -1;
	}
	/* 开始监听 */
	if (listen((*listenFD), maxConnectNum) == -1) {
		close(*listenFD);
		perror("listen");
		return -1;
	}
	printf("tcp socket is listening...\n");
	return 0;
}

/**
 * 功能：指定路径文件载入用户私钥
 * ctx：SSL Content Text
 * filename:私钥文件路径
 * pass:使用BIO读取密钥时候的pass phase
 */
int SSL_CTX_use_PrivateKey_file_pass(SSL_CTX *ctx, const char *filename,
		char *pass) {
	EVP_PKEY *pkey = NULL;
	BIO *key = NULL;
	key = BIO_new(BIO_s_file());
	BIO_read_filename(key, filename);
	pkey = PEM_read_bio_PrivateKey(key, NULL, NULL, pass);
	if (pkey == NULL) {
		printf("BIO读取密钥失败！\n");
		BIO_free(key);
		return -1;
	}
	//载入用户私钥
	if (SSL_CTX_use_PrivateKey(ctx, pkey) <= 0) {
		printf("载入用户私钥失败！\n");
		BIO_free(key);
		return -1;
	}
	BIO_free(key);
	return 1;
}

int verify_callback_server(int preverify_ok, X509_STORE_CTX *ctx) {
	char buf[256];
	X509 *err_cert;
	int err, depth;
	SSL *ssl;
	err_cert = X509_STORE_CTX_get_current_cert(ctx);
	err = X509_STORE_CTX_get_error(ctx);
	depth = X509_STORE_CTX_get_error_depth(ctx);
	ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());

	X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);
	if (!preverify_ok) {
		printf("verify error:num=%d:%s:depth=%d:%s\n", err,
				X509_verify_cert_error_string(err), depth, buf);
	}
	if (!preverify_ok && (err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT)) {
		X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert), buf, 256);
		printf("issuer= %s\n", buf);
	}
	return preverify_ok;
}

/**
 * 功能：SSL前期的一系列准备工作
 * 输入参数：
 * clientCertFilePath：用户的数字证书， 此证书用来发送给客户端， 证书里包含有公钥
 * pKeyFilePath：私钥文件路径
 * caFilePath:CA证书文件路径
 * pass：使用BIO读取密钥时候的pass phase
 * 返回标志：
 *  失败返回NULL
 *  成功返回SSL_CTX类型的指针
 */
SSL_CTX* SSL_prepare(const char *clientCertFilePath, const char *pKeyFilePath,
		const char *caFilePath, char *pass) {
	SSL_CTX *ctxTmp;
	/* SSL 库初始化 */
	SSL_library_init();
	/* 载入所有 SSL 算法 */
	OpenSSL_add_all_algorithms();
	/* 载入所有 SSL 错误消息 */
	SSL_load_error_strings();
	/* 以 SSL V2 和 V3 标准兼容方式产生一个 SSL_CTX ，即 SSL Content Text */
	ctxTmp = SSL_CTX_new(SSLv23_server_method());
	/* 也可以用 SSLv2_server_method() 或 SSLv3_server_method() 单独表示 V2 或 V3标准 */
	if (ctxTmp == NULL) {
		ERR_print_errors_fp(stdout);
		return NULL;
	}
	//载入CA证书
	if ((SSL_CTX_load_verify_locations(ctxTmp, caFilePath, NULL) <= 0)
			|| (SSL_CTX_set_default_verify_paths(ctxTmp) <= 0)) {
		ERR_print_errors_fp(stdout);
		return NULL;
	}
	/* 载入用户的数字证书， 此证书用来发送给客户端，证书里包含有公钥 */
	if (SSL_CTX_use_certificate_file(ctxTmp, clientCertFilePath,
			SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stdout);
		return NULL;
	}
	/*指定文件载入用户私钥 */
	if (SSL_CTX_use_PrivateKey_file_pass(ctxTmp, pKeyFilePath, pass) <= 0) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}
	/* 检查用户私钥是否正确 */
	if (!SSL_CTX_check_private_key(ctxTmp)) {
		ERR_print_errors_fp(stdout);
		return NULL;
	}

	static int s_server_verify = SSL_VERIFY_NONE;
	s_server_verify = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT
			| SSL_VERIFY_CLIENT_ONCE;
	SSL_CTX_set_verify(ctxTmp, s_server_verify, verify_callback_server);
	SSL_CTX_set_client_CA_list(ctxTmp, SSL_load_client_CA_file(caFilePath));

	printf("ssl prepare success!\n");
	return ctxTmp;
}

/**
 * 功能：接收来自客户端的ssl连接请求
 * 输入参数：
 * ctx：SSL Content Text
 * connectFD：客户端的连接套接字描述符
 * 返回标志：
 *  连接失败返回NULL
 *  连接成功返回SSL类型指针
 */
SSL* sslAccept(SSL_CTX *ctx, int connectFD) {
	SSL *ssl;
	/* 基于 ctx 产生一个新的 SSL */
	ssl = SSL_new(ctx);
	/* 将连接用户的 socket 加入到 SSL */
	SSL_set_fd(ssl, connectFD);
	/* 建立 SSL 连接 */
	if (SSL_accept(ssl) == -1) {
		perror("accept");
		close(connectFD);
		return NULL;
	}
	printf("ssl accept success!\n");
	return ssl;
}
