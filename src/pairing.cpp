/*
 *  RAOP server: control an AirPlay-1 client
 *
 *  (c) Philippe, philippe_44@outlook.com
 *
 *  See LICENSE
 *
 */

#include <string>
#include <string_view>
#include <sstream>
#include <map>
#include <algorithm>
#include <vector>
#include <variant>
#include <cstdarg>
#include <cstdlib>

#include "openssl/ssl.h"
#include "openssl/sha.h"
#include "openssl/srp.h"

extern "C" {
#include "cross_log.h"
#include "cross_util.h"
#include "cross_net.h"
#include "mdnssd.h"
#include "raop_client.h"
}

#include "bplist.h"

// See https://htmlpreview.github.io/?https://github.com/philippe44/RAOP-Player/blob/master/doc/auth_protocol.html
// for the explanations of all that soup

//#define TEST_VECTOR

// a few global, not pretty but convenient
#define KEYSIZE 32
static BIGNUM* A, * a;
static char K[20*2];
static uint8_t scratch[1024];

std::vector<uint8_t> computeM1(std::vector<uint8_t> pk, std::vector<uint8_t> salt, char* user, char* passwd) {
	// initialize SRP context
	SRP_gN* gN = SRP_get_default_gN("2048");

	// transform pk (B) and salt (s)
	BIGNUM* B = BN_new();
	BN_bin2bn(pk.data(), pk.size(), B);
	BIGNUM* s = BN_new();
	BN_bin2bn(salt.data(), salt.size(), s);

	// test vector
#ifdef TEST_VECTOR
	char* _pk = (char*) "4223ddb35967419ddfece40d6b552b797140129c1c262da1b83d413a7f9674aff834171336dabadf9faa95962331e44838d5f66c46649d583ee44827755651215dcd5881056f7fd7d6445b844ccc5793cc3bbd5887029a5abef8b173a3ad8f81326435e9d49818275734ef483b2541f4e2b99b838164ad5fe4a7cae40599fa41bd0e72cb5495bdd5189805da44b7df9b7ed29af326bb526725c2b1f4115f9d91e41638876eeb1db26ef6aed5373f72e3907cc72997ee9132a0dcafda24115730c9db904acbed6d81dc4b02200a5f5281bf321d5a3216a709191ce6ad36d383e79be76e37a2ed7082007c51717e099e7bedd7387c3f82a916d6aca2eb2b6ff3f3";
	BN_hex2bn(&B, _pk);
	char* _salt = (char*) "d62c98fe76c77ad445828c33063fc36f";
	BN_hex2bn(&s, _salt);
	user = (char*) "366B4165DD64AD3A";
	BN_hex2bn(&a, "a18b940d3e1302e932a64defccf560a0714b3fa2683bbe3cea808b3abfa58b7d");
	passwd = (char*) "1234";
	char* _M1 = (char*) "4b4e638bf08526e4229fd079675fedfd329b97ef";
	char* _a_pub = (char*) "0ceaa63dedd87d2da05ff0bdfbd99b5734911269c70664b9a74e04ae5cdbeca7";
#endif
	// end test vector

	// verify B
	int verify = SRP_Verify_B_mod_N(B, gN->N);
	verify = verify;

	A = SRP_Calc_A(a, gN->N, gN->g);
	BIGNUM* x = SRP_Calc_x(s, user, passwd);
	BIGNUM* u = SRP_Calc_u(A, B, gN->N);
	BIGNUM* S = SRP_Calc_client_key(gN->N, B, gN->g, x, a, u);

	// M1 = SHA1(SHA1(N) ^ SHA1(g) | SHA1(I) | s | PAD(A) | PAD(B) | K)
	std::vector<uint8_t> data;
	size_t lenN = BN_num_bytes(gN->N);
	
	// do sha1(N)
	uint8_t sha[20];
	SHA1(scratch, BN_bn2bin(gN->N, scratch), sha);
	data.insert(data.begin(), sha, sha + sizeof(sha));

	// do sha1(g) and xor in place with sha1(N)
	SHA1(scratch, BN_bn2bin(gN->g, scratch), sha);
	for (size_t i = 0; i < sizeof(sha); i++) data[i] ^= sha[i];

	// append sha1(user) (I)
	SHA1((uint8_t*)user, strlen(user), sha);
	data.insert(data.end(), sha, sha + sizeof(sha));

	// append salt (s) - it could be taken from salt but we want compatibility with test
	size_t len = BN_bn2bin(s, scratch);
	data.insert(data.end(), scratch, scratch + len);

	// append PAD(A) and PAD(B)
	BN_bn2binpad(A, scratch, lenN);
	data.insert(data.end(), scratch, scratch + lenN);
	BN_bn2binpad(B, scratch, lenN);
	data.insert(data.end(), scratch, scratch + lenN);

	// append K = SHA1(S | \x00\x00\x00\x00) | SHA(S | \x00\x00\x00\x01)
	memcpy(scratch + BN_bn2binpad(S, scratch, lenN), "\0\0\0\0", 4);
	SHA1(scratch, lenN + 4, sha);
	memcpy(K, sha, sizeof(sha));
	data.insert(data.end(), sha, sha + sizeof(sha));

	memcpy(scratch + BN_bn2binpad(S, scratch, lenN), "\0\0\0\1", 4);
	SHA1(scratch, lenN + 4, sha);
	memcpy(K + sizeof(sha), sha, sizeof(sha));
	data.insert(data.end(), sha, sha + sizeof(sha));

	// this M1 has been verified with test pattern
	SHA1(data.data(), data.size(), sha);

	// free eveything
	BN_free(B);
	BN_free(u);
	BN_free(x);
	BN_free(S);

	std::vector<uint8_t> M1;
	M1.insert(M1.begin(), sha, sha + sizeof(sha));
	return M1;
}

extern "C" {

bool AppleTVpairing(struct mdnssd_handle_s* mDNShandle, char **pSecret, const char *target_ip, int port) {
	// make sure we can safely free these
	A = a = NULL;
	bool success = false;

	if (!target_ip || !*target_ip) {
		fprintf(stderr, "Error: IP address is required for pairing\n");
		fflush(stderr);
		return false;
	}

	fprintf(stderr, "Pairing with device at %s:%d\n", target_ip, port);
	fflush(stderr);

	struct sockaddr_in peer = { };
	key_data_t headers[16] = { };
	int sock = -1;

	peer.sin_family = AF_INET;
	peer.sin_addr.s_addr = inet_addr(target_ip);
	peer.sin_port = htons(port > 0 ? port : 7000);
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (!tcp_connect(sock, peer)) return false;

	kd_add(headers, "Connection", "keep-alive");
	kd_add(headers, "Content-Type", "application/octet-stream");

	char *buffer = http_send(sock, "POST /pair-pin-start HTTP/1.1", headers);
	if (!buffer) {
		kd_free(headers);
		closesocket(sock);
		return false;
	}
	//printf("%s", buffer);
	NFREE(buffer);
	kd_free(headers);

	char method[16], resource[16];
	int len;

	a = BN_new();
	BN_rand(a, 256, -1, 0);

	// request a PIN code to be displayed on ATV
#ifndef TEST_VECTOR
	if (http_parse(sock, method, resource, NULL, headers, NULL, &len) && strcasestr(resource, "200")) {
		kd_free(headers);
#else
	if (1) {
#endif
		char pin[5];
		fprintf(stderr, "enter PIN code displayed on AppleTV:\n");
		fflush(stderr);
#ifndef TEST_VECTOR
		(void)!scanf("%4s", pin);
#else
		strcpy(pin, "1234");
#endif

		// Generate UDN from IP address
		char UDN[16 + 1] = { };
		snprintf(UDN, sizeof(UDN), "%02X%02X%02X%02X%02X%02X%02X%02X",
			target_ip[0], target_ip[1], target_ip[2], target_ip[3],
			target_ip[4], target_ip[5], target_ip[6], target_ip[7]);

		bplist list;
		list.add(2, "method", bplist::STRING, "pin",
					"user", bplist::STRING, UDN);

		auto data = list.toData();
		kd_add(headers, "Server", "spotraop");
		kd_add(headers, "Connection", "keep-alive");
		kd_add(headers, "Content-Type", "application/x-apple-binary-plist");
		kd_vadd(headers, "Content-Length", "%zu", data.size());

		char* httpStr = http_send(sock, "POST /pair-setup-pin HTTP/1.1", headers);
		if (!httpStr) {
			kd_free(headers);
			closesocket(sock);
			return false;
		}
		send(sock, (const char*) data.data(), data.size(), 0);
		//printf("%s", httpStr);
		fprintf(stderr, "step1 ... verifying pin\n");
		fflush(stderr);
		NFREE(httpStr);
		kd_free(headers);

		// send the PIN code and receive a salt and public key (B)
		char* body = NULL;
#ifndef TEST_VECTOR
		if (http_parse(sock, method, resource, NULL, headers, &body, &len) && strcasestr(resource, "200")) {
			kd_free(headers);
#else
		if (1) {
			body = (char*)data.data();
			len = data.size();
#endif
			bplist ATVresp((uint8_t*)body, len);
			auto pk = ATVresp.getValueData("pk");
			auto salt = ATVresp.getValueData("salt");

			// compute M1 (proof)
			auto M1 = computeM1(pk, salt, UDN, pin);

			// send our public key A and our proof M1
			bplist clientResponse;
			std::vector<uint8_t> buffer(BN_num_bytes(A));
			BN_bn2bin(A, buffer.data());

			clientResponse.add(2, "pk", bplist::DATA, buffer.data(), buffer.size(),
								  "proof", bplist::DATA, M1.data(), M1.size());

			data = clientResponse.toData();
			kd_add(headers, "Server", "spotraop");
			kd_add(headers, "Connection", "keep-alive");
			kd_add(headers, "Content-Type", "application/x-apple-binary-plist");
			kd_vadd(headers, "Content-Length", "%zu", data.size());

			char* httpStr = http_send(sock, "POST /pair-setup-pin HTTP/1.1", headers);
			if (!httpStr) {
				kd_free(headers);
				closesocket(sock);
				return false;
			}
			send(sock, (const char*)data.data(), data.size(), 0);
			fprintf(stderr, "step2 ... verifying M1\n");
			fflush(stderr);
			//printf("%s", httpStr);
			NFREE(httpStr);
			kd_free(headers);

			// get the M2 proof (don't verify it) and sign K and a public key
#ifndef TEST_VECTOR
			if (http_parse(sock, method, resource, NULL, headers, &body, &len) && strcasestr(resource, "200")) {
				kd_free(headers);
#else
			if (1) {
#endif
				// test vectors
				// a_pub: 0ceaa63dedd87d2da05ff0bdfbd99b5734911269c70664b9a74e04ae5cdbeca7
				// aes_key: a043357cee40a9ae0731dd50859cccfb
				// aes_iv: da36ea69a94d51d881086e9080dbaef8
				// epk: 5de0f61622b0d41bc098b07f229863f49e1a1c1030908b0ec620386e089a20c4
				// tag: 3b13d2e85f00555c6a05df5cb03a2105
				// end test vectors

				// get a's public key
				uint8_t a_pub[KEYSIZE];
				BN_bn2bin(a, scratch);
				EVP_PKEY* privKey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, scratch, KEYSIZE);
				size_t size = KEYSIZE;
				EVP_PKEY_get_raw_public_key(privKey, a_pub, &size);
				EVP_PKEY_free(privKey);

				SHA512_CTX digest;
				uint8_t aesKey[16], aesIV[16];

				SHA512_Init(&digest);
				const char *feed = "Pair-Setup-AES-Key";
				SHA512_Update(&digest, feed, strlen(feed));
				SHA512_Update(&digest, K, sizeof(K));
				SHA512_Final(scratch, &digest);
				memcpy(aesKey, scratch, 16);

				SHA512_Init(&digest);
				feed = "Pair-Setup-AES-IV";
				SHA512_Update(&digest, feed, strlen(feed));
				SHA512_Update(&digest, K, sizeof(K));
				SHA512_Final(scratch, &digest);
				memcpy(aesIV, scratch, 16);
				aesIV[15]++;

				uint8_t epk[KEYSIZE], tag[KEYSIZE/2];
				int len;

				EVP_CIPHER_CTX* gcm = EVP_CIPHER_CTX_new();
				EVP_EncryptInit(gcm, EVP_aes_128_gcm(), NULL, NULL);
				EVP_CIPHER_CTX_ctrl(gcm, EVP_CTRL_GCM_SET_IVLEN, sizeof(aesIV), NULL);
				EVP_EncryptInit(gcm, NULL, aesKey, aesIV);
				EVP_EncryptUpdate(gcm, epk, &len, a_pub, sizeof(a_pub));
				EVP_EncryptFinal(gcm, NULL, &len);
				EVP_CIPHER_CTX_ctrl(gcm, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag);
				EVP_CIPHER_CTX_free(gcm);

				bplist list;
				list.add(2, "epk", bplist::DATA, epk, sizeof(epk),
							"authTag", bplist::DATA, tag, sizeof(tag));

				auto data = list.toData();
				kd_add(headers, "Server", "spotraop");
				kd_add(headers, "Connection", "keep-alive");
				kd_add(headers, "Content-Type", "application/x-apple-binary-plist");
				kd_vadd(headers, "Content-Length", "%zu", data.size());

				char* httpStr = http_send(sock, "POST /pair-setup-pin HTTP/1.1", headers);
				if (!httpStr) {
					kd_free(headers);
					closesocket(sock);
					return false;
				}
				send(sock, (const char*)data.data(), data.size(), 0);
				//printf("%s", httpStr);
				fprintf(stderr, "step3 ... verifying AES\n");
				fflush(stderr);
				NFREE(httpStr);
				kd_free(headers);

#ifndef TEST_VECTOR
				if (http_parse(sock, method, resource, NULL, headers, &body, &len) && strcasestr(resource, "200")) {
					kd_free(headers);
					auto a_hex = BN_bn2hex(a);
					*pSecret = strdup(a_hex);
					OPENSSL_free(a_hex);
#else
				if (1) {
#endif

					fprintf(stderr, "success!\nsecret is %s\n", *pSecret);
					fflush(stderr);
					success = true;
				} else {
					fprintf(stderr, "can't authentify, error %s\n", resource);
					fflush(stderr);
				}
			}
		} else {
			fprintf(stderr, "pin failed %s\n", resource);
			fflush(stderr);
		}

		NFREE(body);
	} else {
		fprintf(stderr, "device did not respond to pairing request\n");
		fflush(stderr);
	}

	if (a) BN_free(a);
	if (A) BN_free(A);

	kd_free(headers);
	if (sock != -1) closesocket(sock);
	return success;
}

} // extern "C"
