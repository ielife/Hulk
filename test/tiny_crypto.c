/**
 * \file tiny_crypto.c
 *
 * \brief 本文件提供了一些加解密的接口函数和使用例程，基于mbedtls-2.16.0实现.
 *
 * \author kuili eabi010@gmail.com
 * \data 2019/1/4
 * \version V1.0
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "mbedtls/rsa.h"
#include "mbedtls/rsa_internal.h"
#include "mbedtls/md2.h"
#include "mbedtls/md4.h"
#include "mbedtls/md5.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/base64.h"
#include "mbedtls/md5.h"

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n,b,i)                            \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif

typedef struct
{
    uint32_t key[16];
    uint32_t v0, v1;
} rnd_pseudo_info;

static int rnd_std_rand( void *rng_state, unsigned char *output, size_t len )
{
#if !defined(__OpenBSD__)
    size_t i;

    if( rng_state != NULL )
        rng_state  = NULL;

    for( i = 0; i < len; ++i )
        output[i] = rand();
#else
    if( rng_state != NULL )
        rng_state = NULL;

    arc4random_buf( output, len );
#endif /* !OpenBSD */

    return( 0 );
}

static int rnd_pseudo_rand( void *rng_state, unsigned char *output, size_t len )
{
    rnd_pseudo_info *info = (rnd_pseudo_info *) rng_state;
    uint32_t i, *k, sum, delta=0x9E3779B9;
    unsigned char result[4], *out = output;

    if( rng_state == NULL )
        return( rnd_std_rand( NULL, output, len ) );

    k = info->key;

    while( len > 0 )
    {
        size_t use_len = ( len > 4 ) ? 4 : len;
        sum = 0;

        for( i = 0; i < 32; i++ )
        {
            info->v0 += ( ( ( info->v1 << 4 ) ^ ( info->v1 >> 5 ) )
                            + info->v1 ) ^ ( sum + k[sum & 3] );
            sum += delta;
            info->v1 += ( ( ( info->v0 << 4 ) ^ ( info->v0 >> 5 ) )
                            + info->v0 ) ^ ( sum + k[( sum>>11 ) & 3] );
        }

        PUT_UINT32_BE( info->v0, result, 0 );
        memcpy( out, result, use_len );
        len -= use_len;
        out += 4;
    }

    return( 0 );
}

static void hexdump(unsigned char *buf, int len) {
  int i;

  if (NULL == buf) return;
  for(i=0; i<len; i++){
    printf("%02X",buf[i]);
  }
  printf("\n");
}

/// rsa interface
/**
 * \brief   RSA密钥信息结构体.
 */
typedef struct tiny_rsa_key
{
	char N[1024];
	char E[1024];
	char P[1024];
	char Q[1024];
}tiny_rsa_key_t;

/**
 * \brief          构建rsa句柄.
 *
 * \param handle   rsa句柄指针.
 *
 * \return         \c 0 if successful.
 */
int tiny_rsa_init(void **handle)
{
	mbedtls_rsa_context *prsa_ctx = NULL;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;

	if (NULL == handle) return -1;
	prsa_ctx = (mbedtls_rsa_context *)malloc(sizeof(mbedtls_rsa_context));
	if (NULL == prsa_ctx) return -1;

	mbedtls_rsa_init ( prsa_ctx, 0, 0 );
	*handle = prsa_ctx;

	return 0;
}

/**
 * \brief          rsa私钥公钥生成器.
 *
 * \param handle   rsa句柄.
 * \param nrbits   公钥的bit长度，接口支持1024bit.
 * \param exponent 算法指数，必须是比1大的奇数.
 * \param pers 	   用于随机种子.
 * \param keysets  存放密钥集合.
 *
 * \return         \c 0 if successful.
 */
int tiny_rsa_gen_key(void *handle, int nrbits, int exponent, const char *pers, tiny_rsa_key_t *keysets)
{
	size_t olen;
	mbedtls_rsa_context *prsa_ctx = handle;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	if (NULL == prsa_ctx) return -1;

	mbedtls_ctr_drbg_init( &ctr_drbg );
	mbedtls_entropy_init( &entropy );
	mbedtls_rsa_init ( prsa_ctx, 0, 0 );

	assert( mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func,
				&entropy, (const unsigned char *) pers,
				strlen( pers ) ) == 0 );
	assert( mbedtls_rsa_gen_key( prsa_ctx, mbedtls_ctr_drbg_random, &ctr_drbg, nrbits, exponent ) == 0 );
	assert( mbedtls_rsa_check_privkey( prsa_ctx ) == 0 );
	assert( mbedtls_mpi_cmp_mpi( &prsa_ctx->P, &prsa_ctx->Q ) > 0 );

	memset(keysets, 0, sizeof(tiny_rsa_key_t));
    assert( mbedtls_mpi_write_string( &prsa_ctx->N, 16, keysets->N, sizeof(keysets->N), &olen) == 0 );
    assert( mbedtls_mpi_write_string( &prsa_ctx->E, 16, keysets->E, sizeof(keysets->E), &olen) == 0 );
    assert( mbedtls_mpi_write_string( &prsa_ctx->P, 16, keysets->P, sizeof(keysets->P), &olen) == 0 );
    assert( mbedtls_mpi_write_string( &prsa_ctx->Q, 16, keysets->Q, sizeof(keysets->Q), &olen) == 0 );

	return 0;
}

/**
 * \brief          rsa pkcs1加密.
 *
 * \param output   密文.
 * \param out_len  密文 \p output 的长度.
 * \param msg  	   输入文本.
 * \param msg_len  文本 \p msg 的长度.
 * \param str_N    公钥.
 * \param str_E    公钥指数.
 * \param key_type 公钥或者私钥加密.
 *
 * \return         \c 0 if successful.
 */
int tiny_rsa_pkcs1_encrypt(unsigned char *output, size_t *out_len, 
	const unsigned char *msg, size_t msg_len, char *str_N, char *str_E, int key_type)
{
    mbedtls_rsa_context ctx;
    rnd_pseudo_info rnd_info;

    mbedtls_mpi N, E;
    mbedtls_mpi_init( &N ); mbedtls_mpi_init( &E );

    memset( &rnd_info, 0, sizeof( rnd_pseudo_info ) );

    mbedtls_rsa_init( &ctx, MBEDTLS_RSA_PKCS_V15, 0 );
    memset( output, 0x00, 1000 );

    assert( mbedtls_mpi_read_string( &N, 16, str_N ) == 0 );
    assert( mbedtls_mpi_read_string( &E, 16, str_E ) == 0 );

    assert( mbedtls_rsa_import( &ctx, &N, NULL, NULL, NULL, &E ) == 0 );
    assert( mbedtls_rsa_get_len( &ctx ) == (size_t) ( 1024 / 8 ) );
    assert( mbedtls_rsa_check_pubkey( &ctx ) == 0 );

    assert( mbedtls_rsa_pkcs1_encrypt( &ctx, &rnd_pseudo_rand, &rnd_info,
                                            key_type, msg_len,
                                            msg, output ) == 0 );
    *out_len = ctx.len;
    //assert( hexcmp( output, result_hex_str->x, ctx.len, result_hex_str->len ) == 0 );

    mbedtls_mpi_free( &N ); mbedtls_mpi_free( &E );
    mbedtls_rsa_free( &ctx );

    return 0;
}

/**
 * \brief          rsa pkcs1解密.
 *
 * \param output   输出文本.
 * \param out_len  文本 \p output 的长度.
 * \param msg  	   输入密文.
 * \param msg_len  密文 \p msg 的长度.
 * \param str_N    公钥.
 * \param str_E    公钥指数.
 * \param str_P    由公钥导出私钥的第一个因子.
 * \param str_Q    由公钥导出私钥的第二个因子.
 * \param key_type 公钥或者私钥加密.
 *
 * \return         \c 0 if successful.
 */
int tiny_rsa_pkcs1_decrypt(unsigned char *output, size_t *out_len, 
	const unsigned char *msg, size_t msg_len, 
	char *str_N, char *str_E, char *str_P, char *str_Q, int key_type)
{
    mbedtls_rsa_context ctx;
    rnd_pseudo_info rnd_info;
    mbedtls_mpi N, P, Q, E;

    mbedtls_mpi_init( &N ); mbedtls_mpi_init( &P );
    mbedtls_mpi_init( &Q ); mbedtls_mpi_init( &E );

    mbedtls_rsa_init( &ctx, MBEDTLS_RSA_PKCS_V15, 0 );

    memset( &rnd_info, 0, sizeof( rnd_pseudo_info ) );

    assert( mbedtls_mpi_read_string( &P, 16, str_P ) == 0 );
    assert( mbedtls_mpi_read_string( &Q, 16, str_Q ) == 0 );
    assert( mbedtls_mpi_read_string( &N, 16, str_N ) == 0 );
    assert( mbedtls_mpi_read_string( &E, 16, str_E ) == 0 );

    assert( mbedtls_rsa_import( &ctx, &N, &P, &Q, NULL, &E ) == 0 );
    assert( mbedtls_rsa_get_len( &ctx ) == (size_t) ( 1024 / 8 ) );
    assert( mbedtls_rsa_complete( &ctx ) == 0 );
    assert( mbedtls_rsa_check_privkey( &ctx ) == 0 );

    size_t writen_len = 0;

    int ret = mbedtls_rsa_pkcs1_decrypt( &ctx, rnd_pseudo_rand, &rnd_info, key_type, &writen_len, msg, output, *out_len );
    if (0 == ret) *out_len = writen_len;

    mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P );
    mbedtls_mpi_free( &Q ); mbedtls_mpi_free( &E );
    mbedtls_rsa_free( &ctx );

    return ret;
}
/**
 * \brief          rsa对象注销.
 *
 * \param handle   rsa句柄.
 *
 */
void tiny_rsa_free(void *rsa_handle)
{
	if (rsa_handle) {
		mbedtls_rsa_free(rsa_handle);
		free(rsa_handle);
	}
}

/// aes interface
/**
 * \brief          aes对象初始化.
 *
 * \param handle   aes句柄指针.
 *
 * \return         \c 0 if successful.
 */
int tiny_aes_init(void **handle)
{
	if (NULL == handle) return -1;

	mbedtls_aes_context *paes_ctx = NULL;
	paes_ctx = (mbedtls_aes_context *)malloc(sizeof(mbedtls_aes_context));
	if (NULL == paes_ctx) return -1;

	mbedtls_aes_init(paes_ctx);

	*handle = paes_ctx;

	return 0;
}
/**
 * \brief          aes加密.
 *
 * \param handle   aes句柄.
 * \param key      加密key.
 * \param keybits  \p key 的bit长度.
 * \param msg      加密消息内容.
 * \param msg_len  加密消息 \p msg 的长度.
 * \param vector   加密初始化向量.
 * \param output   密文.
 *
 * \return         \c 0 if successful.
 */
int tiny_aes_encrypt(void *handle, const unsigned char *key, int keybits, 
	const unsigned char *msg, size_t msg_len, unsigned char *vector, unsigned char *output)
{
	mbedtls_aes_context *paes_ctx = (mbedtls_aes_context *)handle;
	if (NULL == paes_ctx) return -1;

	int i;
	unsigned char input[16];
	int count = msg_len / 16;
	int last = msg_len % 16;

	for (i = 0; i < count; i++) {
		memcpy(input, msg+i*16, 16);
		mbedtls_aes_setkey_enc(paes_ctx, key, keybits);
		mbedtls_aes_crypt_cbc(paes_ctx, MBEDTLS_AES_ENCRYPT, 16, vector, input, output+i*16);
	}
	if (0 != last) {
		int padding_value = 16 - last;
		memcpy(input, msg+i*16, last);
		memset(input+last, padding_value, padding_value);
		mbedtls_aes_setkey_enc(paes_ctx, key, keybits);
		mbedtls_aes_crypt_cbc(paes_ctx, MBEDTLS_AES_ENCRYPT, 16, vector, input, output+i*16);
	}

	return 0;

	//mbedtls_aes_setkey_enc(paes_ctx, key, keybits);
	//return mbedtls_aes_crypt_cbc(paes_ctx, MBEDTLS_AES_ENCRYPT, msg_len, vector, msg, output);
}
/**
 * \brief          aes解密.
 *
 * \param handle   aes句柄.
 * \param key      解密key.
 * \param keybits  \p key 的bit长度.
 * \param msg      密文内容.
 * \param msg_len  密文 \p msg 的长度.
 * \param vector   解密初始化向量.
 * \param output   解密后的数据.
 *
 * \return         \c 0 if successful.
 */
int tiny_aes_decrypt(void *handle, const unsigned char *key, int keybits, const unsigned char *msg, size_t msg_len, unsigned char *vector, unsigned char *output)
{
	mbedtls_aes_context *paes_ctx = (mbedtls_aes_context *)handle;
	if (NULL == paes_ctx) return -1;

	int i;
	unsigned char input[16];
	int count = msg_len / 16;
	int last = msg_len % 16;

	for (i = 0; i < count; i++) {
		memcpy(input, msg+i*16, 16);
		mbedtls_aes_setkey_dec(paes_ctx, key, keybits);
		mbedtls_aes_crypt_cbc(paes_ctx, MBEDTLS_AES_DECRYPT, 16, vector, input, output+i*16);
	}

	return 0;

	//mbedtls_aes_setkey_dec(paes_ctx, key, keybits);
	//return mbedtls_aes_crypt_cbc(paes_ctx, MBEDTLS_AES_DECRYPT, message_len, vector, message, output);
}
/**
 * \brief          aes对象注销.
 *
 * \param handle   aes句柄.
 *
 */
void tiny_aes_free(void *aes_handle)
{
	if (aes_handle) {
		mbedtls_aes_free(aes_handle);
		free(aes_handle);
	}
}

/// md5 interface
/**
 * \brief          md5加密.
 *
 * \param input    输入input.
 * \param len      输入 \p input 的长度.
 * \param output   输出output, 占用32字节+1字节字符串结尾，输出格式为hex.
 *
 * \return         \c 0 if successful.
 */
int tiny_md5(const unsigned char *input, size_t len, unsigned char *output)
{
	int i;
	const unsigned char *md5_input = input;
	size_t md5_len = len;
	unsigned char md5_output[16];

	if (NULL == input || NULL == output) return -1;

	mbedtls_md5_context md5_ctx;
	mbedtls_md5_init(&md5_ctx);
	mbedtls_md5(md5_input, md5_len, md5_output);
	for (i = 0; i < 16; i++) {
		sprintf(output+i*2, "%02x", md5_output[i]);
	}
	output[i*2] = '\0';
	mbedtls_md5_free(&md5_ctx);

	return 0;
}

/// base64 interface
/**
 * \brief          对数据执行base64编码.
 *
 * \param src      输入buffer.
 * \param src_len  输入buffer的长度.
 * \param dst      输出buffer.
 * \param dst_len  输出 \p dst 的长度指针.
 * \param olen     The address at which to store the length of the string
 *                 written, including the  final \c NULL byte. This must
 *                 not be \c NULL.
 *
 * \note           dst为内部申请空间，外部注意释放.
 *
 * \return         \c 0 if successful.
 */
int tiny_base64_encode(const unsigned char *src, size_t src_len, unsigned char **dst, size_t *dst_len)
{
	int ret;
	size_t writen_len;
	if ( NULL == dst || NULL == dst_len ) return -1;
	
	mbedtls_base64_encode(NULL, 0, &writen_len, src, src_len);
	*dst = (unsigned char *)malloc(writen_len);
	if (NULL == *dst) return -1;
	*dst_len = writen_len;

	ret = mbedtls_base64_encode(*dst, *dst_len, &writen_len, src, src_len);
	*dst_len = writen_len;

	return 0;
}

/**
 * \brief          对数据执行base64解码.
 *
 * \param src      输入buffer.
 * \param src_len  输入buffer的长度.
 * \param dst      输出buffer.
 * \param dst_len  输出 \p dst 的长度指针.
 * \param olen     The address at which to store the length of the string
 *                 written, including the  final \c NULL byte. This must
 *                 not be \c NULL.
 *
 * \note           dst为内部申请空间，外部注意释放.
 *
 * \return         \c 0 if successful.
 */
int tiny_base64_decode(const unsigned char *src, size_t src_len, unsigned char **dst, size_t *dst_len)
{
	int ret;
	size_t writen_len;
	if ( NULL == dst || NULL == dst_len ) return -1;
	
	mbedtls_base64_decode(NULL, 0, &writen_len, src, src_len);
	*dst = (unsigned char *)malloc(writen_len);
	if (NULL == *dst) return -1;

	*dst_len = writen_len;

	ret = mbedtls_base64_decode(*dst, *dst_len, &writen_len, src, src_len);
	*dst_len = writen_len;
	return 0;
}

static void base64_interface_test()
{
	int ret;
	unsigned char *msg = "1234567890abcdef1234567890abcdef1234567890abcdef";
	size_t msg_len = strlen(msg);
	unsigned char *encode_buffer = NULL;
	unsigned char *decode_buffer = NULL;
	size_t encode_buffer_len, decode_buffer_len;

	do {

		// test for encode
		ret = tiny_base64_encode(msg, msg_len, &encode_buffer, &encode_buffer_len);
		//printf("base64_encode ret:%d\n", ret);

		// test for decode
		//printf("decode_len:%d\n", decode_len);
		ret = tiny_base64_decode(encode_buffer, encode_buffer_len, &decode_buffer, &decode_buffer_len);

	} while(0);
	
	printf("base64 src:%s\n", msg);
	printf("base64 enc:%s\n", encode_buffer);
	printf("base64 dec:%s\n", decode_buffer);

	if (encode_buffer) free(encode_buffer);
	if (decode_buffer) free(decode_buffer);
}

static void md5_interface_test()
{
	unsigned char *input = "jdfljablnlaskdjfpowerjsldkfjskjdhghweifhwefh";
	size_t input_len = strlen(input);
	unsigned char output[33] = {0};
	tiny_md5(input, input_len, output);
	printf("md5_test src:%s\n", input);
	printf("md5_test dst:%s\n", output);
}

static void aes_interface_test()
{
	void *aes_handle = NULL;
	unsigned char *aes_key = "1234567890abcdef";
	unsigned char *aes_msg = "111111111111111122222222222222223333333333333333222222";
	unsigned char iv[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
	unsigned char iv2[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
	size_t aes_len = strlen(aes_msg);

	int output_len = (aes_len/16+1)*16;
	unsigned char *aes_enc_output = (unsigned char*)malloc(output_len);
	unsigned char *aes_dec_output = (unsigned char*)malloc(output_len);

	tiny_aes_init(&aes_handle);
	tiny_aes_encrypt(aes_handle, aes_key, 128, aes_msg, aes_len, iv, aes_enc_output);
	tiny_aes_decrypt(aes_handle, aes_key, 128, aes_enc_output, output_len, iv2, aes_dec_output);

	printf("aes src:");
	hexdump(aes_msg, aes_len);
	printf("aes enc:");
	hexdump(aes_enc_output, output_len);
	printf("aes dec:");
	hexdump(aes_dec_output, output_len);

	tiny_aes_free(aes_handle);

	free(aes_dec_output);
	free(aes_enc_output);
}

static void rsa_interface_test()
{
	void *rsa_handle = NULL;
	unsigned char public_key[1024];
	unsigned char private_key[1024];
	size_t public_key_len = 1024;
	size_t private_key_len = 1024;
	const char *pers = "this is a random seed for gen rsa key";
	const unsigned char *message = "hello rsa";
	unsigned char enc_output[1000] = {0};
	size_t enc_output_len = 1000;
	unsigned char dec_output[1000] = {0};
	size_t dec_output_len = 1000;
	tiny_rsa_key_t keysets;

	tiny_rsa_init(&rsa_handle);
	tiny_rsa_gen_key(rsa_handle, 1024, 55555, pers, &keysets);
	tiny_rsa_free(rsa_handle);

	//printf("N:%s\n", keysets.N);
	//printf("E:%s\n", keysets.E);
	//printf("P:%s\n", keysets.P);
	//printf("Q:%s\n", keysets.Q);

	printf("rsa src:%s\n", message);
	tiny_rsa_pkcs1_encrypt(enc_output, &enc_output_len, message, strlen(message), keysets.N, keysets.E, MBEDTLS_RSA_PUBLIC);
	printf("rsa enc:");
	hexdump(enc_output, enc_output_len);
	tiny_rsa_pkcs1_decrypt(dec_output, &dec_output_len, enc_output, enc_output_len, 
		keysets.N, keysets.E, keysets.P, keysets.Q, MBEDTLS_RSA_PRIVATE);
	printf("rsa dec:%s\n", dec_output);
}

int main(int argc, char *argv[])
{
	rsa_interface_test();
	aes_interface_test();
	md5_interface_test();
	base64_interface_test();

	return 0;
}
