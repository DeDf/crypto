
#include <stdio.h>
#include <windows.h>
#include "aes.h"
#include "md5.h"

unsigned char key[32];
unsigned char iv[16];

typedef void (*block128_f)(const unsigned char *in, unsigned char *out,
                         const AES_KEY *key);

// CFB128，128是指AES算法是以128bit为单元处理数据的，与密钥位数无关！
void CRYPTO_cfb128_encrypt(const unsigned char *in, unsigned char *out,
                           size_t len, AES_KEY *key,
                           unsigned char iv[16], int *num,
                           int enc, block128_f block)
{
    unsigned int n;
    size_t l = 0;

    n = *num;
    if (enc) {
        while (l<len) {
            if (n == 0) {
                (*block)(iv, iv, key);
            }
            out[l] = iv[n] ^= in[l];
            ++l;
            n = (n+1) % 16;
        }
        *num = n;
    }
    else {
        while (l<len) {
            unsigned char c;
            if (n == 0) {
                (*block)(iv, iv, key);
            }
            out[l] = iv[n] ^ (c = in[l]); iv[n] = c;
            ++l;
            n = (n+1) % 16;
        }
        *num=n;
    }
}


int MakeKey(unsigned char *password)
{
    int i;
    //
    MD5_CTX mdContext;
    MD5Init (&mdContext);
    MD5Update (&mdContext, password, 6);
    MD5Final (&mdContext);

    printf("key=");
    for(i=0; i<16; i++)
    {
        key[i] = mdContext.digest[i];
        printf("%02X", mdContext.digest[i]);
    }

    MD5Init (&mdContext);
    MD5Update (&mdContext, key, 16);
    MD5Update (&mdContext, password, 6);
    MD5Final (&mdContext);

    for(i=16; i<32; i++)
    {
        key[i] = mdContext.digest[i-16];
        printf("%02X", mdContext.digest[i-16]);
    }
    printf("\n");

    MD5Init (&mdContext);
    MD5Update (&mdContext, &key[16], 16);
    MD5Update (&mdContext, password, 6);
    MD5Final (&mdContext);
    //
    printf("iv =");
    for(i=0; i<16; i++)
    {
        iv[i] = mdContext.digest[i];
        printf("%02X", mdContext.digest[i]);
    }
    printf("\n");

    return 0;
}

int main()
{
    AES_KEY AESkey;
    unsigned char buf[16];
    unsigned char t_iv[16];
    int num = 0;

    memcpy(buf, "12345678abcdefgh", 16);
    MakeKey((unsigned char *)"fengzi");

    private_AES_set_encrypt_key(key, 256, &AESkey); // 初始化Rc2Key

    memcpy(t_iv, iv, 16);
    CRYPTO_cfb128_encrypt(  // 加密
        buf,
        buf,
        16,
        &AESkey,
        t_iv,
        &num,
        1,
        &AES_encrypt);

    memcpy(t_iv, iv, 16);
    CRYPTO_cfb128_encrypt(  // 解密(也用AES_encrypt函数，要用原始IV)
        buf,
        buf,
        16,
        &AESkey,
        t_iv,
        &num,
        1,
        &AES_encrypt);

    return 0;
}