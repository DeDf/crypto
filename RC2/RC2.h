
// Ron Rivest's Cipher No.2 - RC2
//          FromOpenSSL

#pragma once

#define _In_
#define _Out_
#define _In_Out_
#define _InOpt_
#define _OutOpt_

#define RC2_DECRYPT 0
#define RC2_ENCRYPT 1

#define RC2_INT unsigned int

#define c2l(c,l)	(l =((unsigned long)(*((c)++)))     , \
                     l|=((unsigned long)(*((c)++)))<< 8L, \
                     l|=((unsigned long)(*((c)++)))<<16L, \
                     l|=((unsigned long)(*((c)++)))<<24L)

#define l2c(l,c)	(*((c)++)=(unsigned char)(((l)     )&0xff), \
                     *((c)++)=(unsigned char)(((l)>> 8L)&0xff), \
                     *((c)++)=(unsigned char)(((l)>>16L)&0xff), \
                     *((c)++)=(unsigned char)(((l)>>24L)&0xff))

typedef struct rc2_key_st
{
    RC2_INT data[64];
} RC2_KEY;

// 
// 使用用户指定的Key初始化Rc2Key.
// Rc2Key为Rc2算法内部使用，Key为用户指定的key，KenLen为Key的长度(Bytes), bits默认置0
//
void RC2_set_key(_Out_ RC2_KEY *Rc2Key, const unsigned char *Key, int KeyLen, _InOpt_ int bits);
//
// 需要先调用RC2_set_key()初始化Rc2Key
// 第一个参数必须包含2个DWORD，每次只处理2个DWORD;
// 加密的结果也是2个DWORD，存放在第一个参数指向的2个DWORD中.
//
void RC2_encrypt(_In_Out_ unsigned long *d, RC2_KEY *Rc2Key);
void RC2_decrypt(_In_Out_ unsigned long *d, RC2_KEY *Rc2Key);

void RC2_cfb64_encrypt(const unsigned char *in, unsigned char *out,
                       long length, RC2_KEY *Rc2Key, unsigned char *ivec,
                       int *num, int encrypt);
