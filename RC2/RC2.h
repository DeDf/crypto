
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
// ʹ���û�ָ����Key��ʼ��Rc2Key.
// Rc2KeyΪRc2�㷨�ڲ�ʹ�ã�KeyΪ�û�ָ����key��KenLenΪKey�ĳ���(Bytes), bitsĬ����0
//
void RC2_set_key(_Out_ RC2_KEY *Rc2Key, const unsigned char *Key, int KeyLen, _InOpt_ int bits);
//
// ��Ҫ�ȵ���RC2_set_key()��ʼ��Rc2Key
// ��һ�������������2��DWORD��ÿ��ֻ����2��DWORD;
// ���ܵĽ��Ҳ��2��DWORD������ڵ�һ������ָ���2��DWORD��.
//
void RC2_encrypt(_In_Out_ unsigned long *d, RC2_KEY *Rc2Key);
void RC2_decrypt(_In_Out_ unsigned long *d, RC2_KEY *Rc2Key);

void RC2_cfb64_encrypt(const unsigned char *in, unsigned char *out,
                       long length, RC2_KEY *Rc2Key, unsigned char *ivec,
                       int *num, int encrypt);
