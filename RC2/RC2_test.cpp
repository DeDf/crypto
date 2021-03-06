
#include <stdio.h>
#include "RC2.h"

int main(int argc, char *argv[])  // argc 参数个数，argv[1]，argv[2]..
{
    RC2_KEY Rc2key;
    unsigned char key[] = "12345678";            // 输入密码
    RC2_set_key(&Rc2key, key, sizeof(key)-1, 0); // 初始化Rc2Key

    char a[] = "hmvenus1";                       // 这个是明文
    RC2_encrypt((unsigned long *)a, &Rc2key);    // a即是输入，也是输出，加密后密文也在a中
    RC2_decrypt((unsigned long *)a, &Rc2key);    // 解密

    char plain_text[] = "hmvenus";
    char iv[] = "\x11\x22\x33\x44\x55\x66\x77\x88";//"k\xbb\xf4""B\x18\xe9U\xd0";
    int ivLen = sizeof(iv)-1;
    unsigned char buf[200];

    RC2_cfb64_encrypt((unsigned char *)plain_text, buf, 8, &Rc2key, (unsigned char *)iv, &ivLen, RC2_ENCRYPT);

    return 0;
}