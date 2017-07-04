
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "md5.h"

char *MD5_file (char *path, int md5_len)
{
    FILE *fp = fopen (path, "rb");
    MD5_CTX mdContext;
    int bytes;
    unsigned char data[1024];
    char *file_md5;
    int i;
    if (fp == NULL) {
        fprintf (stderr, "fopen %s failed\n", path);
        return NULL;
    }
    MD5Init (&mdContext);
    while ((bytes = fread (data, 1, 1024, fp)) != 0)
    {
        MD5Update (&mdContext, data, bytes);
    }
    MD5Final (&mdContext);

    file_md5 = (char *)malloc((md5_len + 1) * sizeof(char));
    if(file_md5 == NULL)
    {
        fprintf(stderr, "malloc failed.\n");
        return NULL;
    }
    memset(file_md5, 0, (md5_len + 1));

    if(md5_len == 16)
    {
        for(i=4; i<12; i++)
        {
            sprintf(&file_md5[(i-4)*2], "%02x", mdContext.digest[i]);
        }
    }
    else if(md5_len == 32)
    {
        for(i=0; i<16; i++)
        {
            sprintf(&file_md5[i*2], "%02x", mdContext.digest[i]);
        }
    }
    else
    {
        fclose(fp);
        free(file_md5);
        return NULL;
    }

    fclose (fp);
    return file_md5;
}

int main(int argc, char *argv[])
{
//     char *md5;
//
//     md5 = MD5_file("d:\\p\\1\\objchk_wxp_x86\\i386\\1.sys", 16);
//     printf("16: %s\n", md5);
//     free(md5);
//
//     md5 = MD5_file("d:\\p\\1\\objchk_wxp_x86\\i386\\1.sys", 32);
//     printf("32: %s\n", md5);
//     free(md5);

    unsigned char key[32];
    unsigned char iv[16];
    int i;
    //
    MD5_CTX mdContext;
    MD5Init (&mdContext);
    MD5Update (&mdContext, "fengzi", 6);
    MD5Final (&mdContext);  // 前16字节！

    printf("key=");
    for(i=0; i<16; i++)
    {
        key[i] = mdContext.digest[i];
        printf("%02X", mdContext.digest[i]);
    }

    MD5Init (&mdContext);
    MD5Update (&mdContext, key, 16);
    MD5Update (&mdContext, "fengzi", 6);
    MD5Final (&mdContext);  // 后16字节!
    
    for(i=16; i<32; i++)
    {
        key[i] = mdContext.digest[i-16];
        printf("%02X", mdContext.digest[i-16]);
    }
    printf("\n");

    MD5Init (&mdContext);
    MD5Update (&mdContext, &key[16], 16);
    MD5Update (&mdContext, "fengzi", 6);
    MD5Final (&mdContext);

    printf("iv =");
    for(i=0; i<16; i++)
    {
        iv[i] = mdContext.digest[i];
        printf("%02X", mdContext.digest[i]);
    }
    printf("\n");

    getchar();
    return 0;
}
