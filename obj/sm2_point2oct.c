/*#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <linux/limits.h>
#include <features.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include "openssl/bn.h"
*/
#include "autoc.h"


/*
void print_hex(const char *pTitle, const char *pSendBuff, int SendLen)
{
    int i;
    printf("%s ---> (%d)(%d): [", pTitle, SendLen, SendLen);
    for(i = 0; i < SendLen; i ++) 
    {
        printf("%02X", pSendBuff[i]);
    }
    
    printf("]\r\n");
}
*/
void print_hex(const char *pTitle, const char *pSendBuff, int SendLen)
{
	int str_len;
	unsigned char outstr[4096]={0};
	str_len=AscString2HexString((unsigned char *)pSendBuff,SendLen,outstr);
	printf("[%s]---->str_len=[%d],out = [ %s ]\n",pTitle,str_len,outstr);
}


void print_bn(char *pchT, BIGNUM* pBG_p)
{
	unsigned char aucY[1024+1] = {0};
	int iYLen = 0;
	
	iYLen = BN_bn2bin ( pBG_p, aucY);
	print_hex(pchT, aucY, iYLen);
}

/**********************************************************************************************//**
*  @fn       void sm2_point_ini(void);
*  @brief    点压缩算法的初始化
*  
*  @param   [io] void
*  @return   - void
*            -
*  @bug    (bug修复的描述问题)
*            - 1.
*            - 2.
***************************************************************************************************/

/**********************************************************************************************//**
	p=FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
	a=FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
	b=28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
	n=FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
	Gx=32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
	Gy=BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0

	A.5.2 Fp上椭圆曲线点的压缩与解压缩方法
	设P=(xP, yP)是定义在Fp上椭圆曲线E：y2 = x3 +ax+b上的一个点，˜yP为yP的最右边的一个比特，
	则点P可由xP和比特˜yP 表示。
	由xP和˜yP恢复yP的方法如下：
	a) 计算域元素α=(xP^3+aXp+b) modp；
	b) 计算α modp的平方根β(参见附录B.1.4)，若输出是“不存在平方根”，则报错；
	c) 若β的最右边比特等于˜yP，则置yP=β；否则置yP = p−β。

***************************************************************************************************/
void sm2_point2oct (unsigned char ucType, unsigned char* pucInX, unsigned char* pucOutXY )
{
/*	unsigned char* puc_p= "\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
	unsigned char* puc_a= "\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFC";
	unsigned char* puc_b= "\x28\xE9\xFA\x9E\x9D\x9F\x5E\x34\x4D\x5A\x9E\x4B\xCF\x65\x09\xA7\xF3\x97\x89\xF5\x15\xAB\x8F\x92\xDD\xBC\xBD\x41\x4D\x94\x0E\x93";
	unsigned char* puc_n= "\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x72\x03\xDF\x6B\x21\xC6\x05\x2B\x53\xBB\xF4\x09\x39\xD5\x41\x23";
	unsigned char* puc_Gx= "\x32\xC4\xAE\x2C\x1F\x19\x81\x19\x5F\x99\x04\x46\x6A\x39\xC9\x94\x8F\xE3\x0B\xBF\xF2\x66\x0B\xE1\x71\x5A\x45\x89\x33\x4C\x74\xC7";
	unsigned char* puc_Gy= "\xBC\x37\x36\xA2\xF4\xF6\x77\x9C\x59\xBD\xCE\xE3\x6B\x69\x21\x53\xD0\xA9\x87\x7C\xC6\x2A\x47\x40\x02\xDF\x32\xE5\x21\x39\xF0\xA0";
*/
	unsigned char puc_p[32]={0};
	unsigned char puc_a[32]={0};
	unsigned char puc_b[32]={0};
	unsigned char puc_n[32]={0};
	unsigned char puc_Gx[32]={0};
	unsigned char puc_Gy[32]={0};

	BIGNUM* g_pBG_p;
	BIGNUM* g_pBG_a;
	BIGNUM* g_pBG_b;
	BIGNUM* g_pBG_n;
	BIGNUM* g_pBG_Gx;
	BIGNUM* g_pBG_Gy;
	BIGNUM* g_pBGXp;
	BIGNUM* g_pBGX3;
	BIGNUM* g_pBGX;
	BIGNUM* g_pBGY;
	BIGNUM* g_pR;
	BIGNUM* g_pTemp;
	BN_CTX *ctx;

	g_pBG_p = BN_new();
	g_pBG_a = BN_new();
	g_pBG_b = BN_new();
	g_pBG_n = BN_new();
	g_pBG_Gx = BN_new();
	g_pBG_Gy = BN_new();
	g_pBGXp = BN_new();
	g_pBGX3 = BN_new();
	g_pBGX = BN_new();
	g_pBGY = BN_new();
	g_pR = BN_new();
	g_pTemp = BN_new();
	ctx = BN_CTX_new();

	HexStringToAsc(_P,puc_p);
	HexStringToAsc(_a,puc_a);
	HexStringToAsc(_b,puc_b);
	HexStringToAsc(_n,puc_n);
	HexStringToAsc(_Gx,puc_Gx);
	HexStringToAsc(_Gy,puc_Gy);


	unsigned char aucY[64+1] = {0};
	int iYLen = 0;
	int y_bit = 0;
	
	y_bit = ucType & 1;

	g_pBG_p = BN_bin2bn( puc_p, 32, NULL );
//	print_bn("g_pBG_p", g_pBG_p);
	g_pBG_a = BN_bin2bn( puc_a, 32, NULL );
	g_pBG_b = BN_bin2bn( puc_b, 32, NULL );
	g_pBG_n = BN_bin2bn( puc_n, 32, NULL );
	g_pBG_Gx = BN_bin2bn( puc_Gx, 32, NULL );
	g_pBG_Gy = BN_bin2bn( puc_Gy, 32, NULL );
//	print_bn("g_pBG_Gy", g_pBG_Gy);

	BN_clear(g_pBGXp);
	BN_clear(g_pBGX3);
	BN_clear(g_pBGX);
	BN_clear(g_pBGY);
	BN_clear(g_pR);
	BN_clear(g_pTemp);

	g_pBGXp = BN_bin2bn( pucInX, 32, NULL );
	
	BN_sqr(g_pR, g_pBGXp, ctx); 
	BN_mul(g_pBGX3, g_pR, g_pBGXp, ctx);
	//print_bn("g_pBGX3", g_pBGX3);

	BN_mul(g_pR, g_pBG_a, g_pBGXp, ctx);
	//print_bn("aXp", g_pR);

	BN_add(g_pR, g_pR, g_pBGX3);
	BN_add(g_pTemp, g_pBG_b, g_pR);
	//print_bn("Xp^3+aXp+b ", g_pTemp);
	
	BN_mod(g_pR, g_pTemp, g_pBG_p, ctx);
	//print_bn("α = temp modp", g_pR);
	
	BN_mod_sqrt ( g_pTemp, g_pR, g_pBG_p, ctx );
	print_bn("β", g_pTemp);

	if ( y_bit != BN_is_odd ( g_pTemp ) )
	{
		BN_usub( g_pBGY, g_pBG_p, g_pTemp );
		print_bn("Y=p−β", g_pBGY);
		iYLen = BN_bn2bin(g_pBGY, aucY);
	}
	else
	{
		//print_bn("β", g_pTemp);
		iYLen = BN_bn2bin(g_pTemp, aucY);
	}

	
	memcpy(pucOutXY, pucInX, 32);
	memcpy(pucOutXY+32, aucY, 32);
	//print_hex("Y", aucY, iYLen);
	print_hex("XY", pucOutXY, iYLen*2);



	BN_free(g_pBG_p);
	BN_free(g_pBG_a);
	BN_free(g_pBG_b);
	BN_free(g_pBG_n);
	BN_free(g_pBG_Gx);
	BN_free(g_pBG_Gy);
	BN_free(g_pBGXp);
	BN_free(g_pBGX3);
	BN_free(g_pBGX);
	BN_free(g_pBGY);
	BN_free(g_pR);
	BN_free(g_pTemp);
	//BN_CTX_end(ctx);
	BN_CTX_free(ctx);

}

//input :ucType=x[0];pucInX=&x[1];output :pucOutXY=y;//lenth is 1,32,32;checked by wel in 20190528
int untar_x_to_y(const char* ucType, const char* pucInX, unsigned char* pucOutXY)
{
	unsigned char InXoutstr[32]={0};

	int str_len;
	unsigned char type=0;
	//printf("atoi(Type)=[%d]\n",atoi(ucType));
	if(compressy0==atoi(ucType))
		type=0;
	else if(compressy1==atoi(ucType))
		type=1;
	else
	{
		printf("Uncompress type [%d] error!\n",atoi(ucType));
		return 0;
	}

	str_len=HexStringToAsc(pucInX,InXoutstr);
	if(32!=str_len)
	{
		printf("Publickey X length=[%d],error!\n",str_len);
		return 0;
	}
	sm2_point2oct(type, InXoutstr, pucOutXY);

	return 1;
}

