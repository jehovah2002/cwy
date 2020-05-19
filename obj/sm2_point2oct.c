#include "common.h"
#include "sm2_point2oct.h"


/**********************************************************************************************//**
	p=FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
	a=FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
	b=28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
	n=FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
	Gx=32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
	Gy=BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0

	Compression and decompression of elliptic curve points on Fp:
	Set P = (xP, yP) is to define the elliptic curve on the Fp E: y2 = a point on the x3 + ax + b, ˜ yP for yP most the right side a bit,
	The point P can be represented by the xP and bit ˜ yP.
	The xP and ˜ yP yP recovery method is as follows:
	A) calculation domain element =(xP^3+aXp+b) modp;
	B) calculate the square root of the modp (see appendix b.1.4), and report an error if the output is "no square root";
	C) if the right side of the beta bits equal ˜ yP, buy yP = β;Otherwise, set yP = p−β.

***************************************************************************************************/
void sm2_point2oct (unsigned char ucType, unsigned char* pucInX, unsigned char* pucOutXY )
{
	BIGNUM* g_pBG_p=NULL;BIGNUM* g_pBG_a=NULL;BIGNUM* g_pBG_b=NULL;BIGNUM* g_pBG_n=NULL;BIGNUM* g_pBG_Gx=NULL;BIGNUM* g_pBG_Gy=NULL;
	BIGNUM* g_pBGXp=NULL;BIGNUM* g_pBGX3=NULL;BIGNUM* g_pBGX=NULL;BIGNUM* g_pBGY=NULL;BIGNUM* g_pR=NULL;BIGNUM* g_pTemp=NULL;
	BN_CTX *ctx=NULL;

	if ( !(ctx = BN_CTX_secure_new()) )
	{
	   return;
	}
	BN_CTX_start(ctx);
	g_pBG_p = BN_CTX_get(ctx);
	g_pBG_a = BN_CTX_get(ctx);
	g_pBG_b = BN_CTX_get(ctx);
	g_pBG_n = BN_CTX_get(ctx);
	g_pBG_Gx = BN_CTX_get(ctx);
	g_pBG_Gy = BN_CTX_get(ctx);
	g_pBGXp = BN_CTX_get(ctx);
	g_pBGX3 = BN_CTX_get(ctx);
	g_pBGX = BN_CTX_get(ctx);
	g_pBGY = BN_CTX_get(ctx);
	g_pR = BN_CTX_get(ctx);
	g_pTemp = BN_CTX_get(ctx);

	unsigned char aucY[64+1] = {0};
	int iYLen = 0;
	int y_bit = 0;
	
	y_bit = ucType & 1;

	g_pBG_p = BN_bin2bn( g_sm2_P, 32, NULL );
	g_pBG_a = BN_bin2bn( g_sm2_a, 32, NULL );
	g_pBG_b = BN_bin2bn( g_sm2_b, 32, NULL );
	g_pBG_n = BN_bin2bn( g_sm2_n, 32, NULL );
	g_pBG_Gx = BN_bin2bn( g_sm2_Gx, 32, NULL );
	g_pBG_Gy = BN_bin2bn( g_sm2_Gy, 32, NULL );

	BN_clear(g_pBGXp);
	BN_clear(g_pBGX3);
	BN_clear(g_pBGX);
	BN_clear(g_pBGY);
	BN_clear(g_pR);
	BN_clear(g_pTemp);

	g_pBGXp = BN_bin2bn( pucInX, 32, NULL );
	
	BN_sqr(g_pR, g_pBGXp, ctx); 
	BN_mul(g_pBGX3, g_pR, g_pBGXp, ctx);

	BN_mul(g_pR, g_pBG_a, g_pBGXp, ctx);

	BN_add(g_pR, g_pR, g_pBGX3);
	BN_add(g_pTemp, g_pBG_b, g_pR);
	
	BN_mod(g_pR, g_pTemp, g_pBG_p, ctx);
	
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
	//print_HexString(aucY,iYLen,"Y");
	print_HexString(pucOutXY,iYLen*2,"XY");


	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

}

//input :ucType=x[0];pucInX=&x[1];output :pucOutXY=y;//lenth is 1,32,32;checked by wel in 20190528
int untar_x_to_y(const int ucType, const char* pucInX, unsigned char* pucOutXY)
{
	unsigned char InXoutstr[32]={0};

	int str_len;
	unsigned char type=0;
	//printf("atoi(Type)=[%d]\n",atoi(ucType));
	if(compressy0==ucType)
		type=0;
	else if(compressy1==ucType)
		type=1;
	else
	{
		ERROR_PRINT("Uncompress type [%d] error!\n",ucType);
		return 0;
	}

	str_len=HexStringToAsc(pucInX,InXoutstr);
	if(32!=str_len)
	{
		ERROR_PRINT("Publickey X length=[%d],error!\n",str_len);
		return 0;
	}
	
	//init P a b n Gx Gy
	//init_curve_param(fp256);
	sm2_point2oct(type, InXoutstr, pucOutXY);

	return 1;
}

