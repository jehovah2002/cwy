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
	print_bn("β", g_pTemp,DEBUG_OUTPUT);

	if ( y_bit != BN_is_odd ( g_pTemp ) )
	{
		BN_usub( g_pBGY, g_pBG_p, g_pTemp );
		print_bn("Y=p−β", g_pBGY,DEBUG_OUTPUT);
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
	print_HexString(pucOutXY,iYLen*2,"XY",DEBUG_OUTPUT);


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

#define KEY_SHM_PKCACHE 20258614

static TUncompressedShm* g_uncompressedPKCache = NULL;
static EC_GROUP *g_SM2Group = NULL;

int BN_bn2bin_ex(BIGNUM *bn, unsigned char *to, int len)
{
	int padding_size = len - BN_num_bytes(bn);

	if (padding_size < 0) {

	}
	else if (padding_size > 0) 
	{
		memset(to, 0, padding_size);
		BN_bn2bin(bn, to + padding_size);
	}
	else 
	{
		BN_bn2bin(bn, to);
	}

	// return padding_size;
	return len;
}


EC_GROUP* SM2Group()
{
	int result = 0;
	BIGNUM *p = NULL, *a = NULL, *b = NULL, *Gx = NULL,
            *Gy = NULL, *n = NULL, *Px = NULL, *Py = NULL,
            *d = NULL, *n_minus_2 = NULL;
	BN_CTX *ctx = NULL;
	EC_GROUP *group = NULL;
	EC_POINT *G = NULL, *P = NULL;
	
	if (g_SM2Group != NULL)
		return g_SM2Group;

	d = BN_new();
	p = BN_new();
	a = BN_new();
	b = BN_new();
	Gx = BN_new();
	Gy = BN_new();
	n = BN_new();
	Px = BN_new();
	Py = BN_new();
	
	ctx = BN_CTX_new();
	if (!BN_hex2bn(&n_minus_2, _n))
        {
		result = -1;
		goto err;
        }
        if (!BN_sub_word(n_minus_2, 2))
        {
		result = -1;
		goto err;
        }
        if (!BN_rand_range(d, n_minus_2))
        {
		result = -1;
		goto err;
        }
        if (!BN_add_word(d, 1))
        {
		result = -1;
		goto err;
        }

	if (!BN_hex2bn(&p, _P) ||
        !BN_hex2bn(&a, _a) ||
        !BN_hex2bn(&b, _b) ||
        !BN_hex2bn(&Gx, _Gx) ||
        !BN_hex2bn(&Gy, _Gy) ||
        !BN_hex2bn(&n, _n)
        )
	{
		result = -1;
		goto err;
	}

	// EC setup
	group = EC_GROUP_new(EC_GFp_mont_method());
	if (!EC_GROUP_set_curve_GFp(group, p, a, b, ctx))
	{
		result = -1;
		goto err;
	}

	G = EC_POINT_new(group);
	P = EC_POINT_new(group);

	// set point G(G_x, G_y)
	if (!EC_POINT_set_affine_coordinates_GFp(group, G, Gx, Gy, ctx))
	{
		result = -1;
		goto err;
	}

	// P = [d]G
	if (!EC_GROUP_set_generator(group, G, n, BN_value_one()))
	{
		result = -1;
		goto err;
	}

	if (!EC_POINT_mul(group, P, d, NULL, NULL, ctx))
	{
		result = -1;
		goto err;
	}

	// EC_POINT P is public key, saving at pucPublicKey
	if (!EC_POINT_get_affine_coordinates_GFp(group, P, Px, Py, ctx))
	{
		result = -1;
		goto err;
	}
err:
	if (G) EC_POINT_free(G);
	if (P) EC_POINT_free(P);
	if (d) BN_free(d);
	if (p) BN_free(p);
	if (a) BN_free(a);
	if (b) BN_free(b);
	if (n) BN_free(n);
	if (Gx) BN_free(Gx);
	if (Gy) BN_free(Gy);
	if (Px) BN_free(Px);
	if (Py) BN_free(Py);

	if (ctx) BN_CTX_free(ctx);
	if (result != 0){
		if (group) EC_GROUP_free(group);
		group = NULL;
	}

	g_SM2Group = group;
	return g_SM2Group;
}


int MizarInitShm(int key, int size)
{
	int shmid = 0;
	key_t iKey = key;
	shmid = shmget(iKey, size, IPC_CREAT | IPC_EXCL | 0666);
	if (shmid < 0 && errno == EEXIST)
		shmid = shmget(iKey, size, 0666);

	return shmid;
}

void *MizarAttachShm(int shmid)
{
	int flag = 0;
	void *shmem = shmat(shmid, 0, flag);
	if ((void*)-1 == shmem)
	{
		shmem = NULL;
	}
	
	return shmem;
}



int UncompressCacheGet(unsigned long long xdata, unsigned char* pk)
{
	int shmid = 0;
	int i = 0;

	if (g_uncompressedPKCache == NULL)
	{		
		shmid = MizarInitShm(KEY_SHM_PKCACHE, sizeof(TUncompressedShm));
		if (shmid < 0)
		{

			ERROR_PRINT("UncompressCacheGet failed.\n");
			return -1;
		}
		g_uncompressedPKCache = (TUncompressedShm *)MizarAttachShm(shmid);
	}

	if (g_uncompressedPKCache == NULL)
	{
		ERROR_PRINT("UncompressCacheGet failed.\n");
		return -1;
	}

	for (i = 0; i < MAX_PKCACHE_NUM; i++)
	{
		if (g_uncompressedPKCache->uncompressPK[i].nXValue == xdata)
		{
			memcpy(pk, g_uncompressedPKCache->uncompressPK[i].pk, 64);
			DEBUG_PRINT("    UncompressCacheGet: slot = %d", i);
			print_HexString((unsigned char*)&xdata, 8, "    Found X_DATA: ",DEBUG_OUTPUT);
			print_HexString(pk, 64, "    Cache_PK: ",DEBUG_OUTPUT);
			return 0;
		}
	}

	return 1;
}
int UncompressPKCachePut(unsigned long long xdata, unsigned char* pk)
{
	int shmid = 0;
	int i = 0;
	if (g_uncompressedPKCache == NULL)
	{
		ERROR_PRINT("UncompressPKCachePut failed. g_uncompressedPKCache is NULL.");
		return -1;
	}

	i = g_uncompressedPKCache->index%MAX_PKCACHE_NUM;
	g_uncompressedPKCache->uncompressPK[i].nXValue = xdata;
	memcpy(g_uncompressedPKCache->uncompressPK[i].pk, pk, 64);
	g_uncompressedPKCache->index = (i+1)%MAX_PKCACHE_NUM;
	
	return 0;
}



int CryptoUncompressPK(int cacheFlag, unsigned char* compressed, int len, unsigned char *pk)
{
	int ret = 0;
	int buf_len = 0;
	EC_GROUP* group = NULL;
	BN_CTX* ctx = BN_CTX_new();
	EC_POINT *ptPubKey = NULL;
	BIGNUM* bnPubKey1 = NULL;
	BIGNUM* bnPubKey2 = NULL;
	unsigned long long xdata = 0;
	unsigned char* cachePK = NULL;

	memcpy((unsigned char*)&xdata, compressed+1, 8);

    group = SM2Group();

	if (cacheFlag)
	{
		ret = UncompressCacheGet(xdata, pk);
		if (ret < 0)
		{
			ret = -1;
			goto err;
		}
		else if (ret == 0)
			return 0;
	}

	ptPubKey = EC_POINT_new(group);
	bnPubKey1 = BN_bin2bn(pk, 32, NULL);	
	bnPubKey2 = BN_bin2bn(pk+32, 32, NULL);
	if(bnPubKey2 == NULL || bnPubKey1 == NULL)
	{
		ret = -1;
		goto err;
	}

	print_HexString(compressed, len, "Compressed-PK: ",DEBUG_OUTPUT);
	if (!EC_POINT_oct2point(group, ptPubKey, compressed, len, ctx))
	{
		ret = -1;
		goto err;
	}
	ret = EC_POINT_get_affine_coordinates_GFp(group, ptPubKey, bnPubKey1, bnPubKey2, ctx);
	if(ret != 1)
	{
		ret = -1;
		goto err;
	}
	ret = -1;
	buf_len = BN_bn2bin_ex(bnPubKey1, pk, 32);
	if( buf_len!= 32)
		goto err;
	buf_len = BN_bn2bin_ex(bnPubKey2, pk+32, 32);
	if( buf_len!= 32)
		goto err;
	ret = 0;
	print_HexString(pk, 32, "Uncompress-X: ",DEBUG_OUTPUT);
	print_HexString(pk+32, 32, "Uncompress-Y: ",DEBUG_OUTPUT);

	if (cacheFlag)
		UncompressPKCachePut(xdata, pk);
err:
	if(bnPubKey1) BN_clear_free(bnPubKey1);
	if(bnPubKey2) BN_clear_free(bnPubKey2);
	if(ptPubKey) EC_POINT_free(ptPubKey);
	if(ctx) BN_CTX_free(ctx);

	return ret;
}


