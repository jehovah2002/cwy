#include "common.h"
#include "sm2crypto.h"
#include "sm2_point2oct.h"


//kdf方法
/*
void *kdf(const EVP_MD *md, const void *in, size_t inlen,
              void *out, size_t *outlen)
{
	EVP_MD_CTX mdctx;
    uint32_t counter = 1;
    uint32_t counter_be;
    unsigned char dgst[EVP_MAX_MD_SIZE];
    unsigned int dgstlen;
    unsigned char *pout = out;
    size_t rlen = *outlen;
    size_t len;
    
    EVP_MD_CTX_init(&mdctx);
    
    while (rlen > 0) {
        counter_be = cpu_to_be32(counter);
        counter++;
        
        EVP_DigestInit(&mdctx, md);
        EVP_DigestUpdate(&mdctx, in, inlen);
        EVP_DigestUpdate(&mdctx, &counter_be, sizeof(counter_be));
        EVP_DigestFinal(&mdctx, dgst, &dgstlen);
        
        len = dgstlen <= rlen ? dgstlen : rlen;
        memcpy(pout, dgst, len);
        rlen -= len;
        pout += len;
    }
    
    EVP_MD_CTX_cleanup(&hash);
    return out;
}
*/

//Function:my_KDF(key stretching)
//to realize the key derived function KDF in state secret SM2 encryption and decryption algorithm
//Input:  cdata      - data string (binary value) used for calculation
//        datalen    - length of cdata
//        keylen     - length required to derive
//Output: retdata    - the content returned after the calculation (binary value) is allocated at least as required for keylen
//Return: int 0 is success，others failed
/* X9.63 with no salt happens to match the KDF used in SM2 */
//int ecdh_KDF_X9_63(unsigned char *out, size_t outlen,
//                   const unsigned char *Z, size_t Zlen,
//                   const unsigned char *sinfo, size_t sinfolen,
//                   const EVP_MD *md)
int my_KDF(const char* cdata, int datalen, int keylen, char* retdata)
{
    int nRet = -1;
    unsigned char *pRet;
    unsigned char *pData;
	unsigned int hash_len=0;

    if(cdata==NULL || datalen<=0 || keylen<=0)
    {
        goto err;
    }

    if(NULL == (pRet=(unsigned char *)malloc(keylen)))
    {
        goto err;
    }

    if(NULL == (pData=(unsigned char *)malloc(datalen+4)))
    {
        goto err;
    }

    memset(pRet,  0, keylen);
    memset(pData, 0, datalen+4);

    unsigned char cdgst[32]={0}; //hash
    unsigned char cCnt[4] = {0}; //The memory representation of the counter
    int nCnt  = 1;  //counter
    int nDgst = 32; //hash length

    int nTimes = (keylen+31)/32; //The number of times you have to count
    int i=0;
    memcpy(pData, cdata, datalen);
    for(i=0; i<nTimes; i++)
    {
        //cCnt
        {
            cCnt[0] =  (nCnt>>24) & 0xFF;
            cCnt[1] =  (nCnt>>16) & 0xFF;
            cCnt[2] =  (nCnt>> 8) & 0xFF;
            cCnt[3] =  (nCnt    ) & 0xFF;
        }
        memcpy(pData+datalen, cCnt, 4);
        sm3_hash(pData, datalen+4, cdgst,&hash_len);

        if(i == nTimes-1) //For the last calculation, intercept the value of the digest based on whether keylen/32 is divisible
        {
            if(keylen%32 != 0)
            {
                nDgst = keylen%32;
            }
        }
        memcpy(pRet+32*i, cdgst, nDgst);

        i    ++;  //
        nCnt ++;  //
    }

    if(retdata != NULL)
    {
        memcpy(retdata, pRet, keylen);
    }

    nRet = 0;
err:
    if(pRet)
        free(pRet);
    if(pData)
        free(pData);

    return nRet;
}


unsigned long sm2Encrypt(unsigned char *x,
								unsigned char *y,
								unsigned char *encryptData,
								unsigned long encryptDataLen,
								unsigned char *outData)
{
	const EC_POINT *G = NULL;
	EC_POINT *c1 = NULL;
	BIGNUM *k;
	BIGNUM *bn_x;
	BIGNUM *bn_y;
	BIGNUM *x2;
	BIGNUM *y2;
	EC_GROUP *group = NULL;
	BN_CTX *ctx = NULL;
	EC_KEY *ec_key = NULL;
	EC_POINT *tempPoint = NULL;
	int error_code;
	EC_POINT *P = NULL;
	unsigned long outDataLen = 0;
	
	unsigned char c1bin[65];
	unsigned long c1binlen = 65;
	unsigned char x2y2[64] = {0};
    unsigned long x2y2len = 0;
	unsigned long c2len = 0;
	unsigned char c3[32];
    unsigned long c3len = 32;
	unsigned long klen;
	klen=encryptDataLen;
	unsigned char t[klen];
	unsigned long tlen;
	tlen=klen;
	unsigned char c2[tlen];
	unsigned char M[klen];
	int hash_len;
	unsigned char c[4096*10];
	//unsigned long clen = 0;
	unsigned long ret = 0;
	
	unsigned char tempC3[64+klen];

	int i;
	//init
	//group = EC_GROUP_new(EC_GFp_mont_method());
	ctx = BN_CTX_new();
	BN_CTX_start(ctx);

	bn_x = BN_CTX_get(ctx);
	bn_y = BN_CTX_get(ctx);
	x2 = BN_CTX_get(ctx);
	y2 = BN_CTX_get(ctx);

	if ( !(group = EC_GROUP_new_by_curve_name(NID_sm2)) )
	{
		goto clean_up;
	}

	if ( !(P = EC_POINT_new(group)) )
	{
		goto clean_up;
	}

	if ( !(BN_bin2bn(x,32, bn_x)) )
	{
		return 0;
	}
	if ( !(BN_bin2bn(y,32, bn_y)) )
	{
		return 0;
	}

	print_bn("bn_x",bn_x,DEBUG_OUTPUT);
	print_bn("bn_y",bn_y,DEBUG_OUTPUT);
	if ( !(EC_POINT_set_affine_coordinates(group,P,bn_x,bn_y,ctx)))
	{
		goto clean_up;
	}
	//if ( !(ec_key = EC_KEY_new_by_curve_name(NID_sm2)) )
	//{
	//	goto clean_up;
	//}
	//EC_KEY_generate_key(ec_key);
	//EC_KEY_set_private_key(ec_key, d);
	//EC_KEY_set_public_key(ec_key, P);

	//ec_group = EC_KEY_get0_group(ec_key);
	G = EC_GROUP_get0_generator(group);
	

	//get G
	c1 = EC_POINT_new(group);
	k=k_creat(group,ctx);
	//print_bn("k",k);
	EC_POINT_mul(group, c1, NULL, G, k, ctx);
	EC_POINT_point2oct(group, c1, POINT_CONVERSION_UNCOMPRESSED, c1bin, c1binlen, ctx);

	//S=[h] PB
	error_code = EC_POINT_is_on_curve(group, P, ctx);
	if(!error_code)
	{
		ERROR_PRINT("Points are not equal\n");
		goto clean_up;
	}
	
	error_code = EC_POINT_is_at_infinity(group, P);
	if(error_code)
	{
		ERROR_PRINT("Point is not on the curve\n");
		goto clean_up;
	}

	tempPoint = EC_POINT_new(group);
	
	//(x2,y2)=[k] PB
	EC_POINT_mul(group, tempPoint, NULL, P, k, ctx);
	EC_POINT_get_affine_coordinates_GFp(group,tempPoint, x2, y2, ctx);

	//x2||y2
    x2y2len += BN_bn2bin(x2, x2y2);
    x2y2len += BN_bn2bin(y2, &x2y2[32]);
    //print_HexString(x2y2,64,"x2y2");
	//print_bn("x2",x2);
	//print_bn("y2",y2);
	error_code=my_KDF(x2y2,sizeof(x2y2),tlen,t);
	DEBUG_PRINT("my_KDF error_code =[%d] \n",error_code);
	if(error_code)
	{
		ERROR_PRINT("KDF error!\n");
		goto clean_up;
	}
	
	memcpy(M,encryptData,klen);
	
	//C2
	for (int i = 0; i < tlen; i ++) {
        c2[i] = M[i] ^ t[i];
        c2len++;
    }

	
	outDataLen = c1binlen + c2len + c3len;
	
	//C3=Hash(x2||M||y2)
    BN_bn2bin(x2, tempC3);
    BN_bn2bin(y2, &tempC3[32+klen]);
    memcpy(&tempC3[32], M, klen);
    //sm3(tempC3, x2y2len+klen, c3);
	sm3_hash(tempC3, x2y2len+klen, c3,&hash_len);

	//C=C1||C3||C2
    memcpy(c, c1bin, c1binlen);
    memcpy(&c[c1binlen], c3, c3len);
    memcpy(&c[c1binlen+c3len], c2, c2len);
	memcpy(outData, c, outDataLen);

	ret = outDataLen;
		
clean_up:
	if (ctx)
	{
	   BN_CTX_end(ctx);
	   BN_CTX_free(ctx);
	}
	
	if (group)
	{
	   EC_GROUP_free(group);
	}
	if (tempPoint)
	{
	   EC_POINT_free(tempPoint);
	}
	if (ec_key)
	{
	   EC_KEY_free(ec_key);
	}
	return ret;

}

unsigned long sm2Encrypt_Ex(const int keytype,
									const unsigned char *pub_key,
									unsigned char *encryptData,
									unsigned long encryptDataLen,
									unsigned char *outData)
{
	unsigned char pub_key_temp[128]={0};
	unsigned char pub_key_t[64]={0};
	unsigned char pub_key_x[32]={0};
	unsigned char pub_key_y[32]={0};
	BN_CTX *ctx = NULL;
	BIGNUM *bn_x;
	BIGNUM *bn_y;
	int str_len;


	//printf("in sm2Encrypt_ex\n");
	if(!((128==strlen(pub_key)||(64==strlen(pub_key))||(130==strlen(pub_key)))))
		return 0;

	if((uncompress==keytype)&&(130==strlen(pub_key)))
	{
		str_len=HexStringToAsc(pub_key+2,pub_key_temp);
		print_HexString(pub_key_temp,str_len,"pub_key_temp",DEBUG_OUTPUT);
	}
	else if((uncompress==keytype)&&(128==strlen(pub_key)))
	{
		str_len=HexStringToAsc(pub_key,pub_key_temp);
		print_HexString(pub_key_temp,str_len,"pub_key_temp",DEBUG_OUTPUT);
	}
	else if((compressy0==keytype)&&(64==strlen(pub_key)))
	{
		if(!untar_x_to_y(keytype,pub_key,pub_key_temp))
				ERROR_PRINT("uncompress error!\n");
	}
	else if((compressy1==keytype)&&(64==strlen(pub_key)))
	{
		if(!untar_x_to_y(keytype,pub_key,pub_key_temp))
				ERROR_PRINT("uncompress error!\n");
	}
	else
	{
		ERROR_PRINT("Key type or length error!\n");
		return 0;
	}
	memcpy(pub_key_x,pub_key_temp,sizeof(char)*32);
	memcpy(pub_key_y,pub_key_temp+32,sizeof(char)*32);
	print_HexString(pub_key_x,32,"pub_key_x",DEBUG_OUTPUT);
	print_HexString(pub_key_y,32,"pub_key_y",DEBUG_OUTPUT);
	
	return sm2Encrypt(pub_key_x,pub_key_y,encryptData,encryptDataLen,outData);

}

unsigned long sm2Decrypt(unsigned char *prikey,
								unsigned char *decryptData,
								unsigned long decryptDataLen,
								unsigned char *outData)
{

	BN_CTX *ctx = NULL;
	EC_GROUP *ec_group = NULL;
	EC_POINT  *c1 = NULL;
	EC_POINT *dC1 = NULL;
	int error_code;
	BIGNUM *d;
	BIGNUM *x2;
	BIGNUM *y2;
	int ret;
	
	unsigned char c1Bin[POINT_BIN_LENGTH];
	unsigned long c1Binlen = POINT_BIN_LENGTH;
	unsigned char x2y2[64] = {0};
    unsigned long x2y2len = 0;
	unsigned long c3len = 32;
	unsigned long klen;
	klen = decryptDataLen - (c1Binlen+c3len);
    unsigned char t[klen];
    unsigned long tlen = klen;
	unsigned char c2[tlen];
	unsigned char M[tlen+1];
    unsigned long Mlen = 0;
	
	memcpy(c1Bin,decryptData, POINT_BIN_LENGTH);
	ctx = BN_CTX_new();
	BN_CTX_start(ctx);
	x2 = BN_CTX_get(ctx);
	y2 = BN_CTX_get(ctx);
	d = BN_CTX_get(ctx);

	if ( !(ec_group = EC_GROUP_new_by_curve_name(NID_sm2)) )
	{
		goto clean_up;
	}
	if ( !(c1 = EC_POINT_new(ec_group)) )
	{
		goto clean_up;
	}

	EC_POINT_oct2point(ec_group, c1, c1Bin, c1Binlen, ctx);

	error_code = EC_POINT_is_on_curve(ec_group, c1, ctx);
    if (!error_code) 
	{
        ERROR_PRINT("C1 is not on curve !\n");
		goto clean_up;
    }
	if ( !(dC1 = EC_POINT_new(ec_group)) )
	{
		goto clean_up;
	}
	error_code = EC_POINT_is_on_curve(ec_group, dC1, ctx);
    if (!error_code) 
	{
        ERROR_PRINT("dC1 is not on curve !\n");
		goto clean_up;
    }
	
	if ( !(BN_bin2bn(prikey,32, d)) )
	{
		ERROR_PRINT("Set prikey error !\n");
		goto clean_up;
	}
	//print_HexString(prikey, 32, "prikey");
	//print_bn("d",d);

    EC_POINT_mul(ec_group, dC1, NULL, c1, d, ctx);
    

	if ( !(EC_POINT_get_affine_coordinates_GFp(ec_group,dC1, x2, y2, ctx)))
	{
		goto clean_up;
	}
	print_bn("x2",x2,DEBUG_OUTPUT);
	print_bn("y2",y2,DEBUG_OUTPUT);

	
    //x2||y2
    x2y2len += BN_bn2bin(x2, x2y2);
    x2y2len += BN_bn2bin(y2, &x2y2[32]);
    
    //sm3_kdf1(EVP_sm3(), x2y2, sizeof(x2y2), t, &tlen);
	error_code=my_KDF(x2y2,sizeof(x2y2),tlen,t);
	if(error_code)
	{
		ERROR_PRINT("KDF error!\n");
		ERROR_PRINT("my_KDF error_code =[%d] \n",error_code);
		goto clean_up;
	}

	memcpy(c2, decryptData+c1Binlen+c3len, tlen);
	
    for (int i = 0; i < tlen; i ++) {
        M[i] = c2[i] ^ t[i];
        Mlen++;
    }
    M[tlen] = '\0';
    DEBUG_PRINT("M'-->%s\n",M);

	memcpy(outData, M, tlen);
	ret=tlen;

clean_up:
	if (ctx)
	{
	   BN_CTX_end(ctx);
	   BN_CTX_free(ctx);
	}
	
	if (ec_group)
	{
	   EC_GROUP_free(ec_group);
	}

	return ret;



}
unsigned long sm2Decrypt_Ex(unsigned char *prikey,
								unsigned char prikeyLen,
								unsigned char *decryptData,
								unsigned char decryptDataLen,
								unsigned char *outData)
{
	unsigned char buf_arr1[prikeyLen];
	unsigned char buf_arr2[decryptDataLen];
	

	int str_len1=0;
	int str_len2=0;
	memset(buf_arr1,0,prikeyLen);
	memset(buf_arr2,0,decryptDataLen);
	
	str_len1=HexStringToAsc(prikey,buf_arr1);
	if(32!=str_len1)
		return 0;
	str_len2=HexStringToAsc(decryptData,buf_arr2);
	

	return sm2Decrypt(buf_arr1,buf_arr2,str_len2,outData);
}



