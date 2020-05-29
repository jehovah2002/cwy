#include "common.h"
#include "autoc.h"
#include "sm3.h"
#include "sm2_sign_and_verify.h"
#include "sm2_create_key_pair.h"
#include "sm2_point2oct.h"
#include "sm2crypto.h"
#include "autoasn.h"
#include "network.h"

char *rspstr="02818183028100AB9C7DF39472045F0911433D434E2C434E3D436963764D6F744153200000836573330276088000C45E7595CCA8B41F6C14D9E22E708C998770CCFD683033FD0000811D2579832E143D830080EB760D172C12F9B31287C337E298E3EC750CB21319D6A39EAEF9F04F4A2A8204E0E1B2738E4D318B6B8DD23B6DC5BC7BBCB113080719A1995FAAB80D8A054F9C008201410180810001E14A73F59D6CB62783028100AB9C7DF39472045F0312433D434E2C434E3D436963764D6F7445434120000083B5D69B452B68A6D4BAB6A7F1F20A39D760D37A101ED933FA1FE22C556612C8110000811D2579832E143D8300808C1B64D67E6C57E9EF1CE833280C1ACF130CE6B60AE587ED4CD4786ECE8FCA55E3CBCEB8E904AE8B82AB316442E13EB99FD08FA175403FE01D5131AD503EE3BB83028100113326CFB964232300096F627532303031343000000084697D6910521C4B22A4BCF3CE35232F4293258D1EC2A07159C49EF7DBD244BF82BA85F712B1B962FDAE58BD01731B7C18DAB271FD50CE0F7C8A842D1995EA42DC008020661DEA0080C42C2E3558D490E0183AA24500B978D97EEE112FA1B48F92087C83DE4F3FCEEF064A48260EAEB5E288C351C18F3B6A53D6A22F3D23294462F677DA7CFCB8B33000808DFE2FC6AE4B6802DD769234333F39432CEB65B636F37F446EE923BCEB3161DA8823F247F301A08131294CACB64841BE22EC73949FF2DEF5A5A97BE7EE12AE1B";

void Useage()
{
	printf("**************************************************\n");
	printf("***  cmd:[Hex2File] <filename> <Str>           ***\n");
	printf("***       Save Hex string to bin file.         ***\n");
	printf("***  cmd:[File2Hex] <filename>                 ***\n");
	printf("***       return:<Hex String>                  ***\n");
	printf("***       Read bin file and print Hex string   ***\n");
	printf("***  cmd:[HexStr2Asc] <HexString>              ***\n");
	printf("***       return:<Asc String>                  ***\n");
	printf("***  cmd:[Asc2HexStr] <Asc String>             ***\n");
	printf("***       return:<Hex String>                  ***\n");
	printf("***  cmd:[Base2HexStr] <Base64 Str>            ***\n");
	printf("***       return:<Hex String>                  ***\n");
	printf("***  cmd:[HexStr2Base] <Hex String>            ***\n");
	printf("***       return:<Base64 Str>                  ***\n");
	printf("***  cmd:[senddata] <host ip> <port> <str>     ***\n");
	printf("***       return:<Response>                    ***\n");
	printf("***       Send HexString to server             ***\n");
	printf("***  cmd:[sendoer] <host ip> <port> <filename> ***\n");
	printf("***       return:<Response>                    ***\n");
	printf("***       Send OER file to server              ***\n");
	printf("***  cmd:[sm3file] <filename>                  ***\n");
	printf("***       return:<SM3 String>                  ***\n");
	printf("***  cmd:[sm3string] <HexString>               ***\n");
	printf("***       return:<SM3 String>                  ***\n");
	printf("***  cmd:[uncompressY] <Gx> <type>             ***\n");
	printf("***                    type 0: xonly           ***\n");
	printf("***                    type 1: fill            ***\n");
	printf("***                    type 2: compressy0      ***\n");
	printf("***                    type 3: compressy1      ***\n");
	printf("***                    type 4: uncompress      ***\n");
	printf("***       return:<Gy> & <Gx+Gy>                ***\n");
	printf("***  cmd:[test_sign_and_verify] <message>      ***\n");
	printf("***  cmd:[createkey]                           ***\n");
	printf("***  cmd:[sign] <type> <pubkey> <msg> <prikey> ***\n");
	printf("***                    [64/32]         [32]    ***\n");
	printf("***       return:<r> <s>                       ***\n");
	printf("***  cmd:[verify] <type> <pubkey> <msg> <r> <s>***\n");
	printf("***                      [64/32]               ***\n");
	printf("***       return:success or failed             ***\n");
	printf("***  cmd:[encrypt] <type> <pubkey> <msg>       ***\n");
	printf("***       return:C1||C2||C3 & datalen          ***\n");
	printf("***  cmd:[decrypt] <prikey> <msg>              ***\n");
	printf("***       return:decode_msg & datalen          ***\n");
    printf("***  cmd:[showtime]                            ***\n");
    printf("***  cmd:[ECA] <name>                          ***\n");
    printf("***  cmd:[test]                                ***\n");
	printf("**************************************************\n");

}


int main(int argc, const char *argv[])
{

	unsigned char buf_arr[4096]={0};
	unsigned char buf_out[4096]={0};
	unsigned char outstr[4096*10]={0};
	int buf_len=0;
	int str_len=0;
	int ret=0;
	int i=0;
	unsigned long buf_long=0;

    CicvserverRespond_t serverRespond;

	//int msg_len;
	int error_code;
	SM2_SIGNATURE_STRUCT sm2_sig_out;
	//SM2_SIGNATURE_STRUCT *sm2_sig_in;
	SM2_KEY_PAIR key_pair;
	
	char asn_arr[4096]={0};

	init_curve_param(fp256);

	if((argc>2)&&(!strcmp("Hex2File",argv[1])&&(NULL!=argv[3])))
	{
		str_len=HexStringToAsc(argv[3],outstr);
		printf("argv[3]=[%s],outstr=[%s],str_len=[%d],strlen(outstr)=[%ld]\n",argv[3],outstr,str_len,strlen(outstr));
		AscStringSaveToBin(argv[2],outstr,str_len);
	}
	else if((argc>1)&&(!strcmp("HexStr2Asc",argv[1])&&(NULL!=argv[2])))
	{
		str_len=HexStringToAsc(argv[2],outstr);
		printf("argv[2]=[%s],outstr=[%s],str_len=[%d],len=[%ld]\n",argv[2],outstr,str_len,strlen(outstr));
	}
	else if((argc>1)&&(!strcmp("Asc2HexStr",argv[1])&&(NULL!=argv[2])))
	{
		str_len=AscString2HexString((unsigned char *)argv[2],strlen(argv[2]),outstr);
		//arrayToStr(argv[2],strlen(argv[2]),outstr);
		printf("str_len=[%d],out = [ %s ]\n",str_len,outstr);
	}
	else if((argc>1)&&(!strcmp("File2Hex",argv[1])&&(NULL!=argv[2])))
	{
		buf_len=ReadBinToarr(argv[2],buf_arr);
		arrayToStr(buf_arr,buf_len,outstr);
		printf("out = [ %s ]\n", outstr);
	}
	else if((argc>1)&&(!strcmp("Base2HexStr",argv[1])&&(NULL!=argv[2])))
	{
		buf_len=base64_decode(argv[2],buf_arr);
		printf("String = [%s] strlen=[%d] \n",buf_arr,buf_len);
		str_len=arrayToStr(buf_arr,buf_len,outstr);
		printf("str_len=[%d],out = [ %s ]\n",str_len,outstr);
	}
	else if((argc>1)&&(!strcmp("HexStr2Base",argv[1])&&(NULL!=argv[2])))
	{
		buf_len=HexStringToAsc(argv[2],buf_arr);
		//printf("str_len=[%d],len=[%ld]\n",buf_len,strlen(buf_arr));
		str_len=base64_encode(buf_arr,buf_len,outstr);
		printf("str_len=[%d],out = [ %s ]\n",str_len,outstr);
	}
	else if((argc>3)&&(!strcmp("senddata",argv[1])&&(NULL!=argv[4])))
	{
		str_len=HexStringToAsc(argv[4],asn_arr);
		printf("argv[4]=[%s],asn_arr=[%s],str_len=[%d],len=[%ld]\n",argv[4],asn_arr,str_len,strlen(asn_arr));
		SendbyPost("POST","self-enrollment-certificate",argv[2],argv[3],asn_arr,str_len,outstr);
		ret=splitRecvPkg(outstr,&serverRespond);
		//printf("recv [%d] arrs!",ret);
		printrespond(&serverRespond);
	}
	else if((argc>3)&&(!strcmp("sendoer",argv[1])&&(NULL!=argv[4])))
	{
		buf_len=ReadBinToarr(argv[4],buf_arr);
		printf("filename=[%s],len=[%d]\n",argv[4],buf_len);
		SendbyPost("POST","self-enrollment-certificate",argv[2],argv[3],buf_arr,buf_len,outstr);
		ret=splitRecvPkg(outstr,&serverRespond);
		//printf("recv [%d] arrs!",ret);
		printrespond(&serverRespond);
	}
	else if((argc>1)&&(!strcmp("sm3file",argv[1])&&(NULL!=argv[2])))
	{
		buf_len=ReadBinToarr(argv[2],buf_arr);
		printf("SM3(%s) = [",argv[2]);
		sm3_hash(buf_arr,buf_len,outstr,&str_len);
		for (i = 0; i < str_len; i++)
		{
	    	printf("%02X", outstr[i]);
		}
		printf("]\n");
		printf("hash length = [%d] bytes.\n", str_len);
	}
	else if((argc>1)&&(!strcmp("sm3string",argv[1])&&(NULL!=argv[2])))
	{
		buf_len=strlen(argv[2]);
		printf("SM3(%s) = \n[",argv[2]);
		sm3_string_hash(argv[2],buf_len,outstr,&str_len);
		for (i = 0; i < str_len; i++)
		{
	    	printf("%02X", outstr[i]);
		}
		printf("]\n");
		printf("hash length = [%d] bytes.\n", str_len);
        str_len=sm3_string_hash_string(argv[2],buf_arr);
        printf("hash buf_arr=[%s], length = [%d] bytes.\n", buf_arr,str_len);
	}
	else if((argc>2)&&(!strcmp("uncompressY",argv[1])&&(NULL!=argv[3])))
	{
		if(!untar_x_to_y(atoi(argv[3]),argv[2],outstr))
				printf("uncompress error!\n");
	}
	else if((argc>1)&&(!strcmp("test_sign_and_verify",argv[1])))
	{
		//msg_len=HexStringToAsc(argv[2],buf_arr);
		if ( error_code = test_sm2_sign_and_verify(argv[2]) )
		{
			printf("Test create SM2 key pair, sign data and verify signature failed!\n");
			return error_code;
		}
		else
		{
			printf("Test create SM2 key pair, sign data and verify signature succeeded!\n");
		}
	}
	else if((argc>1)&&(!strcmp("createkey",argv[1])))
	{
		printf(">>>>>>>>>>Now start create SM2 key pair!<<<<<<<<<<\n");
		if ( error_code = sm2_create_key_pair(&key_pair) )
		{
		   printf("Create SM2 key pair failed!\n");
		   return (-1);
		}
		printf("Create SM2 key pair succeeded!\n");
		printf("Private key:\n");
		print_HexString(key_pair.pri_key,sizeof(key_pair.pri_key),"pri_key");
		printf("\n\n");
		printf("Public key:\n");
		print_HexString(key_pair.pub_key,sizeof(key_pair.pub_key),"pub_key");
		print_HexString(key_pair.pub_key+1,sizeof(key_pair.pri_key),"pub_key.x");
		print_HexString(key_pair.pub_key+33,sizeof(key_pair.pri_key),"pub_key.y");
		printf("\n\n");

	}
	else if((argc>1)&&(!strcmp("sign",argv[1]))&&(NULL!=argv[5]))
	{
		if((64!=strlen(argv[5]))||!((64==strlen(argv[3])||(128==strlen(argv[3])))))
		{
			printf("Input error !\n");
			return 0;
		}
		if ( error_code = sm2_sign(argv[4],
									atoi(argv[2]),
									g_IDA,
									argv[3],
									argv[5],
									&sm2_sig_out))
		{
			printf("Create SM2 signature failed!\n");
			return error_code;
		}
		printf("Create SM2 signature succeeded!\n");
		printf("SM2 signature:\n");
		printf("r coordinate:\n");
		print_HexString(sm2_sig_out.r_coordinate,sizeof(sm2_sig_out.r_coordinate),"r");
		printf("s coordinate:\n");
		print_HexString(sm2_sig_out.s_coordinate,sizeof(sm2_sig_out.s_coordinate),"s");
		printf("\n\n");
		printf("/*********************************************************/\n");
	}
	else if((argc>1)&&(!strcmp("verify",argv[1]))&&(NULL!=argv[6]))
	{
		if((64!=strlen(argv[5]))||(64!=strlen(argv[6]))||!((64!=strlen(argv[3])||(128!=strlen(argv[3])))))
		{
			printf("Input error !\n");
			return 0;
		}
		//memcpy(sm2_sig_in->r_coordinate, argv[5], sizeof(sm2_sig_in->r_coordinate));
		//memcpy(sm2_sig_in->s_coordinate, argv[6], sizeof(sm2_sig_in->s_coordinate));
		if ( error_code = sm2_verify(argv[4],
									atoi(argv[2]),
									g_IDA,
									argv[3],
									argv[5],
									argv[6]))
		{
			printf("Verify SM2 signature failed! [%d]\n",error_code);
			return error_code;
		}
        printf("Verify SM2 signature success!\n");
		printf("/*********************************************************/\n");

	}
	else if((argc>1)&&(!strcmp("encrypt",argv[1]))&&(NULL!=argv[4]))
	{
		if(!((64!=strlen(argv[3]))||(128!=strlen(argv[3]))))
		{
			printf("Input error !\n");
			return 0;
		}
		//memcpy(sm2_sig_in->r_coordinate, argv[5], sizeof(sm2_sig_in->r_coordinate));
		//memcpy(sm2_sig_in->s_coordinate, argv[6], sizeof(sm2_sig_in->s_coordinate));
		if(0 < ( buf_long = sm2Encrypt_Ex(atoi(argv[2]),
										argv[3],
										(unsigned char *)argv[4],
										strlen(argv[4]),
										buf_arr)))
		{
			str_len=AscString2HexString(buf_arr,buf_long,outstr);
			printf("outstr = [%s],outlen=[%ld] strlen=[%d]\n",outstr,buf_long,str_len);
		}
		else
			printf("outlen=[%ld] \n",buf_long);
		printf("/*********************************************************/\n");

	}
	else if((argc>1)&&(!strcmp("decrypt",argv[1]))&&(NULL!=argv[3]))
	{
		if(64!=strlen(argv[2]))
		{
			printf("Input error !\n");
			return 0;
		}
		if(0 < ( buf_long = sm2Decrypt_Ex((unsigned char *)argv[2],
										strlen(argv[2]),
										(unsigned char *)argv[3],
										strlen(argv[3]),
										buf_arr)))
		{
			str_len=AscString2HexString(buf_arr,buf_long,outstr);
			//printf("outstr = [%s],outlen=[%ld] strlen=[%d]\n",outstr,buf_long,str_len);
			printf("outlen=[%ld] \n",buf_long);
		}
		else
			printf("outlen=[%ld] \n",buf_long);
		printf("/*********************************************************/\n");

	}
    else if((argc>1)&&(!strcmp("showtime",argv[1])))
    {
        struct timeval tv;
        struct timezone tz;
        gettimeofday(&tv,&tz);

        sprintf(buf_arr,"%02lX",tv.tv_sec);
        printf("tv_sec=[%ld]\n",tv.tv_sec);
        printf("CICV tv_sec=[%ld]\n",tv.tv_sec-1072886400);
        printf("char tv_sec=[%s]\n",buf_arr);
        memset(buf_arr,0,sizeof(buf_arr));
        sprintf(buf_arr,"%02lX",tv.tv_sec-1072886400);
        printf("CICV char tv_sec=[%s]\n",buf_arr);
        printf("CICV char tv_sec by func=[%ld],[%08lX]\n",get_CICV_current_time(),get_CICV_current_time());
        printf("test=[%02X]\n",123456789);

        
    }
    else if((argc>2)&&(!strcmp("ECA",argv[1])))
    {
//        TbsCert_t *out_st=NULL;
//        out_st=malloc(sizeof(TbsCert_t));
//        str_len=EncodeSignPublicVerifyKey(sgdsm2,asnuncompressedP256,"CD4A8CF276F4C439A9B4245D5C3332A74909AF6411900A9584F6407FA1E1F04D","643EF9B90859BB8F26F1D5B605B65B898E6032E0863A75C95AAA0DD56C2B8D32",outstr);
//        printf("SignPublicVerifyKey outstr=[%s],str_len=[%d]\n",outstr,str_len);
//        memset(outstr,0,sizeof(outstr));
//        str_len=EncodeSubjectInfo(0,"obu1234",outstr);
//        printf("SubjectInfo outstr=[%s],str_len=[%d]\n",outstr,str_len);
//        SetTbsCert_CICV("abcde12345",g_pubkx,g_pubky,543553242,out_st);
//        str_len=Encode_TbsCert(out_st,outstr);
//        printf("SetSubjectAttributes outstr=[%s],str_len=[%d]\n",outstr,str_len);

//        free(out_st);
        Auto_ECA(argv[2],
                    g_LTCprikey,
                    g_LTCpubkey,
                    g_OBUpubkx,
                    g_OBUpubky,
                    g_LTC);
        //INFO_PRINT("outstr=[%s]\n",outstr);

    }
    else if((argc>1)&&(!strcmp("test",argv[1])))
    {
        SecuredMessage_t outstruct;
        Decode_SecuredMessage(rspstr,&outstruct,buf_out);
        //char bufsize[4]={0};

        //snprintf(bufsize,2+1,"%s",argv[2]);
        //printf("bufsize=[%d]\n",HexToDec(bufsize));
    }
	else
	{
		Useage();
	}
	
	return 0;

}

