#include "common.h"
#include "autoc.h"
#include "sm3.h"
#include "sm2_sign_and_verify.h"
#include "sm2_create_key_pair.h"
#include "sm2_point2oct.h"

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
	printf("**************************************************\n");

}


int main(int argc, const char *argv[])
{

	unsigned char buf_arr[4096]={0};
	unsigned char outstr[4096]={0};
	int buf_len=0;
	int str_len=0;
	int ret=0;
	int i=0;
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
		SendbyPost(argv[2],argv[3],asn_arr,str_len,outstr);
		ret=splitRecvPkg(outstr);
		//printf("recv [%d] arrs!",ret);
		printrespond();
	}
	else if((argc>3)&&(!strcmp("sendoer",argv[1])&&(NULL!=argv[4])))
	{
		buf_len=ReadBinToarr(argv[4],buf_arr);
		printf("filename=[%s],len=[%d]\n",argv[4],buf_len);
		SendbyPost(argv[2],argv[3],buf_arr,buf_len,outstr);
		ret=splitRecvPkg(outstr);
		//printf("recv [%d] arrs!",ret);
		printrespond();
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
		printf("/*********************************************************/\n");

	}
	else
	{
		Useage();
	}
	
	return 0;

}

