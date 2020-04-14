#include "autoc.h"

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
	
	char asn_arr[4096]={0};

	if((argc>2)&&(!strcmp("Hex2File",argv[1])))
	{
		str_len=HexStringToAsc(argv[3],outstr);
		printf("argv[3]=[%s],outstr=[%s],str_len=[%d],strlen(outstr)=[%ld]\n",argv[3],outstr,str_len,strlen(outstr));
		AscStringSaveToBin(argv[2],outstr,str_len);
	}
	else if((argc>1)&&(!strcmp("HexStr2Asc",argv[1])))
	{
		str_len=HexStringToAsc(argv[2],outstr);
		printf("argv[2]=[%s],outstr=[%s],str_len=[%d],len=[%ld]\n",argv[2],outstr,str_len,strlen(outstr));
	}
	else if((argc>1)&&(!strcmp("Asc2HexStr",argv[1])))
	{
		str_len=AscString2HexString((unsigned char *)argv[2],strlen(argv[2]),outstr);
		//arrayToStr(argv[2],strlen(argv[2]),outstr);
		printf("str_len=[%d],out = [ %s ]\n",str_len,outstr);
	}
	else if((argc>1)&&(!strcmp("File2Hex",argv[1])))
	{
		buf_len=ReadBinToarr(argv[2],buf_arr);
		arrayToStr(buf_arr,buf_len,outstr);
		printf("out = [ %s ]\n", outstr);
	}
	else if((argc>1)&&(!strcmp("Base2HexStr",argv[1])))
	{
		buf_len=base64_decode(argv[2],buf_arr);
		printf("String = [%s] strlen=[%d] \n",buf_arr,buf_len);
		str_len=arrayToStr(buf_arr,buf_len,outstr);
		printf("str_len=[%d],out = [ %s ]\n",str_len,outstr);
	}
	else if((argc>1)&&(!strcmp("HexStr2Base",argv[1])))
	{
		buf_len=HexStringToAsc(argv[2],buf_arr);
		//printf("str_len=[%d],len=[%ld]\n",buf_len,strlen(buf_arr));
		str_len=base64_encode(buf_arr,buf_len,outstr);
		printf("str_len=[%d],out = [ %s ]\n",str_len,outstr);
	}
	else if((argc>3)&&(!strcmp("senddata",argv[1])))
	{
		str_len=HexStringToAsc(argv[4],asn_arr);
		printf("argv[4]=[%s],asn_arr=[%s],str_len=[%d],len=[%ld]\n",argv[4],asn_arr,str_len,strlen(asn_arr));
		SendbyPost(argv[2],argv[3],asn_arr,str_len,outstr);
		ret=splitRecvPkg(outstr);
		//printf("recv [%d] arrs!",ret);
		printrespond();
	}
	else if((argc>3)&&(!strcmp("sendoer",argv[1])))
	{
		buf_len=ReadBinToarr(argv[4],buf_arr);
		printf("filename=[%s],len=[%d]\n",argv[4],buf_len);
		SendbyPost(argv[2],argv[3],buf_arr,buf_len,outstr);
		ret=splitRecvPkg(outstr);
		//printf("recv [%d] arrs!",ret);
		printrespond();
	}
	else if((argc>1)&&(!strcmp("sm3file",argv[1])))
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
	else if((argc>1)&&(!strcmp("sm3string",argv[1])))
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
	else
	{
		Useage();
	}
	
	return 0;

}

