#include "autoc.h"

void Useage()
{
	printf("**************************************************\n");
	printf("***  cmd:[Hex2File] <filename> <Str>           ***\n");
	printf("***       Save Hex string to bin file.         ***\n");
	printf("***  cmd:[File2Hex] <filename>                 ***\n");
	printf("***       return:<Hex String>                  ***\n");
	printf("***       Read bin file and print Hex string   ***\n");
	printf("***  cmd:[B642Hex] <Base 64 Str>               ***\n");
	printf("***       return:<Hex String>                  ***\n");
	printf("***       Read bin file and print Hex string   ***\n");
	printf("***  cmd:[senddata] <host ip> <port> <str>     ***\n");
	printf("***       return:<Response>                    ***\n");
	printf("***       Send HexString to server             ***\n");
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
		str_len=HexStringToHex(argv[3],outstr);
		printf("argv[3]=[%s],outstr=[%s],str_len=[%d],len=[%ld]\n",argv[3],outstr,str_len,strlen(outstr));
		StringSaveToBin(argv[2],outstr,str_len);
	}
	else if((argc>1)&&(!strcmp("File2Hex",argv[1])))
	{
		buf_len=ReadBinToarr(argv[2],buf_arr);
		arrayToStr(buf_arr,buf_len,outstr);
	}
	else if((argc>1)&&(!strcmp("B642Hex",argv[1])))
	{
		str_len=base64_decode(argv[2],buf_arr);
		printf("String = [%s] strlen=[%d] \n",buf_arr,str_len);
		arrayToStr(buf_arr,str_len,outstr);

	}
	else if((argc>3)&&(!strcmp("senddata",argv[1])))
	{
		str_len=HexStringToHex(argv[4],asn_arr);
		printf("argv[4]=[%s],asn_arr=[%s],str_len=[%d],len=[%ld]\n",argv[4],asn_arr,str_len,strlen(asn_arr));
		SendbyPost(argv[2],argv[3],asn_arr,str_len,outstr);
		ret=splitRecvPkg(outstr);
		//printf("recv [%d] arrs!",ret);
		printrespond();
	}
	else
	{
		Useage();
	}
	
	return 0;

}

