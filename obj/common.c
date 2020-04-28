#include "common.h"


unsigned char CharToHex(unsigned char bHex){
    if((bHex>=0)&&(bHex<=9))
        bHex += 0x30;
    else if((bHex>=10)&&(bHex<=15))//��д��ĸ
        bHex += 0x37;
    else bHex = 0xff;
    return bHex;
}
unsigned char HexToChar(unsigned char bChar){
    if((bChar>=0x30)&&(bChar<=0x39))
        bChar -= 0x30;
    else if((bChar>=0x41)&&(bChar<=0x46))//��д��ĸ
        bChar -= 0x37;
    else if((bChar>=0x61)&&(bChar<=0x66))//Сд��ĸ
        bChar -= 0x57;
    else bChar = 0xff;
    return bChar;
}


int AscString2HexString(unsigned char *str,unsigned int str_len,char *out)
{
	int i=0;
	i=arrayToStr(str,str_len,out);
	return i;
}


int HexStringToAsc(const char *str,unsigned char *out)
{
    const char *p = str;
    char high = 0, low = 0;
    int tmplen = strlen(p), cnt = 0;
    tmplen = strlen(p);
    while(cnt < (tmplen/2))
    {	
//    	printf("*p=[%c]\n",*p);
        high = ((*p > '9') && ((*p <= 'F') || (*p <= 'f'))) ? *p-48-7 : *p-48;
        low = (*(++p) > '9' && ((*p <= 'F') || (*p <= 'f'))) ? *(p)-48-7 : *(p)-48;
 //       printf("%X,%X \n",high,low);
        out[cnt] = ((high & 0x0f) << 4 | (low & 0x0f));
        p++;
        cnt++;
    }
    if(tmplen%2 != 0) 
        out[cnt] = ((*p > '9') && ((*p <= 'F') || (*p <= 'f'))) ? *p-48-7 : *p-48;
    
//    if(outlen != NULL) 
//    	*outlen = tmplen/2 + tmplen%2;
    return tmplen/2 + tmplen%2;
}

int arrayToStr(unsigned char *buf, unsigned int buflen,unsigned char *out)
{
    char strBuf[4096] = {0};
    char pbuf[4096];
    int i;
    for(i = 0; i < buflen; i++)
    {
        sprintf(pbuf, "%02X", buf[i]);
        strncat(strBuf, pbuf, 2);
    }
    strncpy(out, strBuf, buflen*2);
    //printf("out = [ %s ]\n", out);
    return buflen*2;
}



void AscStringSaveToBin(const char *filename,const char *str,unsigned int str_len)
{
    FILE *fp;
    int i;
	if((fp = fopen(filename,"wb")) != NULL)
	{
		 for(i=0;i < str_len; i=i+2)
		 {
	    	fwrite(str,sizeof(unsigned char),2,fp);
	    	str=str+2;
	    }
	    fclose(fp);
	}
}

int ReadBinToarr(const char * filename,unsigned char *buf_arr)
{
	int i=0;
    FILE *fp_r = NULL;
    if(NULL != (fp_r = fopen(filename, "r")))
    {
    	while(!feof(fp_r))
		{
		    fread(&buf_arr[i], sizeof(char), 1, fp_r);
		    //printf("0x%x, ", buf_arr[i]);
		    i++;
		}
		//printf("\n");
		fclose(fp_r);
    }
    return i-1;
}


int base64_encode(unsigned char *str,unsigned int str_len,unsigned char *res_out)  
{  
    long len;  
    //long str_len;  
    //unsigned char *res;  
    int i,j;  
//����base64�����  
    unsigned char *base64_table="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";  
  
//���㾭��base64�������ַ�������  
    //str_len=strlen(str);  
    if(str_len % 3 == 0)  
        len=str_len/3*4;  
    else  
        len=(str_len/3+1)*4;  
  	//printf("str_len=[%d],len=[%d]\n",str_len,len);
    //res=malloc(sizeof(unsigned char)*len+1);  
    res_out[len]='\0';  
  
//��3��8λ�ַ�Ϊһ����б���  
    for(i=0,j=0;i<len-2;j+=3,i+=4)  
    {  
        res_out[i]=base64_table[str[j]>>2]; //ȡ����һ���ַ���ǰ6λ���ҳ���Ӧ�Ľ���ַ�  
        res_out[i+1]=base64_table[(str[j]&0x3)<<4 | (str[j+1]>>4)]; //����һ���ַ��ĺ�λ��ڶ����ַ���ǰ4λ������ϲ��ҵ���Ӧ�Ľ���ַ�  
        res_out[i+2]=base64_table[(str[j+1]&0xf)<<2 | (str[j+2]>>6)]; //���ڶ����ַ��ĺ�4λ��������ַ���ǰ2λ��ϲ��ҳ���Ӧ�Ľ���ַ�  
        res_out[i+3]=base64_table[str[j+2]&0x3f]; //ȡ���������ַ��ĺ�6λ���ҳ�����ַ�  
    }  
  
    switch(str_len % 3)  
    {  
        case 1:  
            res_out[i-2]='=';  
            res_out[i-1]='=';  
            break;  
        case 2:  
            res_out[i-1]='=';  
            break;  
    }  
  
    return len;  
} 

int base64_decode(const char *code,unsigned char *res_out)  //need free
{  
//����base64�����ַ��ҵ���Ӧ��ʮ��������  
    int table[]={0,0,0,0,0,0,0,0,0,0,0,0,
    		 0,0,0,0,0,0,0,0,0,0,0,0,
    		 0,0,0,0,0,0,0,0,0,0,0,0,
    		 0,0,0,0,0,0,0,62,0,0,0,
    		 63,52,53,54,55,56,57,58,
    		 59,60,61,0,0,0,0,0,0,0,0,
    		 1,2,3,4,5,6,7,8,9,10,11,12,
    		 13,14,15,16,17,18,19,20,21,
    		 22,23,24,25,0,0,0,0,0,0,26,
    		 27,28,29,30,31,32,33,34,35,
    		 36,37,38,39,40,41,42,43,44,
    		 45,46,47,48,49,50,51
    	       };  
    long len;  
    long str_len;  
 //   unsigned char *res;  
    int i,j;  
  
//����������ַ�������  
    len=strlen(code);

//�жϱ������ַ������Ƿ���=  
    if(strstr(code,"=="))  
        str_len=len/4*3-2;  
    else if(strstr(code,"="))  
        str_len=len/4*3-1;  
    else  
        str_len=len/4*3;  
  
//    res=malloc(sizeof(unsigned char)*str_len+1);  
    res_out[str_len]='\0';  

//��4���ַ�Ϊһλ���н���  
    for(i=0,j=0;i < len-2;j+=3,i+=4)  
    {  
        res_out[j]=((unsigned char)table[code[i]])<<2 | (((unsigned char)table[code[i+1]])>>4); //ȡ����һ���ַ���Ӧbase64���ʮ��������ǰ6λ��ڶ����ַ���Ӧbase64���ʮ�������ĺ�2λ�������  
        res_out[j+1]=(((unsigned char)table[code[i+1]])<<4) | (((unsigned char)table[code[i+2]])>>2); //ȡ���ڶ����ַ���Ӧbase64���ʮ�������ĺ�4λ��������ַ���Ӧbas464���ʮ�������ĺ�4λ�������  
        res_out[j+2]=(((unsigned char)table[code[i+2]])<<6) | ((unsigned char)table[code[i+3]]); //ȡ���������ַ���Ӧbase64���ʮ�������ĺ�2λ���4���ַ��������  
    }  
  
    return str_len;  
  
}


char *memcat(void *dest, unsigned int dest_len, const char *src, unsigned int src_len)
{
	memcpy(dest+dest_len, src, src_len);
	return dest;
}

int getnum(char *instr)
{
	int i=0;
	while('\0' != *instr)
	{
		if(*instr >='0' && *instr <='9')
		{
			*instr++;
			i++;
		}
		else
			break;
	}
	return i;
}

void print_HexString(unsigned char *input,unsigned int str_len,unsigned char *input_name)
{
	unsigned char outstr[4096]={0};

	memset(outstr,0,sizeof(char)*32);
	str_len=AscString2HexString((unsigned char *)input,str_len,outstr);
	printf("[%s] =====> [ %s ],str_len=[%d]\n",input_name,outstr,str_len);

}

void print_bn(char *pchT, BIGNUM* pBG_p)
{
	unsigned char aucY[1024+1] = {0};
	int iYLen = 0;
	
	iYLen = BN_bn2bin ( pBG_p, aucY);
	print_HexString(aucY, iYLen,pchT);
}


void init_curve_param(int curve_type)
{
	if(fp256==curve_type)
	{
		HexStringToAsc(_P,g_sm2_P);
		HexStringToAsc(_a,g_sm2_a);
		HexStringToAsc(_b,g_sm2_b);
		HexStringToAsc(_n,g_sm2_n);
		HexStringToAsc(_Gx,g_sm2_Gx);
		HexStringToAsc(_Gy,g_sm2_Gy);
	}
	else
		printf("This curve is not currently supported !\n");
}


