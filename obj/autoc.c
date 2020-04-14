#include "autoc.h"

cicvserverRequest serverRequest={0};
cicvserverRespond serverRespond={0};
char *res_head="HTTP/1.1";
char *res_errnum="CSCMS-Error: ";
char *res_errmsg="CSCMS-Error-Message: ";
char *res_type="Content-Type: ";
char *res_length="Content-Length: ";
char *res_date="Date: ";
char *res_end="Connection: close";


unsigned char CharToHex(unsigned char bHex){
    if((bHex>=0)&&(bHex<=9))
        bHex += 0x30;
    else if((bHex>=10)&&(bHex<=15))//大写字母
        bHex += 0x37;
    else bHex = 0xff;
    return bHex;
}
unsigned char HexToChar(unsigned char bChar){
    if((bChar>=0x30)&&(bChar<=0x39))
        bChar -= 0x30;
    else if((bChar>=0x41)&&(bChar<=0x46))//大写字母
        bChar -= 0x37;
    else if((bChar>=0x61)&&(bChar<=0x66))//小写字母
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
//定义base64编码表  
    unsigned char *base64_table="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";  
  
//计算经过base64编码后的字符串长度  
    //str_len=strlen(str);  
    if(str_len % 3 == 0)  
        len=str_len/3*4;  
    else  
        len=(str_len/3+1)*4;  
  	//printf("str_len=[%d],len=[%d]\n",str_len,len);
    //res=malloc(sizeof(unsigned char)*len+1);  
    res_out[len]='\0';  
  
//以3个8位字符为一组进行编码  
    for(i=0,j=0;i<len-2;j+=3,i+=4)  
    {  
        res_out[i]=base64_table[str[j]>>2]; //取出第一个字符的前6位并找出对应的结果字符  
        res_out[i+1]=base64_table[(str[j]&0x3)<<4 | (str[j+1]>>4)]; //将第一个字符的后位与第二个字符的前4位进行组合并找到对应的结果字符  
        res_out[i+2]=base64_table[(str[j+1]&0xf)<<2 | (str[j+2]>>6)]; //将第二个字符的后4位与第三个字符的前2位组合并找出对应的结果字符  
        res_out[i+3]=base64_table[str[j+2]&0x3f]; //取出第三个字符的后6位并找出结果字符  
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
//根据base64表，以字符找到对应的十进制数据  
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
  
//计算解码后的字符串长度  
    len=strlen(code);

//判断编码后的字符串后是否有=  
    if(strstr(code,"=="))  
        str_len=len/4*3-2;  
    else if(strstr(code,"="))  
        str_len=len/4*3-1;  
    else  
        str_len=len/4*3;  
  
//    res=malloc(sizeof(unsigned char)*str_len+1);  
    res_out[str_len]='\0';  

//以4个字符为一位进行解码  
    for(i=0,j=0;i < len-2;j+=3,i+=4)  
    {  
        res_out[j]=((unsigned char)table[code[i]])<<2 | (((unsigned char)table[code[i+1]])>>4); //取出第一个字符对应base64表的十进制数的前6位与第二个字符对应base64表的十进制数的后2位进行组合  
        res_out[j+1]=(((unsigned char)table[code[i+1]])<<4) | (((unsigned char)table[code[i+2]])>>2); //取出第二个字符对应base64表的十进制数的后4位与第三个字符对应bas464表的十进制数的后4位进行组合  
        res_out[j+2]=(((unsigned char)table[code[i+2]])<<6) | ((unsigned char)table[code[i+3]]); //取出第三个字符对应base64表的十进制数的后2位与第4个字符进行组合  
    }  
  
    return str_len;  
  
}


char *memcat(void *dest, unsigned int dest_len, const char *src, unsigned int src_len)
{
	memcpy(dest+dest_len, src, src_len);
	return dest;
}

int jointPostPkg(const char *IPSTR,const char *PORT,unsigned const char *str,int str_len,char *res_out)
{
	int strlen_buf=0;
	char short_buf[4]={0};
	//add enum for path
	memset(res_out, 0, 4096);
	strcat(res_out, "POST /self-enrollment-certificate HTTP/1.1\n");
	strcat(res_out, "Host: ");
	strcat(res_out, IPSTR);
	strcat(res_out, ":");
	strcat(res_out, PORT);
	strcat(res_out, "\n");
	strcat(res_out, "Accept: */*\n");
	strcat(res_out, "Content-Type: application/octet-stream\n");
	strcat(res_out, "Content-Length: ");
	sprintf(short_buf, "%d", str_len);
	strcat(res_out, short_buf);
	strcat(res_out, "\n\n");
	strlen_buf=strlen(res_out);
	res_out=memcat(res_out, sizeof(char)*strlen_buf,str,sizeof(char)*str_len);
	return strlen_buf+str_len;
	
}

int SendbyPost(const char *IPSTR,const char *PORT,unsigned const char *str,int str_len,unsigned char *res)
{
	int sockfd, ret, i, h;
	struct sockaddr_in servaddr;
	char strbuf[4096]={0};
	fd_set   t_set1;
	struct timeval  tv;
	
	int strlen_buf=0;


	if (0>(ret=(sockfd = socket(AF_INET, SOCK_STREAM, 0)))) 
	{
        printf("Create socket failed!\n");
        return ret;
	};
//	printf("socket fd =[%d]\n",sockfd);

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(atoi(PORT));
	servaddr.sin_addr.s_addr = inet_addr(IPSTR); 


	if (0>(ret=connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)))){
        printf("connect error !\n");
        return ret;
	}
	printf("Connect success !\n");

	strlen_buf=jointPostPkg(IPSTR,PORT,str,str_len,strbuf);
	//printf("strlen_buf=[%d],strbuf=[%s]\n",strlen_buf,strbuf);
	
	ret = write(sockfd,strbuf,strlen_buf);
	if (ret < 0) {
        printf("Send error ! error code =[%d] , error message =[%s]\n",errno, strerror(errno));
        return ret;
	}
	else
	{
        printf("Send success for [%d] bytes !\n\n", ret);
	}
	//str的值为post的数据



	FD_ZERO(&t_set1);
	FD_SET(sockfd, &t_set1);

	tv.tv_sec= 1;
	tv.tv_usec= 0;
	h= 0;

	while(1)
	{
		h = select(sockfd +1, &t_set1, NULL, NULL, &tv);
		if (h == -1) {
			close(sockfd);
			printf("Socket error! Read failed !\n");
			return -1;
		};
		if ( FD_ISSET(sockfd, &t_set1) )
		{
			memset(res, 0, 4096);
			i= read(sockfd, res, 4095);
			if (i==0){
				close(sockfd);
				printf("Cannot connect to server !\n");
				return -1;
			}
			//printf("%s\n", res);
			break;
		}
	}
	close(sockfd);
	return 0;
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

void respondSave(char *instr,int flag)
{
	char buf[4096]={0};
	//printf("flag=[%d]\n",flag);
	//printf("instr=[%s]\n",instr);
	if(!flag)
	{
		if(!strncmp(instr,res_head,strlen(res_head))){
			instr=instr+strlen(res_head);
			//printf("instr=[%s],len=[%ld]\n",instr,strlen(res_head));
			memcpy(serverRespond.res,instr,strlen(instr));
		}
		else if(!strncmp(instr,res_errnum,strlen(res_errnum))){
			instr=instr+strlen(res_errnum);
			//printf("instr=[%s],len=[%ld],getnum(instr)=[%d]\n",instr,strlen(res_errnum),getnum(instr));
			memcpy(serverRespond.errnum,instr,getnum(instr));
			//printf("buf=[%s]\n",buf);
			//serverRespond.errnum=atoi(buf);
		}
		else if(!strncmp(instr,res_errmsg,strlen(res_errmsg))){
			instr=instr+strlen(res_errmsg);
			//printf("instr=[%s],len=[%ld]\n",instr,strlen(res_errmsg));
			memcpy(serverRespond.errmsg,instr,strlen(instr));
		}
		else if(!strncmp(instr,res_type,strlen(res_type))){
			instr=instr+strlen(res_type);
			//printf("instr=[%s],len=[%ld]\n",instr,strlen(res_type));
			memcpy(serverRespond.type,instr,strlen(instr));
		}
		else if(!strncmp(instr,res_length,strlen(res_length))){
			instr=instr+strlen(res_length);
			//printf("instr=[%s],len=[%ld],getnum(instr)=[%d]\n",instr,strlen(res_length),getnum(instr));
			memcpy(serverRespond.length,instr,getnum(instr));
			//printf("buf=[%s]\n",buf);
			//serverRespond.length=atoi(buf);
		}
		else if(!strncmp(instr,res_date,strlen(res_date))){
			instr=instr+strlen(res_date);
			//printf("instr=[%s],len=[%ld]\n",instr,strlen(res_date));
			memcpy(serverRespond.date,instr,strlen(instr));
		}
	}
	else
	{
		if(strncmp(instr,res_end,strlen(res_end))){
			arrayToStr(instr,atoi(serverRespond.length),serverRespond.str);
		}	
	}
}

int splitRecvPkg(unsigned char *instr)
{
	char *p=NULL;
	char *q=NULL;
	int i=0;
	char outstr[4096]={0};
	char buf[4096]={0};
	int flag=0;
	
	q=p=instr;
	p = memchr(p,'\r',strlen(p));
	memcpy(outstr,instr,p-q);
	//printf("outstr[%d]=[%s]\n",i,&outstr[i]);
	respondSave(outstr,flag);
	i++;
	while(1)
	{
		memset(outstr,0,sizeof(outstr));
		if(*(p+1) == '\n')
		{
			/*if the pkg is over ?\r\n\r\n*/
			if(*(p+2) == '\r')
			{
				flag=1;
				p=p+4;
				respondSave(p,flag);
				break;
			}
			p = p+2;
		}
		q=p;
		memset(buf,0,sizeof(buf));
		memcpy(buf,p,strlen(p));
		p = memchr(p,'\r',strlen(p));
		memcpy(outstr,buf,p-q);
		//printf("outstr[%d]=[%s]\n",i,&outstr[i]);
		respondSave(outstr,flag);
	}
	return i;

}


void printrespond()
{
	if(0 < strlen(serverRespond.res))
		printf("serverRespond head=[%s]\n",serverRespond.res);
	if(0 < strlen(serverRespond.type))
		printf("serverRespond type=[%s]\n",serverRespond.type);
	if(0 < strlen(serverRespond.errnum))
		printf("serverRespond errnum=[%s]\n",serverRespond.errnum);
	if(0 < strlen(serverRespond.errmsg))
		printf("serverRespond errmsg=[%s]\n",serverRespond.errmsg);
	if(0 < strlen(serverRespond.length))
		printf("serverRespond length=[%s]\n",serverRespond.length);
	if(0 < strlen(serverRespond.date))
		printf("serverRespond date=[%s]\n",serverRespond.date);
	if(0 < strlen(serverRespond.str))
		printf("serverRespond str=[%s]\n",serverRespond.str);

}


