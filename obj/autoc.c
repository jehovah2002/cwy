#include "autoc.h"
#include "common.h"


cicvserverRequest serverRequest={0};
cicvserverRespond serverRespond={0};
char *res_head="HTTP/1.1";
char *res_errnum="CSCMS-Error: ";
char *res_errmsg="CSCMS-Error-Message: ";
char *res_type="Content-Type: ";
char *res_length="Content-Length: ";
char *res_date="Date: ";
char *res_end="Connection: close";

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


