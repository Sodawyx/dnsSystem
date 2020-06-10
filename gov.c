#include<stdio.h>
#include<sys/types.h>
#include<string.h>
#include<unistd.h>
#include<netinet/in.h>
#include<sys/socket.h>
#include<unistd.h>
#include<stdlib.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<stdint.h>
#include "DNS.h"
#define LINE     10
#define DNS_MAX_LENGTH 1023

unsigned int getHeader(char *q, dns_header *header);
unsigned int getQuery(char *q, dns_query *query);
int isequal(char *str1, char* str2);
unsigned int rr2buf(char *o, dns_rr* rr);
unsigned int query2buf(char *o, dns_query *query);
unsigned int head2buf(char *o, dns_header *header);
unsigned int add2buf(char *o, dns_rr* rr, dns_query* query);
void init_sockaddr_in(char* ip, int port, struct sockaddr_in* addr);
int main(){
	int state=0;  //查到没有 
	int sockup;
	struct sockaddr_in localAddr;
	struct sockaddr_in upAddr;
	struct sockaddr_in downAddr;
	unsigned int upAddrLen;
	char upInBuffer[DNS_MAX_LENGTH];
	char upOutBuffer[DNS_MAX_LENGTH];
	unsigned short port=53;
	int recvMsgSize;
	int outMsgSize; 
	char ipAddr[100];
	//不需要分割名字，因为已经是最底层服务器，拿文件查询即可 
	
	//接受的结构体 
	dns_query *recvQuery = (dns_query *)malloc(sizeof(dns_query));initQuery(recvQuery);
	dns_header *recvHead = (dns_header *)malloc(sizeof(dns_header));initHead(recvHead);
	dns_rr *recvrRecord = (dns_rr *)malloc(sizeof(dns_rr));initRR(recvrRecord);  
	//回应的结构体 
	dns_query *resQuery = (dns_query *)malloc(sizeof(dns_query));initQuery(resQuery);
	dns_header *resHead = (dns_header *)malloc(sizeof(dns_header));initHead(resHead);
	dns_rr *resRecord = (dns_rr *)malloc(sizeof(dns_rr));initRR(resRecord); 
	//MX第二次查询ip
	dns_query *mxQuery = (dns_query *)malloc(sizeof(dns_query));initQuery(mxQuery);
	dns_header *mxHead = (dns_header *)malloc(sizeof(dns_header));initHead(mxHead);
	dns_rr *mxRecord = (dns_rr *)malloc(sizeof(dns_rr));initRR(mxRecord);
	
	
	if((sockup=socket(PF_INET,SOCK_DGRAM,0))<0)  printf("socket() failed\n");
	
	init_sockaddr_in("127.0.0.7", 53, &localAddr);
	if((bind (sockup,(struct sockaddr*)&localAddr,sizeof(localAddr)))<0){
		printf("bind() failed\n");
	} 
	while(1){
	state=0;
	upAddrLen=sizeof(upAddr);
	//receive
	if((recvMsgSize=recvfrom(sockup,upInBuffer,DNS_MAX_LENGTH,0,(struct sockaddr*)&upAddr,&upAddrLen))<0){
		printf("recvfrom() failed\n");
	}
	printf("Handling client %s\n",inet_ntoa(upAddr.sin_addr));
	
	//解析 
	char *i = upInBuffer;
	i += getHeader(i, recvHead);
	i += getQuery(i, recvQuery); 	
	//printf("The domain name is: %s\n", recvQuery->name);
	
    //以下为回应的部分
	resHead->id =htons(recvHead->id);
	resHead->tag =htons(0x8000);
	resHead->queryNum =htons(recvHead->queryNum);
	resHead->answerNum = htons(1); //这里不一定是1，若没查到怎么办？？ 
	resHead->authorNum = 0;
	resHead->addNum = 0;
	resQuery = recvQuery;
	resRecord->name=recvQuery->name;
    resRecord->rclass=recvQuery->qclass;
	resRecord->type=recvQuery->qtype;
	resRecord->ttl = (uint32_t)86400;
	resRecord->data_len = 4;
	
	/*
	 *返回查询结果 
	 */
	 if(recvQuery->qtype==A_TYPE){
	   freopen("govA.txt", "r", stdin);
	   char file_name[255],file_ttl[255],file_class[255],file_type[255],file_ip[255];
	    while(~scanf("%s%s%s%s%s", file_name, file_ttl, file_class,file_type,file_ip)){
	    	if(isequal(recvQuery->name,file_name)){
	    		printf("file_name: %s\n",file_name);
	    		printf("file_ttl: %s\n",file_ttl);
	    		printf("file_class； %s\n",file_class);
	    		printf("file_type: %s\n",file_type);
	    		printf("file_ip: %s\n",file_ip);
	    		//printf("recv->Query: %s\n",recvQuery->name);
	    		//在结构体里把rdata赋值为 file_ip ,在head里把anwernum赋值为1,flag为8180 
	    		resRecord->name = (char*)malloc((strlen(file_name)+1)*sizeof(char));
				strcpy(resRecord->name, file_name);
				resRecord->ttl = (uint32_t)(atoi(file_ttl));
				resRecord->rdata = (char*)malloc((strlen(file_ip)+1)*sizeof(char));
				strcpy(resRecord->rdata, file_ip);
				resRecord->data_len=strlen(resRecord->rdata)+1;
				resHead->answerNum = htons(1);
				resHead->tag = htons(0x8180);
	    		state=1;   //表明查到 
	    		break;
			}
		}  
	}
	else if(recvQuery->qtype==CNAME_TYPE){
	 freopen("govC.txt", "r", stdin);
	   char file_name[255],file_ttl[255],file_class[255],file_type[255],file_addr[255];
	    while(~scanf("%s%s%s%s%s", file_name, file_ttl, file_class,file_type,file_addr)){
	    	if(isequal(recvQuery->name,file_name)){
	    		printf("file_name: %s\n",file_name);
	    		printf("file_ttl: %s\n",file_ttl);
	    		printf("file_class； %s\n",file_class);
	    		printf("file_type: %s\n",file_type);
	    		printf("file_addr: %s\n",file_addr);
	    		//printf("recv->Query: %s\n",recvQuery->name);
	    		//在结构体里把rdata赋值为 file_ip ,在head里把anwernum赋值为1,flag为8180 
	    		resRecord->name = (char*)malloc((strlen(file_name)+1)*sizeof(char));
				strcpy(resRecord->name, file_name);
				resRecord->ttl = (uint32_t)(atoi(file_ttl));
				resRecord->rdata = (char*)malloc((strlen(file_addr)+1)*sizeof(char));
				strcpy(resRecord->rdata, file_addr);
				resRecord->data_len=strlen(resRecord->rdata)+1;
				resHead->answerNum = htons(1);
				resHead->tag = htons(0x8180);
	    		state=1;   //表明查到 
	    		break;
			}
		}  	
	}
	else if(recvQuery->qtype==MX_TYPE){
		//printf("in file M\n");
		freopen("govM.txt", "r", stdin);
		printf("flag1\n"); 
	   char file_name[255],file_ttl[255],file_class[255],file_type[255],file_addr[255];
	    while(~scanf("%s%s%s%s%s", file_name, file_ttl, file_class,file_type,file_addr)){
	    	//printf("flag2\n");
	    	if(isequal(recvQuery->name,file_name)){
	    		printf("file_name: %s\n",file_name);
	    		printf("file_name length: %d\n",strlen(file_name));
	    		printf("file_ttl: %s\n",file_ttl);
	    		printf("file_class； %s\n",file_class);
	    		printf("file_type: %s\n",file_type);
	    		printf("file_addr: %s\n",file_addr);
				//不确定你从文件里读出来的是什么样子的，含不含空格，长度下面有可能不对

				resRecord->name = (char*)malloc((strlen(file_name)+1)*sizeof(char));
				strcpy(resRecord->name, file_name);
				resRecord->ttl = (uint32_t)(atoi(file_ttl));
				resRecord->rdata = (char*)malloc((strlen(file_addr)+1)*sizeof(char));
				strcpy(resRecord->rdata, file_addr);
				resHead->answerNum = htons(1);
				//这里用现在的域名减去查询的名字长度再+2(pre..)+2(压缩指针)
		        resRecord->data_len = strlen(resRecord->rdata)-strlen(recvQuery->name) + 4;
				resHead->tag = htons(0x8180);

	    		//printf("recv->Query: %s\n",recvQuery->name);
	    		//在结构体里把rdata赋值为 file_ip ,在head里把anwernum赋值为1，flag为8180 
	    		state=1;   //表明查到 
	    		break;
			}
		} 
		if(state==1){
		mxQuery->name = (char*)malloc((strlen(resRecord->rdata)+1)*sizeof(char));
		strcpy(mxQuery->name, resRecord->rdata);
		//printf("mxQueryName: %s\n", mxQuery->name);
		mxQuery->qclass = recvQuery->qclass;
		mxQuery->qtype = A_TYPE; //这里要用上一次的结果A方式查询一下
		freopen("govA.txt", "r", stdin);
	    char file_ip[255];
	    while(~scanf("%s%s%s%s%s", file_name, file_ttl, file_class,file_type,file_ip)){
	    	if(isequal(mxQuery->name,file_name)){
	    		printf("file_name: %s\n",file_name);
	    		printf("file_name length: %d\n",strlen(file_name));
	    		printf("file_ttl: %s\n",file_ttl);
	    		printf("file_class； %s\n",file_class);
	    		printf("file_type: %s\n",file_type);
	    		printf("file_ip: %s\n",file_ip);
				//不确定你从文件里读出来的是什么样子的，含不含空格，长度下面有可能不对	
		    	mxRecord->name = (char*)malloc((strlen(file_name)+1)*sizeof(char));
				strcpy(mxRecord->name, file_name);
				mxRecord->ttl = (uint32_t)(atoi(file_ttl));
				mxRecord->rdata = (char*)malloc((strlen(file_addr)+1)*sizeof(char));
				strcpy(mxRecord->rdata, file_ip);
				mxRecord->data_len=4;
				mxRecord->type=A_TYPE; 
	            mxRecord->rclass=recvQuery->qclass;
                resHead->addNum = htons(1); 

	    		//printf("recv->Query: %s\n",recvQuery->name);
	    		//在结构体里把rdata赋值为 file_ip ,在head里把anwernum赋值为1，flag为8180 
	    		state=1;   //表明查到 
	    		break;
			}
		}
	  }
	 }
	 	  
	//printf("state %d\n",state);
	char* o=upOutBuffer;
	if(state==0){
		resHead->tag =htons(0x8183);
		resHead->answerNum = 0;
	 	o = upOutBuffer; 
		o += head2buf(o, resHead);
	 	o += query2buf(o,resQuery);    
	}else{
		o = upOutBuffer; 
	 	o += head2buf(o, resHead);
	 	o += query2buf(o,resQuery); 
	 	o += rr2buf(o,resRecord);
	 	if(recvQuery->qtype == MX_TYPE)
	 	o+=add2buf(o, mxRecord, recvQuery);
	}
    
    
	 

	//统一返回
	//把upOutBuffer赋值 
	outMsgSize = o - upOutBuffer + 1;
	//printf("length:%d \n",outMsgSize);
	if(sendto(sockup,upOutBuffer,outMsgSize,0,(struct sockaddr*)&upAddr,sizeof(upAddr))!=outMsgSize){
		printf("sendto() problem!\n");
	}
  }
	
}	
unsigned int head2buf(char *o, dns_header *head){
	memcpy(o, head, sizeof(dns_header));
	//////////////////////////////////////////////没转主机字节序！！！！！ 
	return sizeof(dns_header);
}

void init_sockaddr_in(char* ip, int port, struct sockaddr_in* addr){
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    addr->sin_addr.s_addr=inet_addr(ip);
    memset(addr->sin_zero, 0, sizeof(addr->sin_zero));
}

unsigned int getHeader(char *q, dns_header *header){
	// int i = 0;
	// while(1){
	// 	if(i<100){
	// 		printf("headerIn: %d\n", q[i]);i++;
	// 	}
		
	// 	else break;
	// }
	
	header->id = ntohs(*(uint16_t*) (q));
	header->tag = ntohs(*(uint16_t*) (q+2));
	header->queryNum = ntohs(*(uint16_t*) (q+4));
	printf("queryName: %d\n", header->id);
	header->answerNum = ntohs(*(uint16_t*) (q+6));
	header->authorNum = ntohs(*(uint16_t*) (q+8));
	header->addNum = ntohs(*(uint16_t*) (q+10));
	
	return sizeof(dns_header);
}

//下面这三个函数和localServer中的一样，可以考虑打包进.h 
unsigned int getQuery(char *q, dns_query *query){
	char domainName[100];
	memset(domainName, 0, 100);
	char *d = domainName;
	printf("d: %s\n", d);
	uint8_t count = 0;
	int i = 0; 
	//count = ntohs(*(uint8_t*)(q));
	//完成报文中数字加域名形式至点分值的转换 
	while(1){
		if(*q!='\0'){
			count = *(uint8_t*)(q);
			//printf("count:%d\n", count);
			q++;
			while(count){
				//printf("i: %d\n", i);
				//printf("char1:%c\n", *q);
				memcpy(&(domainName[i]), q, sizeof(char));
				//printf("domain name i: %c\n", domainName[i]);
				count--; q++; i++;
			}
			domainName[i] = '.'; //加点 
			i++;
		}
		else{
			domainName[i-1] = '\0'; //标注结束 
			q++; 
			break;
		}
	}
	// printf("i: %d\n", i);  
	// printf("Converted domain name: %s\n", domainName);
	// printf("length: %d\n", i);
	query->name = (char*)malloc(i*sizeof(char));
	memcpy(query->name, domainName, i); //此时的i便为转换后变长字符串的长度了，经过了循环遍历 
	//printf("Query name: %s\n", query->name);
	
	query->qtype = ntohs(*(uint16_t*) (q));
	query->qclass = ntohs(*(uint16_t*) (q+2));
	//printf("Query Type: %d\n", query->qtype);
	//printf("Query Class: %d\n", query->qclass);
	return i+4+1; //补一个1的原因是网络的域名形式和转换后的差一位 
}

unsigned int query2buf(char *o, dns_query *query){
	char* ini = o; //for initial
	uint8_t count = 0;
	int i = 0;
	int j = 1; //转换后计数 
	int tempts = 0;
	o++; //先往后移动一位 
	while(1){
		//printf("get: %c\n", query->name[i]);
		if(query->name[i] == '.'){
				memcpy(o-count-1, &count, sizeof(char));
				//printf("Count: %d\n", count);
				count = 0;
				o++; i++;
				tempts = 1;
				
		}
		else if(query->name[i] == '\0'){
			memcpy(o, &(query->name[i]), sizeof(char));
			memcpy(o-count-1, &count, sizeof(char));
			count = 0;
			break;
		}
		else{
			memcpy(o, &(query->name[i]), sizeof(char));
			o++;
			i++;
			count++; 
		}
	}
	o++;
	int len = o - ini; //计算出名字的长度
	//printf("length: %d\n", len); 
	uint16_t temp = htons(query->qtype);
	memcpy(o, &temp, sizeof(short));
	temp = htons(query->qclass);
	o+=sizeof(short);
	memcpy(o, &temp, sizeof(short));
	o+=sizeof(short);
//	int p=0;
//	while(p<=100){
//	printf("buff1: %hu\n", o[p]);
//	p++;
//	}
	//printf("length22: %d\n",  len+2*sizeof(short)); 
	return len+2*sizeof(short);
}

unsigned int rr2buf(char *o, dns_rr* rr) {
	int i = 0;
	uint16_t temp;
	uint32_t temp32;
	temp =  htons(49164); //这里指代1100000000001100，DNS报文中压缩指针的操作
	memcpy(o, &temp, sizeof(short)); 
	
//	printf("rr2leng: %d\n", strlen(rr->name));
//	memcpy(o,rr->name,strlen(rr->name)+1);
//	while(1){
//		printf("ccc: %c\n", o[i]);
//		i++;
//		if(i == 5) break;
//	}
//	printf("rrName: %s\n", o);
	o+=2;
	//printf("flag3\n");
	temp=htons(rr->type);
	memcpy(o, &temp, sizeof(short));
	//printf("rrType: %d\n", rr->type);
	o+=2;
	//printf("flag3\n");
	temp=htons(rr->rclass);
	memcpy(o, &temp, sizeof(short));
	o+=2;
	//printf("flag3\n");
	temp32=htonl(rr->ttl); //这里是htonl 32位数字的主机字节序转化 
	//printf("ttlconvert: %d\n", temp32);
	memcpy(o, &temp32, (2*sizeof(short)));
	o+=4;
	//printf("flag3\n");
	temp=htons(rr->data_len);
	memcpy(o, &temp, sizeof(short));
	o+=2;
	//printf("flag3\n");
	//这里指preference，MX里面要多两个字节哦
	if(rr->type == MX_TYPE){
		temp=htons(1);
		memcpy(o, &temp, sizeof(short));
		o+=2;
	}
	
	if(rr->type == A_TYPE){
		uint32_t  ipAddr = inet_addr(rr->rdata);
		memcpy(o, &ipAddr,rr->data_len); //将字符串转化为网络字节序的4bytes数据 
		//printf("rrDate: %s\n", o);
		o+=rr->data_len; //也就是要移动4位 
		return 16;
	}
	else if(rr->type == CNAME_TYPE){
		char* ini = o; //for initial
	uint8_t count = 0;
	int i = 0;
	int j = 1; //转换后计数 
	int tempts = 0;
	o++; //先往后移动一位 
	while(1){
		//printf("get: %c\n", rr->rdata[i]);
		if(rr->rdata[i] == '.'){
				memcpy(o-count-1, &count, sizeof(char));
				//printf("Count: %d\n", count);
				count = 0;
				o++; i++;
				tempts = 1;
				
		}
		else if(rr->rdata[i] == '\0'){
			memcpy(o, &(rr->rdata[i]), sizeof(char));
			memcpy(o-count-1, &count, sizeof(char));
			count = 0;
			break;
		}
		else{
			memcpy(o, &(rr->rdata[i]), sizeof(char));
			o++;
			i++;
			count++; 
		}
	}
		return 12 + rr->data_len + 1;
	}
	else if(rr->type == MX_TYPE){ //MX的情况
		char* ini = o; //for initial
	uint8_t count = 0;
	int i = 0;
	int j = 1; //转换后计数 
	int tempts = 0;
	o++; //先往后移动一位 
	while(1){
		//printf("get: %c\n", rr->rdata[i]);
		if(rr->rdata[i] == '.'){
				memcpy(o-count-1, &count, sizeof(char));
				//printf("Count: %d\n", count);
				count = 0;
				o++; i++;
				tempts = 1;
				break;
				
		}
		else if(rr->rdata[i] == '\0'){
			memcpy(o, &(rr->rdata[i]), sizeof(char));
			memcpy(o-count-1, &count, sizeof(char));
			count = 0;
			break;
		}
		else{
			memcpy(o, &(rr->rdata[i]), sizeof(char));
			o++;
			i++;
			count++; 
		}
	}
	o--;
	//printf("i=%d\n", i);
	temp =  htons(49164); //这里指代1100000000001100，DNS报文中压缩指针的操作
	memcpy(o, &temp, sizeof(short)); 
	return 16+i;
	}
	
	
}

 //用于MX的ip查询，放到addtion里面
unsigned int add2buf(char *o, dns_rr* rr, dns_query* query) {
	//printf("add2buf rrdata: %s\n", rr->rdata);
	//printf("datalength: %d\n", strlen(rr->rdata));
	int i = 0;
	uint16_t temp;
	uint32_t temp32;
	temp =  htons(49152+12+strlen(query->name)+2+4+14); //这里指代1100000000001100，DNS报文中压缩指针的操作
	memcpy(o, &temp, sizeof(short)); 
//	printf("rr2leng: %d\n", strlen(rr->name));
//	memcpy(o,rr->name,strlen(rr->name)+1);
//	while(1){
//		printf("ccc: %c\n", o[i]);
//		i++;
//		if(i == 5) break;
//	}
//	printf("rrName: %s\n", o);
	o+=2;
	temp=htons(rr->type);
	memcpy(o, &temp, sizeof(short));
	//printf("rrType: %d\n", rr->type);
	o+=2;

	temp=htons(rr->rclass);
	memcpy(o, &temp, sizeof(short));
	o+=2;

	temp32=htonl(rr->ttl); //这里是htonl 32位数字的主机字节序转化 
	//printf("ttlconvert: %d\n", temp32);
	memcpy(o, &temp32, (2*sizeof(short)));
	o+=4;

	temp=htons(rr->data_len);
	memcpy(o, &temp, sizeof(short));
	o+=2;

	
	
	uint32_t  ipAddr = inet_addr(rr->rdata);
	memcpy(o, &ipAddr, rr->data_len); //将字符串转化为网络字节序的4bytes数据 
	//printf("rrDate: %d\n", ipAddr);
	o+=rr->data_len; //也就是要移动4位 
	return 16;


}
 int isequal(char *str1, char* str2)
{
    if (strlen(str1)!=strlen(str2))
     return 0;
     int i=0;
    for (i = 0; str1[i]!='\0'; i++){
        if (str1[i]!=str2[i])
        return 0;
     }
   return 1;
  }
