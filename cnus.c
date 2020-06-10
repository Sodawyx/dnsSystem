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
int isequal(char *str1, char* str2);
void init_sockaddr_in(char* ip, int port, struct sockaddr_in* addr);
unsigned int getHeader(char *q, dns_header *header);
unsigned int getQuery(char *q, dns_query *query);
void splitTwoDomainName(char *domainName, char *splitName);
unsigned int head2buf(char *o, dns_header *header);
unsigned int query2buf(char *o, dns_query *query);
unsigned int getRRs(char *q, dns_rr *rRecord);
unsigned int rr2buf(char *o, dns_rr* rr); 

int main(){
	int sockup;
	struct sockaddr_in localAddr;
	struct sockaddr_in upAddr;
	struct sockaddr_in downAddr;
	unsigned int upAddrLen;
	char upInBuffer[DNS_MAX_LENGTH];
	char upOutBuffer[DNS_MAX_LENGTH];
	char splitName[128]; //把二级域名存进来 
	char ipAddr[100];
	dns_query *recvQuery = (dns_query *)malloc(sizeof(dns_query));initQuery(recvQuery);
	dns_header *recvHead = (dns_header *)malloc(sizeof(dns_header));initHead(recvHead);
	//回应的结构体 
	dns_query *resQuery = (dns_query *)malloc(sizeof(dns_query));initQuery(resQuery);
	dns_header *resHead = (dns_header *)malloc(sizeof(dns_header));initHead(resHead);
	dns_rr *resRecord = (dns_rr *)malloc(sizeof(dns_rr));initRR(resRecord);
	unsigned short port=53;
	int recvMsgSize;
	int outMsgSize; 
	char *i;
	char *o;
	
	
	if((sockup=socket(PF_INET,SOCK_DGRAM,0))<0)  printf("socket() failed\n");
	
	init_sockaddr_in("127.0.0.5", 53, &localAddr);
	if((bind (sockup,(struct sockaddr*)&localAddr,sizeof(localAddr)))<0){
		printf("bind() failed\n");
	} 
	while(1){
	upAddrLen=sizeof(upAddr);
	//receive
	if((recvMsgSize=recvfrom(sockup,upInBuffer,DNS_MAX_LENGTH,0,(struct sockaddr*)&upAddr,&upAddrLen))<0){
		printf("recvfrom() failed\n");
	}
	printf("Handling client %s\n",inet_ntoa(upAddr.sin_addr));
	
    //解析localServer传过来的数据 
	i = upInBuffer;
	i += getHeader(i, recvHead);
	i += getQuery(i, recvQuery); 	
	//printf("The domain name is: %s\n", recvQuery->name);
	//printf("The First Class Name is: %s\n", splitOneDomainName(recvQuery->name));
	splitTwoDomainName(recvQuery->name, splitName);
	
	
	//解析部分至上就结束了，以下为回应部分
	resHead->id =htons(recvHead->id);
	resHead->tag =htons(0x8000);
	resHead->queryNum =htons(recvHead->queryNum);
	resHead->answerNum = htons(1); //这里不一定是1，若没查到怎么办？？ 
	resHead->authorNum = 0;
	resHead->addNum = 0;
	resQuery = recvQuery;
	resRecord->name=recvQuery->name;
    resRecord->rclass=recvQuery->qclass;
	resRecord->type=A_TYPE;
	resRecord->ttl = (uint32_t)86400;
	resRecord->data_len = 4;
	
	//printf("compare:  %s\n",splitName);
    int tf=isequal(splitName,"com");
    //printf("bbbbbb: %d\n",tf);
    tf=isequal(splitName,"org");
    //printf("basafds: %d\n",tf);
	
	/*
	 *返回查询结果 
	 */
	if(isequal(splitName,"edu.cn")){
		//在结构体里把rdata赋值为 "127.0.0.6" ,在head里把anwernum赋值为 1，flag为8000 
	   // printf("hello, in edu.cn!\n");
	    strcpy(ipAddr, "127.0.0.6");
	    //printf("hello,%s\n", ipAddr);
	    char *p = ipAddr;
	    int len = strlen(ipAddr)+1;
	    resRecord->rdata=(char*)malloc(len*sizeof(char));
	    //printf("hello, in org!\n");
	    memcpy(resRecord->rdata,p,len);
	    //printf("resRecordDataL %s\n", resRecord->rdata);
	    //printf("hello, out edu.cn!\n");
		o = upOutBuffer; 
	 	o += head2buf(o, resHead);
	 	o += query2buf(o,resQuery); 
	 	o += rr2buf(o,resRecord);

	}
	else if (isequal(splitName,"gov.us")){
		//在结构体里把rdata赋值为 "127.0.0.7" ,在head里把anwernum赋值为 1，flag 为8000 
		//printf("hello, in gov!\n");
		strcpy(ipAddr, "127.0.0.7");
		char *p = ipAddr;
	    int len = strlen(ipAddr)+1;
	    resRecord->rdata=(char*)malloc(len*sizeof(char));
	    memcpy(resRecord->rdata,p,len);
	    //printf("resRecordDataL %s\n", resRecord->rdata);
	    //printf("hello, out gov!\n");
		o = upOutBuffer; 
	 	o += head2buf(o, resHead);
	 	o += query2buf(o,resQuery); 
	 	o += rr2buf(o,resRecord);
		
	}
	else{
		//在结构体里把rdata赋值为空，head answernum赋值为1 flag 为8183 
		resHead->answerNum = 0;
		//printf("in else\n");
		strcpy(ipAddr, "255.255.255.255");
		resHead->tag =htons(0x8183);
		char *p = ipAddr;
	    int len = strlen(ipAddr)+1;
	    resRecord->rdata=(char*)malloc(len*sizeof(char));
	    memcpy(resRecord->rdata,p,len);
	    //printf("resRecordDataL %s\n", resRecord->rdata);
	    //printf("out else\n");
		//rdata无数值，anwernum为0
		//查询失败 
		o = upOutBuffer; 
	 	o += head2buf(o, resHead);
		o += query2buf(o,resQuery); 
	}
	
	/*
	 *压缩返回 
	 */
	
	
	//send
	outMsgSize=o - upOutBuffer +1;
	//printf("length:%d \n",outMsgSize);
	if(sendto(sockup,upOutBuffer,outMsgSize,0,(struct sockaddr*)&upAddr,sizeof(upAddr))!=outMsgSize){
		printf("sendto() problem!\n");
	}
	
	}	
}
void splitTwoDomainName(char *domainName, char *splitName){
	int i = strlen(domainName)-1; //免去\0的影响 
	//printf("domainName: %s\n", domainName);
	int j = 0;
	int k = 0;
	int countdot=0;
	char invertName[100];
	char splitOneName[100];
	memset(invertName, 0, 100);
	memset(splitOneName, 0, 100);
	while(1){
		if(domainName[i]!='.'){
			//printf("d: %c\n", domainName[i]);
			invertName[j] = domainName[i];
			//printf("s: %c\n", invertName[j]);
			i--;j++; 
		}
		else if(countdot==0){
			//printf("d: %c\n", domainName[i]);
			invertName[j] = domainName[i];
			//printf("s: %c\n", invertName[j]);
			i--;j++; 
			countdot++;
		}
		else break;
	}
	invertName[j] = '\0';
	//printf("splitOneInvert: %s\n", invertName);
	i = strlen(invertName)-1;
	while(1){
		if(k < strlen(invertName)){
			//printf("s: %c\n", invertName[i]);
			splitName[k] = invertName[i];
			i--; k++;
		}else break;
		
	}
	splitName[k] = '\0';
	//printf("splitTwo: %s\n", splitName);
}
void init_sockaddr_in(char* ip, int port, struct sockaddr_in* addr){
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    addr->sin_addr.s_addr=inet_addr(ip);
    memset(addr->sin_zero, 0, sizeof(addr->sin_zero));
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
  
unsigned int head2buf(char *o, dns_header *head){
	memcpy(o, head, sizeof(dns_header));
	//////////////////////////////////////////////没转主机字节序！！！！！ 
	return sizeof(dns_header);
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
	printf("length22: %d\n",  len+2*sizeof(short)); 
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
	memcpy(o, &ipAddr,rr->data_len); //将字符串转化为网络字节序的4bytes数据 
	//printf("rrDate: %s\n", o);
	o+=rr->data_len; //也就是要移动4位 
	return 11+strlen(rr->name)+(rr->data_len);
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
	//printf("queryName: %d\n", header->id);
	header->answerNum = ntohs(*(uint16_t*) (q+6));
	header->authorNum = ntohs(*(uint16_t*) (q+8));
	header->addNum = ntohs(*(uint16_t*) (q+10));
	
	return sizeof(dns_header);
}

unsigned int getQuery(char *q, dns_query *query){
	char domainName[100];
	memset(domainName, 0, 100);
	char *d = domainName;
	//printf("d: %s\n", d);
	uint8_t count = 0;
	int i = 0; 
	//count = ntohs(*(uint8_t*)(q));
	//完成报文中数字加域名形式至点分值的转换 
	while(1){
		if(*q!='\0'){
			count = *(uint8_t*)(q);
			printf("count:%d\n", count);
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
	// printf("Query Type: %d\n", query->qtype);
	// printf("Query Class: %d\n", query->qclass);
	return i+4+1; //补一个1的原因是网络的域名形式和转换后的差一位 
}

