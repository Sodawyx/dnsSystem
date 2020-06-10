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
	char splitName[128]; //�Ѷ������������ 
	char ipAddr[100];
	dns_query *recvQuery = (dns_query *)malloc(sizeof(dns_query));initQuery(recvQuery);
	dns_header *recvHead = (dns_header *)malloc(sizeof(dns_header));initHead(recvHead);
	//��Ӧ�Ľṹ�� 
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
	
    //����localServer������������ 
	i = upInBuffer;
	i += getHeader(i, recvHead);
	i += getQuery(i, recvQuery); 	
	//printf("The domain name is: %s\n", recvQuery->name);
	//printf("The First Class Name is: %s\n", splitOneDomainName(recvQuery->name));
	splitTwoDomainName(recvQuery->name, splitName);
	
	
	//�����������Ͼͽ����ˣ�����Ϊ��Ӧ����
	resHead->id =htons(recvHead->id);
	resHead->tag =htons(0x8000);
	resHead->queryNum =htons(recvHead->queryNum);
	resHead->answerNum = htons(1); //���ﲻһ����1����û�鵽��ô�죿�� 
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
	 *���ز�ѯ��� 
	 */
	if(isequal(splitName,"edu.cn")){
		//�ڽṹ�����rdata��ֵΪ "127.0.0.6" ,��head���anwernum��ֵΪ 1��flagΪ8000 
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
		//�ڽṹ�����rdata��ֵΪ "127.0.0.7" ,��head���anwernum��ֵΪ 1��flag Ϊ8000 
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
		//�ڽṹ�����rdata��ֵΪ�գ�head answernum��ֵΪ1 flag Ϊ8183 
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
		//rdata����ֵ��anwernumΪ0
		//��ѯʧ�� 
		o = upOutBuffer; 
	 	o += head2buf(o, resHead);
		o += query2buf(o,resQuery); 
	}
	
	/*
	 *ѹ������ 
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
	int i = strlen(domainName)-1; //��ȥ\0��Ӱ�� 
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
	//////////////////////////////////////////////ûת�����ֽ��򣡣������� 
	return sizeof(dns_header);
}

unsigned int query2buf(char *o, dns_query *query){
	char* ini = o; //for initial
	uint8_t count = 0;
	int i = 0;
	int j = 1; //ת������� 
	int tempts = 0;
	o++; //�������ƶ�һλ 
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
	int len = o - ini; //��������ֵĳ���
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
	temp =  htons(49164); //����ָ��1100000000001100��DNS������ѹ��ָ��Ĳ���
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
	
	temp32=htonl(rr->ttl); //������htonl 32λ���ֵ������ֽ���ת�� 
	//printf("ttlconvert: %d\n", temp32);
	memcpy(o, &temp32, (2*sizeof(short)));
	o+=4;
	
	temp=htons(rr->data_len);
	memcpy(o, &temp, sizeof(short));
	o+=2;
	
	uint32_t  ipAddr = inet_addr(rr->rdata);
	memcpy(o, &ipAddr,rr->data_len); //���ַ���ת��Ϊ�����ֽ����4bytes���� 
	//printf("rrDate: %s\n", o);
	o+=rr->data_len; //Ҳ����Ҫ�ƶ�4λ 
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
	//��ɱ��������ּ�������ʽ�����ֵ��ת�� 
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
			domainName[i] = '.'; //�ӵ� 
			i++;
		}
		else{
			domainName[i-1] = '\0'; //��ע���� 
			q++; 
			break;
		}
	}
	// printf("i: %d\n", i);  
	// printf("Converted domain name: %s\n", domainName);
	// printf("length: %d\n", i);
	query->name = (char*)malloc(i*sizeof(char));
	memcpy(query->name, domainName, i); //��ʱ��i��Ϊת����䳤�ַ����ĳ����ˣ�������ѭ������ 
	//printf("Query name: %s\n", query->name);
	
	query->qtype = ntohs(*(uint16_t*) (q));
	query->qclass = ntohs(*(uint16_t*) (q+2));
	// printf("Query Type: %d\n", query->qtype);
	// printf("Query Class: %d\n", query->qclass);
	return i+4+1; //��һ��1��ԭ���������������ʽ��ת����Ĳ�һλ 
}

