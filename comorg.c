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
unsigned int getRRs(char *q, dns_rr *rRecord);
int isequal(char *str1, char* str2);
unsigned int rr2buf(char *o, dns_rr* rr);
unsigned int query2buf(char *o, dns_query *query);
unsigned int head2buf(char *o, dns_header *header);
unsigned int add2buf(char *o, dns_rr* rr, dns_query* query);


void init_sockaddr_in(char* ip, int port, struct sockaddr_in* addr);
int main(){
	int state=0;  //�鵽û�� 
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
	//����Ҫ�ָ����֣���Ϊ�Ѿ�����ײ�����������ļ���ѯ���� 
	
	//���ܵĽṹ�� 
	dns_query *recvQuery = (dns_query *)malloc(sizeof(dns_query));initQuery(recvQuery);
	dns_header *recvHead = (dns_header *)malloc(sizeof(dns_header));initHead(recvHead);
	dns_rr *recvrRecord = (dns_rr *)malloc(sizeof(dns_rr));initRR(recvrRecord);  
	//��Ӧ�Ľṹ�� 
	dns_query *resQuery = (dns_query *)malloc(sizeof(dns_query));initQuery(resQuery);
	dns_header *resHead = (dns_header *)malloc(sizeof(dns_header));initHead(resHead);
	dns_rr *resRecord = (dns_rr *)malloc(sizeof(dns_rr));initRR(resRecord);
	//MX�ڶ��β�ѯip
	dns_query *mxQuery = (dns_query *)malloc(sizeof(dns_query));initQuery(mxQuery);
	dns_header *mxHead = (dns_header *)malloc(sizeof(dns_header));initHead(mxHead);
	dns_rr *mxRecord = (dns_rr *)malloc(sizeof(dns_rr));initRR(mxRecord);
	
	
	if((sockup=socket(PF_INET,SOCK_DGRAM,0))<0)  printf("socket() failed\n");
	
	init_sockaddr_in("127.0.0.4", 53, &localAddr);
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
	
	//����
	char *i = upInBuffer;
	i += getHeader(i, recvHead);
	i += getQuery(i, recvQuery); 	
	printf("The domain name is: %s\n", recvQuery->name);
	
	//����Ϊ��Ӧ�Ĳ���
	resHead->id =htons(recvHead->id);
	resHead->tag =htons(0x8000);
	resHead->queryNum =htons(recvHead->queryNum);
	resHead->answerNum = htons(1); //���ﲻһ����1����û�鵽��ô�죿�� 
	resHead->authorNum = 0;
	resHead->addNum = 0;
	resQuery = recvQuery;
	resRecord->name=recvQuery->name;
    resRecord->rclass=recvQuery->qclass;
	resRecord->type=recvQuery->qtype;
	resRecord->ttl = (uint32_t)86400;
	resRecord->data_len = 4;
	
	//printf("recvQuery->qType: %d\n",recvQuery->qtype);
	/*
	 *���ز�ѯ��� 
	 */
	 if(recvQuery->qtype==A_TYPE) {
	   freopen("comorgA.txt", "r", stdin);
	   char file_name[255],file_ttl[255],file_class[255],file_type[255],file_ip[255];
	    while(~scanf("%s%s%s%s%s", file_name, file_ttl, file_class,file_type,file_ip)){
	    	if(isequal(recvQuery->name,file_name)){
	    		printf("file_name: %s\n",file_name);
	    		printf("file_name length: %d\n",strlen(file_name));
	    		printf("file_ttl: %s\n",file_ttl);
	    		printf("file_class�� %s\n",file_class);
	    		printf("file_type: %s\n",file_type);
	    		printf("file_ip: %s\n",file_ip);
				//��ȷ������ļ������������ʲô���ӵģ��������ո񣬳��������п��ܲ���

				resRecord->name = (char*)malloc((strlen(file_name)+1)*sizeof(char));
				strcpy(resRecord->name, file_name);
				resRecord->ttl = (uint32_t)(atoi(file_ttl));
				resRecord->rdata = (char*)malloc((strlen(file_ip)+1)*sizeof(char));
				strcpy(resRecord->rdata, file_ip);
				resHead->answerNum = htons(1);
				resRecord->data_len=strlen(resRecord->rdata)+1;
				resHead->tag = htons(0x8180);

	    		//printf("recv->Query: %s\n",recvQuery->name);
	    		//�ڽṹ�����rdata��ֵΪ file_ip ,��head���anwernum��ֵΪ1��flagΪ8180 
	    		state=1;   //�����鵽 
	    		break;
			}
		}   
	}
	else if(recvQuery->qtype==CNAME_TYPE){
		freopen("comorgC.txt", "r", stdin);
	   char file_name[255],file_ttl[255],file_class[255],file_type[255],file_addr[255];
	    while(~scanf("%s%s%s%s%s", file_name, file_ttl, file_class,file_type,file_addr)){
	    	if(isequal(recvQuery->name,file_name)){
	    		printf("file_name: %s\n",file_name);
	    		printf("file_name length: %d\n",strlen(file_name));
	    		printf("file_ttl: %s\n",file_ttl);
	    		printf("file_class�� %s\n",file_class);
	    		printf("file_type: %s\n",file_type);
	    		printf("file_ip: %s\n",file_addr);
				//��ȷ������ļ������������ʲô���ӵģ��������ո񣬳��������п��ܲ���

				resRecord->name = (char*)malloc((strlen(file_name)+1)*sizeof(char));
				strcpy(resRecord->name, file_name);
				resRecord->ttl = (uint32_t)(atoi(file_ttl));
				resRecord->rdata = (char*)malloc((strlen(file_addr)+1)*sizeof(char));
				strcpy(resRecord->rdata, file_addr);
				resHead->answerNum = htons(1);
				resRecord->data_len=strlen(resRecord->rdata)+1;
				resHead->tag = htons(0x8180);

	    		//printf("recv->Query: %s\n",recvQuery->name);
	    		//�ڽṹ�����rdata��ֵΪ file_ip ,��head���anwernum��ֵΪ1��flagΪ8180 
	    		state=1;   //�����鵽 
	    		break;
			}
		}   
	}
	else if(recvQuery->qtype==MX_TYPE){
		//printf("in file M\n");
		freopen("comorgM.txt", "r", stdin);
		//printf("flag1\n"); 
	   char file_name[255],file_ttl[255],file_class[255],file_type[255],file_addr[255];
	    while(~scanf("%s%s%s%s%s", file_name, file_ttl, file_class,file_type,file_addr)){
	    	//printf("flag2\n");
	    	if(isequal(recvQuery->name,file_name)){
	    		printf("file_name: %s\n",file_name);
	    		printf("file_name length: %d\n",strlen(file_name));
	    		printf("file_ttl: %s\n",file_ttl);
	    		printf("file_class�� %s\n",file_class);
	    		printf("file_type: %s\n",file_type);
	    		printf("file_addr: %s\n",file_addr);
				//��ȷ������ļ������������ʲô���ӵģ��������ո񣬳��������п��ܲ���

				resRecord->name = (char*)malloc((strlen(file_name)+1)*sizeof(char));
				strcpy(resRecord->name, file_name);
				resRecord->ttl = (uint32_t)(atoi(file_ttl));
				resRecord->rdata = (char*)malloc((strlen(file_addr)+1)*sizeof(char));
				strcpy(resRecord->rdata, file_addr);
				resHead->answerNum = htons(1);
				//���������ڵ�������ȥ��ѯ�����ֳ�����+2(pre..)+2(ѹ��ָ��)
		        resRecord->data_len = strlen(resRecord->rdata)-strlen(recvQuery->name) + 4;
				resHead->tag = htons(0x8180);

	    		//printf("recv->Query: %s\n",recvQuery->name);
	    		//�ڽṹ�����rdata��ֵΪ file_ip ,��head���anwernum��ֵΪ1��flagΪ8180 
	    		state=1;   //�����鵽 
	    		break;
			}
		} 
		if(state==1){
		mxQuery->name = (char*)malloc((strlen(resRecord->rdata)+1)*sizeof(char));
		strcpy(mxQuery->name, resRecord->rdata);
		//printf("mxQueryName: %s\n", mxQuery->name);
		mxQuery->qclass = recvQuery->qclass;
		mxQuery->qtype = A_TYPE; //����Ҫ����һ�εĽ��A��ʽ��ѯһ��
		freopen("comorgA.txt", "r", stdin);
	    char file_ip[255];
	    while(~scanf("%s%s%s%s%s", file_name, file_ttl, file_class,file_type,file_ip)){
	    	if(isequal(mxQuery->name,file_name)){
	    		printf("file_name: %s\n",file_name);
	    		printf("file_name length: %d\n",strlen(file_name));
	    		printf("file_ttl: %s\n",file_ttl);
	    		printf("file_class�� %s\n",file_class);
	    		printf("file_type: %s\n",file_type);
	    		printf("file_ip: %s\n",file_ip);
				//��ȷ������ļ������������ʲô���ӵģ��������ո񣬳��������п��ܲ���	
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
	    		//�ڽṹ�����rdata��ֵΪ file_ip ,��head���anwernum��ֵΪ1��flagΪ8180 
	    		state=1;   //�����鵽 
	    		break;
			}
		}
	  }
	 }	  
	 //printf("state %d\n",state);
	char* o=upOutBuffer;
	//�鲻�������
	if(state==0){
		//printf("1\n");
		resHead->tag =htons(0x8183);
		//printf("2\n");
		resHead->answerNum = 0;
		//printf("3\n");
		o = upOutBuffer; 
		//printf("4\n");
	 	o += head2buf(o, resHead);
	 	//printf("5\n");
	 	o += query2buf(o,resQuery);
		//�ڽṹ�����rdata��ֵΪ�Ҳ��� ,��head���anwernum��ֵΪ 1��flagΪ8183 
	}else{
		o = upOutBuffer; 
	 	o += head2buf(o, resHead);
	 	o += query2buf(o,resQuery); 
	 	o += rr2buf(o,resRecord);
	 	if(recvQuery->qtype == MX_TYPE)
	 	o+=add2buf(o, mxRecord, recvQuery);
	}


	//ͳһ����
	//��upOutBuffer��ֵ 
	outMsgSize = o - upOutBuffer + 1;
	//printf("length:%d \n",outMsgSize);
	if(sendto(sockup,upOutBuffer,outMsgSize,0,(struct sockaddr*)&upAddr,sizeof(upAddr))!=outMsgSize){
		printf("sendto() problem!\n");
	}
	
	}	

}
unsigned int head2buf(char *o, dns_header *head){
	memcpy(o, head, sizeof(dns_header));
	//////////////////////////////////////////////ûת�����ֽ��򣡣������� 
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
	//printf("queryName: %d\n", header->id);
	header->answerNum = ntohs(*(uint16_t*) (q+6));
	header->authorNum = ntohs(*(uint16_t*) (q+8));
	header->addNum = ntohs(*(uint16_t*) (q+10));
	
	return sizeof(dns_header);
}

//����������������localServer�е�һ�������Կ��Ǵ����.h 
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
			//printf("count:%d\n", count);
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
	//printf("Query Type: %d\n", query->qtype);
	//printf("Query Class: %d\n", query->qclass);
	return i+4+1; //��һ��1��ԭ���������������ʽ��ת����Ĳ�һλ 
}

unsigned int getRRs(char *q, dns_rr *rRecord){
	uint32_t ipAddr;
	rRecord->ttl = ntohl(*(uint32_t*)(q)); //������ntohl��32bit���ֵ�ת�� 
	char str[INET_ADDRSTRLEN];
	struct in_addr addr;
	//printf("Query Answer TTL: %d\n", rRecord->ttl);
	q+=sizeof(rRecord->ttl);
	rRecord->data_len = ntohs(*(uint16_t*)(q));
	//printf("Data Length: %d\n", rRecord->data_len);
	q+=sizeof(rRecord->data_len);
	rRecord->rdata = (char*)malloc((rRecord->data_len)*sizeof(char));
	//printf("hello\n");
	if(rRecord->type == MX_TYPE){
		q += 2; //��Preferencre�ĳ��ȿճ�ȥ
	}
	
	if(rRecord->type == A_TYPE){
		ipAddr = *(uint32_t*)(q);
		//printf("Query Answer TTL: %d\n", rRecord->ttl);
		memcpy(&addr, &ipAddr, 4);
		char *ptr = inet_ntop(AF_INET, &addr, str, sizeof(str)); //ת��Ϊʮ���Ƶ��ֵ��IP��ַ
		//printf("Query Answer IP: %s\n", ptr);
		return 4 + 2 + rRecord->data_len;
	}
	else if(rRecord->type == CNAME_TYPE){
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
			//printf("count:%d\n", count);
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
	rRecord->rdata = (char*)malloc(i*sizeof(char));
	memcpy(rRecord->rdata, domainName, i); //��ʱ��i��Ϊת����䳤�ַ����ĳ����ˣ�������ѭ������ 
	// printf("Query name: %s\n", rRecord->rdata);
	// 	printf("The CNAME is: %s\n", rRecord->rdata);
		return 4 + 2 + rRecord->data_len +1;
	}
	else if(rRecord->type == MX_TYPE){
		int firstlen = rRecord->data_len - 5;
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
			//printf("count:%d\n", count);
			q++;
			while(count){
				// printf("i: %d\n", i);
				// printf("char1:%c\n", *q);
				memcpy(&(domainName[i]), q, sizeof(char));
				//printf("domain name i: %c\n", domainName[i]);
				count--; q++; i++;
			}
			domainName[i] = '.'; //�ӵ� 
			i++;
			domainName[i] = '\0';
			i++;
			break;
		}
	}
	// printf("i: %d\n", i);  
	// printf("Converted domain name: %s\n", domainName);
	// printf("length: %d\n", i);
	strcpy(domainName, strcat(domainName, rRecord->name)); //����ѹ����ָ�룬�����ַ�������ƴ��
	//printf("Converted domain name: %s\n", domainName);
	int totalen = strlen(rRecord->name) + i; //ƴ�Ӻ��ܳ���
	rRecord->rdata = (char*)malloc(totalen*sizeof(char));
	memcpy(rRecord->rdata, domainName, totalen); 
	//printf("Query name: %s\n", rRecord->rdata);
		//printf("The CNAME is: %s\n", rRecord->rdata);
		return 12+rRecord->data_len;
	}
	
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
	//printf("length22: %d\n",  len+2*sizeof(short)); 
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
	//printf("flag3\n");
	temp=htons(rr->type);
	memcpy(o, &temp, sizeof(short));
	printf("rrType: %d\n", rr->type);
	o+=2;
	//printf("flag3\n");
	temp=htons(rr->rclass);
	memcpy(o, &temp, sizeof(short));
	o+=2;
	//printf("flag3\n");
	temp32=htonl(rr->ttl); //������htonl 32λ���ֵ������ֽ���ת�� 
	printf("ttlconvert: %d\n", temp32);
	memcpy(o, &temp32, (2*sizeof(short)));
	o+=4;
	//printf("flag3\n");
	temp=htons(rr->data_len);
	memcpy(o, &temp, sizeof(short));
	o+=2;
	//printf("flag3\n");
	//����ָpreference��MX����Ҫ�������ֽ�Ŷ
	if(rr->type == MX_TYPE){
		temp=htons(1);
		memcpy(o, &temp, sizeof(short));
		o+=2;
	}
	
	if(rr->type == A_TYPE){
		uint32_t  ipAddr = inet_addr(rr->rdata);
		memcpy(o, &ipAddr,rr->data_len); //���ַ���ת��Ϊ�����ֽ����4bytes���� 
		//printf("rrDate: %s\n", o);
		o+=rr->data_len; //Ҳ����Ҫ�ƶ�4λ 
		return 16;
	}
	else if(rr->type == CNAME_TYPE){
		char* ini = o; //for initial
	uint8_t count = 0;
	int i = 0;
	int j = 1; //ת������� 
	int tempts = 0;
	o++; //�������ƶ�һλ 
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
	else if(rr->type == MX_TYPE){ //MX�����
		char* ini = o; //for initial
	uint8_t count = 0;
	int i = 0;
	int j = 1; //ת������� 
	int tempts = 0;
	o++; //�������ƶ�һλ 
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
	temp =  htons(49164); //����ָ��1100000000001100��DNS������ѹ��ָ��Ĳ���
	memcpy(o, &temp, sizeof(short)); 
	return 16+i;
	}
	
	
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
  
  //����MX��ip��ѯ���ŵ�addtion����
unsigned int add2buf(char *o, dns_rr* rr, dns_query* query) {
	//printf("add2buf rrdata: %s\n", rr->rdata);
	//printf("datalength: %d\n", strlen(rr->rdata));
	int i = 0;
	uint16_t temp;
	uint32_t temp32;
	temp =  htons(49152+12+strlen(query->name)+2+4+14); //����ָ��1100000000001100��DNS������ѹ��ָ��Ĳ���
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
	memcpy(o, &ipAddr, rr->data_len); //���ַ���ת��Ϊ�����ֽ����4bytes���� 
	//printf("rrDate: %d\n", ipAddr);
	o+=rr->data_len; //Ҳ����Ҫ�ƶ�4λ 
	return 16;


}

