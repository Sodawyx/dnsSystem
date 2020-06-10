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
#define DNS_MAX_LENGTH 1023
#define A 1
#define MX 0x000F 
#define CNAME 5
#define IN 1
void my_strcpy(dns_query *b, char *a);
unsigned char* convertDomainName(char *name);
unsigned int head2buf(char *o, dns_header *header);
unsigned int query2buf(char *o, dns_query *query);
unsigned int getHeader(char *q, dns_header * header); 
unsigned int getQuery(char *q, dns_query *query);
unsigned int getRRs(char *q, dns_rr *rRecord);
//int getPieceLen(char *ptr);



//����TCP������ʵ�ַ������Ϳͻ��˵�ͨ��
int main()
{

//����socket�׽���
	int clientfd=0;
	clientfd=socket(AF_INET,SOCK_STREAM,0);
	if(clientfd<0)
	{
		perror("socket failed");
		return -1;
	}
	//printf("socket ok!\n");
//�ͻ��˿��Բ���IP��ַ�Ͷ˿ںţ�ϵͳ���������
//�ͻ������ӷ�����
	int ret=0;
	int addrlen=0;
	struct sockaddr_in seraddr={0};
	seraddr.sin_family=AF_INET;
	seraddr.sin_port=htons(53);
	seraddr.sin_addr.s_addr=inet_addr("127.0.0.2");
	addrlen=sizeof(seraddr);
	ret=connect(clientfd,(struct sockaddr *)&seraddr,addrlen);
	if(ret<0)
	{
		perror("connect failed");
		close(clientfd);
		return -1;
	}
	printf("Connected with server successfully!\n");
//����send�������������Ϣ


	
		unsigned char queryInfo[127];
		unsigned char qType[127];
		unsigned char* convertQueryInfo; 
		char bufOut[DNS_MAX_LENGTH]; memset(bufOut, 0, DNS_MAX_LENGTH);
		char bufIn[DNS_MAX_LENGTH]; memset(bufIn, 0, DNS_MAX_LENGTH);
		char *o = bufOut + 2; //��ͷ�����ֽ���ʾ��С����ץ�� 
		char *i = bufIn + 2; //�����յ���ǰ���ֽ�ɾ�� 
		unsigned short qClass;
		unsigned short offset = 0;
		unsigned short *offsetptr; 
		int rev=0; 
		/*
		 *���뷢��״̬ 
		 */
	   while(1)
        {
		/*
		 *���ԭ��buff����ʼ�� 
		 */	 
        memset(bufOut, 0, DNS_MAX_LENGTH);
        memset(bufIn, 0, DNS_MAX_LENGTH);
		o = bufOut + 2; //��ͷ�����ֽ���ʾ��С����ץ�� 
		i = bufIn + 2; //�����յ���ǰ���ֽ�ɾ�� 
        offset = 0;
        rev=0; 
        
        /*
		 *�ṹ���ڴ� 
		 */ 
		dns_query *query = (dns_query *)malloc(sizeof(dns_query));initQuery(query);
		dns_header *head = (dns_header *)malloc(sizeof(dns_header));initHead(head);
		dns_rr *rRecord = (dns_rr *)malloc(sizeof(dns_rr));initRR(rRecord);
		//�õ��ĵĽṹ�� 
		dns_query *recvQuery = (dns_query *)malloc(sizeof(dns_query));initQuery(recvQuery);
		dns_header *recvHead = (dns_header *)malloc(sizeof(dns_header));initHead(recvHead);
		dns_rr *recvRecord = (dns_rr *)malloc(sizeof(dns_rr));initRR(recvRecord);
		//MX�ڶ��β�ѯip
		dns_query *mxQuery = (dns_query *)malloc(sizeof(dns_query));initQuery(mxQuery);
		dns_header *mxHead = (dns_header *)malloc(sizeof(dns_header));initHead(mxHead);
		dns_rr *mxRecord = (dns_rr *)malloc(sizeof(dns_rr));initRR(mxRecord);
		/*
		 *�������� 
		 */ 
		do{
			printf("Please input the domain name and query type:\n");
			scanf("%s %s", queryInfo, qType);
			fflush(stdin);
		}while(!strcmp(qType, "A") && !strcmp(qType, "MX") && !strcmp(qType, "0")
			&& !strcmp(qType, "CNAME"));
		
		printf("------------------QUERY------------------\n");
		printf("The Query Domain Name is: %s\n", queryInfo);
		printf("The Query Type is: %s\n", qType);
		printf("Now Start the Query Process\n");
		printf("-----------------------------------------\n");
		head->id = htons(head->id = 1);
		head->tag = htons(head->tag = 4);
		head->queryNum = htons(head->queryNum = 1);
		head->answerNum = 0;
		head->authorNum = 0;
		head->addNum = 0;
		o += head2buf(o, head);
		my_strcpy(query, queryInfo);
		
		
		//������֤���� 
		if(!strcmp(qType, "A")) query->qtype = A_TYPE;
		else if (!strcmp(qType, "MX")) query->qtype = MX_TYPE;
		else if (!strcmp(qType, "CNAME")) query->qtype = CNAME_TYPE;
		else if (!strcmp(qType, "0")) query->qtype = 0; 
		
		query->qclass = IN;
		
		o += query2buf(o,query); 
		offset = o - bufOut - 2; //��ͷ�����ֽ���ʾ��С����ץ�� 
		offsetptr = &offset;
		uint16_t temp = htons(offset); 
		memcpy(bufOut, &temp, sizeof(short)); //��DNS������д��ǰ���ֽ� 
		

		/*
		 *�˳��ӿ� 
		 */ 
        if(query->qtype==0)   break;
        
	    /*
		 *���ͽӿ� 
		 */ 
		if(send(clientfd, bufOut, offset+2, 0)<0){
       	  perror("send");
          return 2;
       }else{ 
    	printf("Send Query to Local Server\n");
    	} 

    	
	    /*
	     *���սӿ� 
	     */
	    memset(bufIn,0,sizeof(bufIn));
      	rev=recv(clientfd,bufIn,sizeof(bufIn),0);
	    // if(rev>0)
     	// {
        //     int i=0;
	    // 	for(i=0;i<rev;i++){
		// 	printf("%d ",bufIn[i]);
		//     }
		// printf("\n");
     	// }
	
		//����Ϊ���մ𰸲������Ĵ���
		printf("------------------ANSWER------------------\n");
		i += getHeader(i, recvHead); 
		if(recvHead->tag == 33152){  //�ɹ��ҵ������ؽ��
		printf("Find the Answers\n");
			i += getQuery(i, recvQuery); 
			recvRecord->name = recvQuery->name; 
			recvRecord->type = recvQuery->qtype;
			recvRecord->rclass = recvQuery->qclass;
			
			i += 6; //ѹ��ָ���������ֽںͺ����2��type����6�ֽ�  
			//��������ȥ������ֻ��rr�ĺ󼸸�ֵ 
			i += getRRs(i, recvRecord);
			if(recvQuery->qtype == MX){
				mxRecord->name = (char*)malloc((strlen(recvRecord->rdata)+1)*sizeof(char));
				strcpy(mxRecord->name, recvRecord->rdata);
				mxRecord->type = A_TYPE;
				mxRecord->rclass = 1;
				i += getRRs(i, mxRecord);
			}

			printf("Query Name: %s\n", recvRecord->name); 
			if(recvRecord->type == A_TYPE){
				printf("Query Type: A\n"); 
				printf("Query Class: IN\n"); 
				printf("TTL: %d\n", recvRecord->ttl);
				printf("IP Addr: %s\n", recvRecord->rdata);
			}
			else if(recvRecord->type == CNAME_TYPE){
				printf("Query Type: CNAME\n");
				printf("Query Class: IN\n"); 
				printf("TTL: %d\n", recvRecord->ttl);
				printf("Another Domain Name Addr: %s\n", recvRecord->rdata);
			} 
			else if(recvRecord->type == MX_TYPE){
				printf("Query Type: MX\n");
				printf("Query Class: IN\n"); 
				printf("TTL: %d\n", recvRecord->ttl);
				printf("Mail Server Domain Name: %s\n", recvRecord->rdata);
				printf("Mail Server IP Address: %s\n", mxRecord->rdata);
			} 
		}else{ //��Ҳû����
			i += getQuery(i, recvQuery); 
			printf("Sorry, we didn't found anything\n");
			printf("Please try again later!\n");
		}
		printf("----------------ANSWER END----------------\n");
		
       }
    printf("Quit with Safety\n");
	close(clientfd);
	return 0;

}

void my_strcpy(dns_query *b, char* a){
	int len = strlen(a)+1;
	//printf("length: %d\n", len);
	b->name = (char*)malloc(len*sizeof(char));
	memcpy(b->name, a, len);
	//printf("look: %s, %s\n", b->name, a);
}

unsigned int head2buf(char *o, dns_header *head){
	memcpy(o, head, sizeof(dns_header));
	int p=0;
	// while(p<=sizeof(dns_header)){
	// printf("buff2: %hu\n", o[p]);
	// p++;
	// }
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
	return len+2*sizeof(short);
}


// //��ȡ��һ���ַ����ĳ��� 
// int getPieceLen(char *ptr){
// 	int i=0;
// 	while(1){
// 		if(ptr[i]==' '||ptr[i]=='\n'||ptr[i]=='\0')
// 			break;
// 		else i++;
// 	}
// 	return i+1;
// }

unsigned char* convertDomainName(char *name){
	//printf("%s\n", name);
	unsigned char *converted;
	int i = 0;
	int j = 1; //ת������� 
	int count = 0;
	int tempts = 0;
	while(1){
		//printf("char %c\n", name[i]);
		if(name[i] == '.'){
			if(tempts == 0){
			converted[0] = count + '0';
			//printf("Count: %d\n", count);
			count = 0;
			i++; j++;
			tempts = 1;
			}
			else{
			converted[j-count-1] = count + '0';
			//printf("Count: %d\n", count);
			count = 0;
			i++; j++;
			}
			
		}
		else if(name[i] == '\0'){
			converted[j] = name[i];
			converted[j-count-1] = count + '0';
			break;
		}
		else{
			converted[j] = name[i];
			j++;
			i++;
			count++; 
		}
	}
	//("Converted: %s\n", converted); 
	return converted;
}

//����������������localServer�е�һ�������Կ��Ǵ����.h 
unsigned int getHeader(char *q, dns_header *header){
	
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
			//("count:%d\n", count);
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
	// printf("Query name: %s\n", query->name);
	
	query->qtype = ntohs(*(uint16_t*) (q));
	query->qclass = ntohs(*(uint16_t*) (q+2));
	// printf("Query Type: %d\n", query->qtype);
	// printf("Query Class: %d\n", query->qclass);
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
	//rRecord->rdata = (char*)malloc((rRecord->data_len)*sizeof(char));
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
		rRecord->rdata = (char*)malloc((strlen(ptr)+1)*sizeof(char));
		strcpy(rRecord->rdata,ptr);
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
				//printf("i: %d\n", i);
				//printf("char1:%c\n", *q);
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
	//printf("i: %d\n", i);  
	//printf("Converted domain name: %s\n", domainName);
	//printf("length: %d\n", i);
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

