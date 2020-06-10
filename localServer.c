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
//创建TCP服务器实现服务器和客户端的通信
unsigned int getHeader(char *q, dns_header * header); 
unsigned int getQuery(char *q, dns_query *recvQuery);
void init_DNS_RR(dns_query *recvQuery,dns_rr*resRecord ,char* col);
unsigned int head2buf(char *o, dns_header *head);
unsigned int query2buf(char *o, dns_query *query);
unsigned int add2buf(char *o, dns_rr* rr, dns_query* query);
unsigned int rr2buf(char *o, dns_rr* rr); 
unsigned int compare( dns_query *query,  char *col);
unsigned int cmpDomainName( char *name,  char *col);
unsigned int cmpTypeClass(unsigned short type, char *col);
unsigned int getRRs(char *q, dns_rr *rRecord);
void init_sockaddr_in(char* ip, int port, struct sockaddr_in* addr);

int main()
{
//创建socket套接字
	int serfd=0;
	serfd=socket(AF_INET,SOCK_STREAM,0);
	if(serfd<0)
	{
		perror("socket failed");
		return -1;
	}
	printf("Socket Created!\n");
//通过调用bind绑定IP地址和端口号
	int ret=0;
	struct sockaddr_in seraddr={0};
	seraddr.sin_family=AF_INET;
	seraddr.sin_port=htons(53);
	seraddr.sin_addr.s_addr=inet_addr("127.0.0.2");
	ret=bind(serfd,(struct sockaddr *)&seraddr,sizeof(seraddr));
	if(ret<0)
	{
		perror("Bind failed");
		close(serfd);
		return -1;
	}
	printf("Bind Starting\n");
//通过调用listen将套接字设置为监听模式
	int lis=0;
	lis=listen(serfd,LINE);
	if(lis<0)
	{
		perror("listen failed");
		close(serfd);
		return -1;
	}
	printf("Listen to the client\n");
//服务器等待客户端连接中，游客户端连接时调用accept产生一个新的套接字
	int confd=0;
	socklen_t addrlen;
	struct sockaddr_in clientaddr={0};
	addrlen=sizeof(clientaddr);
	confd=accept(serfd,(struct sockaddr *)&clientaddr,&addrlen);
	if(confd<0)
	{
		perror("accept failed");
		close(serfd);
		return -1;
	}
	printf("Connect with Client successfully!\n");
	printf("IP=%s, PORT=%u\n",inet_ntoa(clientaddr.sin_addr),ntohs(clientaddr.sin_port));
//调用recv接收客户端的消息

	/*
	 *声明 
	 */ 
	unsigned char queryInfo[127];
	unsigned char* convertQueryInfo;
	//接受的结构体 
	dns_query *recvQuery = (dns_query *)malloc(sizeof(dns_query));initQuery(recvQuery);
	dns_header *recvHead = (dns_header *)malloc(sizeof(dns_header));initHead(recvHead);
	dns_rr *recvrRecord = (dns_rr *)malloc(sizeof(dns_rr));initRR(recvrRecord);  
	//回应的结构体 
	dns_query *resQuery = (dns_query *)malloc(sizeof(dns_query));initQuery(resQuery);
	dns_header *resHead = (dns_header *)malloc(sizeof(dns_header));initHead(resHead);
	dns_rr *resRecord = (dns_rr *)malloc(sizeof(dns_rr));initRR(resRecord);
	//接收DNS服务器传来的结构体
	dns_query *serverQuery = (dns_query *)malloc(sizeof(dns_query));initQuery(serverQuery);
	dns_header *serverHead = (dns_header *)malloc(sizeof(dns_header));initHead(serverHead);
	dns_rr *serverRecord = (dns_rr *)malloc(sizeof(dns_rr));initRR(serverRecord);
	//MX第二次查询ip
	dns_query *mxQuery = (dns_query *)malloc(sizeof(dns_query));initQuery(mxQuery);
	dns_header *mxHead = (dns_header *)malloc(sizeof(dns_header));initHead(mxHead);
	dns_rr *mxRecord = (dns_rr *)malloc(sizeof(dns_rr));initRR(mxRecord);
	
	char bufOut[DNS_MAX_LENGTH]; memset(bufOut, 0, DNS_MAX_LENGTH);
	char bufIn[DNS_MAX_LENGTH]; memset(bufIn, 0, DNS_MAX_LENGTH);
	char closeFlag[5];
	char flag[] = "exit";
	
	unsigned short qType, qClass;
	unsigned short offset = 0;
	unsigned short *offsetptr; 
	int rev = 0; 
	int sed = 0;
	int checkinit=0; 
	


while(1)
{
	/*
	*清空原有buff，初始化 
	*/	 
	checkinit=0; 
    memset(bufOut, 0, DNS_MAX_LENGTH);
    memset(bufIn, 0, DNS_MAX_LENGTH);
	char *o = bufOut + 2; //开头留两字节显示大小便于抓包 
	char *i = bufIn + 2; //接收的时候把前2字节跳过 
    offset = 0;
    rev=0; 

    /*
	 *接收 
	 */ 
	rev=recv(confd,bufIn,sizeof(bufIn),0);
	//printf("ss: %s\n", bufIn);
	i += getHeader(i, recvHead);
	i += getQuery(i, recvQuery); 
	if(rev>0)
	{
		printf("Received the query request from client!\n");
    
	    // int i=0;
		// for(i=0;i<rev;i++){
		// 	printf("%d ",bufIn[i]);
		// }
		// printf("\n");
	}
	//关闭接口函数 
	if(recvQuery->qtype == 0){
		close(confd);break;
	}


    
     /*
	 *解析接口（头） 
	 */ 
    resHead->id =htons(recvHead->id);
	resHead->tag =htons(0x8180);
	resHead->queryNum =htons(recvHead->queryNum);
	resHead->answerNum = htons(1); //这里不一定是1，若没查到怎么办？？ 
	resHead->authorNum = 0;
	resHead->addNum = 0;
	resQuery = recvQuery;
	char *filePath;	
	//printf("type1: %d\n", resQuery->qtype);
	//printf("type2: %d\n", recvQuery->qtype);
	//读文件的代码 A
	if(resQuery->qtype==A_TYPE){
    filePath="localCacheA.txt";
	FILE *fp = fopen(filePath, "r"); //读取对应文件
	char col[DNSMAXLEN]; memset(col, 0, DNSMAXLEN); 
	while(fgets(col, DNSMAXLEN-1, fp) != NULL){ //逐行对比 
	    //printf("in compare whileA\n");
		if(compare(recvQuery, col)){
			//printf("in compareA\n");
			init_DNS_RR(recvQuery,resRecord,col);
			resHead->answerNum = htons(1); //找到answer，在answerNum处赋值 
			checkinit=1;   //表明查询完成，无需再进入下一节点查询 
			break;
			}
		}
	}
	else if(resQuery->qtype==CNAME_TYPE){
	filePath="localCacheC.txt";
	FILE *fp = fopen(filePath, "r"); //读取对应文件
	char col[DNSMAXLEN]; memset(col, 0, DNSMAXLEN); 
	while(fgets(col, DNSMAXLEN-1, fp) != NULL){ //逐行对比 
	    //printf("in compare whileC\n");
		if(compare(recvQuery, col)){
			//printf("in compareC\n");
			init_DNS_RR(recvQuery,resRecord,col);
			resHead->answerNum = htons(1); //找到answer，在answerNum处赋值 
			checkinit=1;   //表明查询完成，无需再进入下一节点查询 
			break;
			}
		}	
	}
	else if(resQuery->qtype==MX_TYPE){
		//第一次先去查一下邮箱服务器地址
		filePath="localCacheMX.txt";
		FILE *fp1 = fopen(filePath, "r"); //读取对应文件
		char col1[DNSMAXLEN]; memset(col1, 0, DNSMAXLEN); 
		while(fgets(col1, DNSMAXLEN-1, fp1) != NULL){ //逐行对比 
	    	//printf("in compare whileMX\n");
			if(compare(recvQuery, col1)){
				//printf("in compareMX\n");
				init_DNS_RR(recvQuery,resRecord,col1);
				resHead->answerNum = htons(1); //找到answer，在answerNum处赋值 
				checkinit=1;   //表明查询完成，无需再进入下一节点查询 
				break;
			}
		}
		if(checkinit==1){
		mxQuery->name = (char*)malloc((strlen(resRecord->rdata)+1)*sizeof(char));
		strcpy(mxQuery->name, resRecord->rdata);
		//printf("mxQueryName: %s\n", mxQuery->name);
		mxQuery->qclass = recvQuery->qclass;
		mxQuery->qtype = A_TYPE; //这里要用上一次的结果A方式查询一下

		//第二次先去查一下ip地址	A
		filePath="localCacheA.txt";
		FILE *fp2 = fopen(filePath, "r"); //读取对应文件
		char col2[DNSMAXLEN]; memset(col2, 0, DNSMAXLEN); 
		while(fgets(col2, DNSMAXLEN-1, fp2) != NULL){ //逐行对比 
	    	//printf("in compare whileMX2\n");
			if(compare(mxQuery, col2)){
				//printf("in compareMX2\n");
				init_DNS_RR(mxQuery,mxRecord,col2);
				resHead->addNum = htons(1); //找到answer，在answerNum处赋值 
				checkinit=1;   //表明查询完成，无需再进入下一节点查询 
				break;
			}
		}	
	 }
	}

	/*
	 *向root查询 
	 */ 
	 if(checkinit!=1){    
	    int sockudp;
		struct sockaddr_in toAddr; //去的地址 
		struct sockaddr_in fromAddr; //本机的地址 
		unsigned short toPort=53;
		unsigned int fromSize;
		
		char bufFromRoot[DNS_MAX_LENGTH];
		memset(bufFromRoot, 0, DNS_MAX_LENGTH);
		
		char *askBuf;
		askBuf = bufIn + 2;
		char recvBuffer[DNS_MAX_LENGTH];
		//char askBuffer[DNS_MAX_LENGTH];
		
		//int outLength; //发出的长度
		int inLength; //收到的字节长度
		
		if((sockudp=socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP))<0)  printf("socket() failed\n");
	    init_sockaddr_in("127.0.0.3", 53, &toAddr);
		printf("Query to Root\n");
		/*
		 *send
		 */
		if(sendto(sockudp,askBuf,DNS_MAX_LENGTH,0,(struct sockaddr*)&toAddr,sizeof(toAddr))!=DNS_MAX_LENGTH){
			printf("send length not right.\n");
		} 
		/*
		 *recv 从根节点接收
		 */
		fromSize=sizeof(fromAddr);
		inLength=recvfrom(sockudp,bufFromRoot,DNS_MAX_LENGTH,0,(struct sockaddr*)&fromAddr,&fromSize);
		//printf("buf: %s\n", bufFromRoot);
		//printf("length: %d\n", inLength);
		//bufFromRoot[inLength]='\0';
		char *p = bufFromRoot; //初始化下面服务器传来的指针
		p += getHeader(p, serverHead);
		//printf("Head Tag From Root: %d\n", serverHead->tag);
		p += getQuery(p, serverQuery);
		serverRecord->name = serverQuery->name; 
		serverRecord->type = A_TYPE;
		serverRecord->rclass = serverQuery->qclass;
		// printf("rRecord Name: %s\n", serverRecord->name); 
		// printf("rRecord Type: %d\n", serverRecord->type); 
		// printf("rRecord Class: %d\n", serverRecord->rclass); 
		// printf("size1: %d\n", strlen(serverRecord->name)+1);
		// printf("size2: %d\n", 2*sizeof(serverRecord->type));
		p += 6; //压缩指针那两个字节和后面的2个type，共6字节  
		//printf("strlen offset: %d\n", strlen(serverRecord->name)+1);
		//i += (2*sizeof(serverRecord->type));
		//printf("sizeof2: %d\n", 2*sizeof(serverRecord->type));
		//在这里送去解析的只有rr的后几个值 
		p += getRRs(p, serverRecord);
		//printf("The next query ipAddr: %s\n", serverRecord->rdata);
		/*
		 *迭代遍历 
		 */
        while(1){
		if(serverHead->tag==32768){   //8000
        	struct sockaddr_in askAddr; //下一阶段问的地址 	
        	unsigned int askSize; //返回的地址长度 
        	int backlength;  //返回的字节长度 
        	printf("Send Query Request to %s\n", serverRecord->rdata);
        	init_sockaddr_in(serverRecord->rdata, 53, &askAddr);
        	
        	if(sendto(sockudp,askBuf,DNS_MAX_LENGTH,0,(struct sockaddr*)&askAddr,sizeof(askAddr))!=DNS_MAX_LENGTH){
			printf("send length not right.\n");
		   } 
		    askSize=sizeof(askAddr);
		    backlength=recvfrom(sockudp,bufFromRoot,DNS_MAX_LENGTH,0,(struct sockaddr*)&askAddr,&askSize);
		    //printf("backlength: %d\n",backlength) ;
		    
		    /*
		     *这段解析代码可以弄个函数 
		     */
		    char *p1 = bufFromRoot; //初始化下面服务器传来的指针
		    p1 += getHeader(p1, serverHead);
	     	//printf("Head Tag From diedai: %d\n", serverHead->tag);
	    	p1 += getQuery(p1, serverQuery);
	    	serverRecord->name = serverQuery->name; 
			if(serverHead->tag==32768){
				serverRecord->type = A_TYPE;
			}else serverRecord->type = serverQuery->qtype;
		    serverRecord->rclass = serverQuery->qclass;
		    // printf("dd rRecord Name: %s\n", serverRecord->name); 
	    	// printf("dd rRecord Type: %d\n", serverRecord->type); 
	    	// printf("dd rRecord Class: %d\n", serverRecord->rclass); 
	    	// printf("dd size1: %d\n", strlen(serverRecord->name)+1);
		    // printf("dd size2: %d\n", 2*sizeof(serverRecord->type));
	     	p1 += 6; //压缩指针那两个字节和后面的2个type，共6字节  
	     	//printf("dd strlen offset: %d\n", strlen(serverRecord->name)+1);
		    //i += (2*sizeof(serverRecord->type));
		   // printf("dd sizeof2: %d\n", 2*sizeof(serverRecord->type));
		    //在这里送去解析的只有rr的后几个值
			if(serverHead->tag!=33155){
	        p1 += getRRs(p1, serverRecord);
	     	    if(serverQuery->qtype==MX_TYPE)  {
	     	    	mxRecord->name = (char*)malloc((strlen(serverRecord->rdata)+1)*sizeof(char));
				    strcpy(mxRecord->name, serverRecord->rdata);
				    mxRecord->type = A_TYPE;
				    mxRecord->rclass = 1;
			    	p1 +=getRRs(p1,mxRecord);
				 }
				  
	       }
	     	    
		    //printf("dd The next query ipAddr: %s\n", serverRecord->rdata);		    
		   
	    }
		else if(serverHead->tag==33155){  //8183
			printf("Not found!\n");
			serverRecord->type = serverQuery->qtype;
			serverHead->id = htons(serverHead->id);
			serverHead->tag = htons(serverHead->tag);
			serverHead->queryNum = htons(serverHead->queryNum);
			serverHead->answerNum = htons(serverHead->answerNum);
			serverHead->authorNum = 0;
			serverHead->addNum = 0;
			char *p2 = bufOut + 2;
			p2 += head2buf(p2, serverHead);
	 		p2 += query2buf(p2,serverQuery); 
	 		//p2 += rr2buf(p2,serverRecord);
			uint16_t offset = p2-bufOut-2;
			uint16_t temp = htons(offset);
			memcpy(bufOut, &temp, sizeof(short));
			sed=send(confd,bufOut,offset+2,0);
			if(sed<0)
			{
				perror("send failed");
				close(serfd);
				return -1;
			}
			printf("Send to Client Success\n");
			break;
		}
		else if(serverHead->tag==33152){  //8180
			printf("Found successful!");
			serverRecord->type = serverQuery->qtype;
			serverHead->id = htons(serverHead->id);
			serverHead->tag = htons(serverHead->tag);
			serverHead->queryNum = htons(serverHead->queryNum);
			serverHead->answerNum = htons(serverHead->answerNum);
			serverHead->authorNum = 0;
			serverHead->addNum = 0;
			if(serverQuery->qtype==MX_TYPE){
				serverHead->addNum = htons(1);
			}
			char *p2 = bufOut + 2;
			p2 += head2buf(p2, serverHead);
	 		p2 += query2buf(p2,serverQuery); 
	 		p2 += rr2buf(p2,serverRecord);
	 		if(serverQuery->qtype==MX_TYPE)
	 		p2 +=add2buf(p2,mxRecord,serverQuery);
			uint16_t offset = p2-bufOut-2;
			uint16_t temp = htons(offset);
			memcpy(bufOut, &temp, sizeof(short));
			sed=send(confd,bufOut,offset+2,0);
			if(sed<0)
			{
				perror("send failed");
				close(serfd);
				return -1;
			}
			printf("Send to Client Success\n");
			break;
		}
        	
        	
		} 


		//printf("Recieved : %s\n", bufFromRoot);
		close(sockudp);	
		//break;
	 	
	 }
	 else{ 
	/*
	 *压缩返回 
	 */
	printf("Find in local server cache.\n");
	 o = bufOut + 2;
	 o += head2buf(o, resHead);
	 o += query2buf(o,resQuery); 
	 o += rr2buf(o,resRecord);
	
	 if(recvQuery->qtype == MX_TYPE)
	 	o+=add2buf(o, mxRecord, recvQuery);
	
	 offset=o-bufOut-2;
	 offsetptr = &offset;
	 uint16_t temp = htons(offset); 
	 memcpy(bufOut, &temp, sizeof(short)); //将DNS包长度写在前两字节 
	 
	 
	sed=send(confd,bufOut,offset+2,0);
	if(sed<0)
	{
		perror("send failed");
		close(serfd);
		return -1;
	}
	printf("Send Success\n");
	 }
	
	
    /*
     *发送回去 
     */
	// int outlen = 0;
	// for(bfrlen = 0; ; bfrlen++){
	// 	if(bufFromRoot[bfrlen] == '\0') break;
	// }
	
}
	close(confd);
	close(serfd);
	
	
return 0;
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
				//("Count: %d\n", count);
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
unsigned int head2buf(char *o, dns_header *head){
	memcpy(o, head, sizeof(dns_header));
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
		//("get: %c\n", query->name[i]);
		if(query->name[i] == '.'){
				memcpy(o-count-1, &count, sizeof(char));
				//("Count: %d\n", count);
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
	memcpy(query->name, domainName, i); //此时的i便为变长字符串的长度了，经过了循环遍历 
	//printf("Query name: %s\n", query->name);
	
	query->qtype = ntohs(*(uint16_t*) (q));
	query->qclass = ntohs(*(uint16_t*) (q+2));
	// printf("Query Type: %d\n", query->qtype);
	// printf("Query Class: %d\n", query->qclass);
	return i+4+1; //网络形式的域名表示和点分值差1，在这里特地补上 
}

unsigned int compare( dns_query *query, char *col){
	unsigned int offset = 0;
	//printf("in cmp\n");
	if(offset = cmpDomainName(query->name,col)){
		//printf("in if 1\n");
 		if(cmpTypeClass(query->qtype, col+offset))
			return 1;
	}
	return 0;
}
unsigned int cmpTypeClass( unsigned short type, char *col){
	return 1;
}
unsigned int cmpDomainName( char *name,  char *col){
	int len = strlen(name),i=0;
//	printf("%d\n",len);
	while(i<len){
//		printf("namei: %c\n",name[i]);
//		printf("coli: %c\n",col[i]);
		if(name[i]!=col[i])
		{return 0;}
		i++;
	}
	if(col[i]!=' ') return 0;
	else return len+1;
}

int blocklen(char *cur){
	int i=0;
	while(1){
		if(cur[i]==' '||cur[i]=='\n'||cur[i]=='\0')
			break;
		else i++;
	}
	return i+1;
}

void init_DNS_RR(dns_query *recvQuery,dns_rr *resRecord ,char *col){
	char* cur=col; //光标
	unsigned int len=0;
	//printf("in DNS\n");
	
	/*
	 *拷贝可从query里获取的信息
	 */
//	resRecord->name = (char*)malloc(strlen(recvQuery->name)*sizeof(char));
    resRecord->name=recvQuery->name;
    resRecord->rclass=recvQuery->qclass;
	resRecord->type=recvQuery->qtype;
	
	/*
	 *拷贝ttl 
	 */
	 len=blocklen(cur);  cur+=len;//name
	 //printf("name_length: %d\n",len);

	 len=blocklen(cur);//ttl字符串长度 
	// printf("ttl_char_length:%d\n",len);
	 
	 char strttl[len]; memcpy(strttl, cur, len-1); strttl[len-1]='\0'; cur += len;
	 int TTL = atoi(strttl);    //printf("TTL；%d\n",TTL); //转换后TTL 
	 resRecord->ttl=(uint32_t)TTL; 
	 //printf("ttl: %d\n",resRecord->ttl);
	 /*
	  *移动光标 
	  */
	 len=blocklen(cur);  cur+=len; //type
	 //printf("cur length:%d\n",len);
	 len=blocklen(cur);  cur+=len;//class
	 //printf("len length:%d\n",len);
	 /*
	  *拷贝 rdata 
	  */
	len=blocklen(cur); 
	//printf("rdata: %d\n",len);
	char strData[len]; memcpy(strData,cur,len-1); strData[len-2]='\0'; 
	char*strPointer=strData;
	resRecord->rdata=(char*)malloc((len-1)*sizeof(char));
	memcpy(resRecord->rdata,strPointer,len-1);
	//printf("size: %d\n",strlen(resRecord->rdata));
	//printf("rdata: %s\n",resRecord->rdata); 
	
	/*
	 *拷贝datalength 
	 */
	if(resRecord->type == A_TYPE){
		resRecord->data_len = 4; //永远是4byte
	}
	else if(resRecord->type == CNAME_TYPE){
		resRecord->data_len = strlen(resRecord->rdata)+1;
	}
	else if(resRecord->type == MX_TYPE){
		//这里用现在的域名减去查询的名字长度再+2(pre..)+2(压缩指针)
		resRecord->data_len = strlen(resRecord->rdata)-strlen(recvQuery->name) + 4;
	}
	  
	 //printf("%hu\n",len-1);
	
}
void init_sockaddr_in(char* ip, int port, struct sockaddr_in* addr){
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    addr->sin_addr.s_addr=inet_addr(ip);
    memset(addr->sin_zero, 0, sizeof(addr->sin_zero));
}

unsigned int getRRs(char *q, dns_rr *rRecord){
	uint32_t ipAddr;
	rRecord->ttl = ntohl(*(uint32_t*)(q)); //这里是ntohl，32bit数字的转化 
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
		q += 2; //将Preferencre的长度空出去
	}
	
	if(rRecord->type == A_TYPE){
		ipAddr = *(uint32_t*)(q);
		//printf("Query Answer TTL: %d\n", rRecord->ttl);
		memcpy(&addr, &ipAddr, 4);
		char *ptr = inet_ntop(AF_INET, &addr, str, sizeof(str)); //转化为十进制点分值的IP地址
		//printf("Query Answer IP: %s\n", ptr);
		rRecord->rdata = (char*)malloc((strlen(ptr)+1)*sizeof(char));
		strcpy(rRecord->rdata,ptr);
		return 4 + 2 + rRecord->data_len;
	}
	else if(rRecord->type == CNAME_TYPE){
		char domainName[100];
	memset(domainName, 0, 100);
	char *d = domainName;
	//("d: %s\n", d);
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
	rRecord->rdata = (char*)malloc(i*sizeof(char));
	memcpy(rRecord->rdata, domainName, i); //此时的i便为转换后变长字符串的长度了，经过了循环遍历 
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
	//完成报文中数字加域名形式至点分值的转换 
		while(1){
		if(*q!='\0'){
			count = *(uint8_t*)(q);
			//printf("count:%d\n", count);
			q++;
			while(count){
				// printf("i: %d\n", i);
				// printf("char1:%c\n", *q);
				memcpy(&(domainName[i]), q, sizeof(char));
				// printf("domain name i: %c\n", domainName[i]);
				count--; q++; i++;
			}
			domainName[i] = '.'; //加点 
			i++;
			domainName[i] = '\0';
			i++;
			break;
		}
	}
	// printf("i: %d\n", i);  
	// printf("Converted domain name: %s\n", domainName);
	// printf("length: %d\n", i);
	strcpy(domainName, strcat(domainName, rRecord->name)); //由于压缩了指针，对两字符串进行拼接
	//printf("Converted domain name: %s\n", domainName);
	int totalen = strlen(rRecord->name) + i; //拼接后总长度
	rRecord->rdata = (char*)malloc(totalen*sizeof(char));
	memcpy(rRecord->rdata, domainName, totalen); 
	//printf("Query name: %s\n", rRecord->rdata);
		//printf("The CNAME is: %s\n", rRecord->rdata);
		return 12+rRecord->data_len;
	}
	
}
//用于MX的ip查询，放到addtion里面
unsigned int add2buf(char *o, dns_rr* rr, dns_query* query) {
	// printf("add2buf rrdata: %s\n", rr->rdata);
	// printf("datalength: %d\n", strlen(rr->rdata));
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

