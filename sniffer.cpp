#include <iostream>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <string>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
using namespace std;
bool analyData(char* dataBuf, int dataLen)
{
//    struct in_addr addr;
//    struct iphdr* pIpHdr = (struct iphdr*)dataBuf;
//    cout<<"ip length:"<<pIpHdr->ihl * 4<<endl;
//    addr.s_addr = pIpHdr->daddr;
//    cout<<"destination host:"<<inet_ntoa(addr)<<endl;
//    addr.s_addr = pIpHdr->saddr;
//    cout<<"source host:"<<inet_ntoa(addr)<<endl;
//    cout<<(int)pIpHdr->protocol<<endl;
//    cout<<pIpHdr->version<<endl;

    //cout<<ntohs(pIpHdr->tot_len)<<"\t"<<dataLen<<endl;
    struct iphdr* pIpHdr;
    struct icmphdr* pIcmpHdr;
    pIpHdr  = (struct iphdr*)dataBuf;
    if(((int)pIpHdr->protocol) == IPPROTO_ICMP)
    {
        pIcmpHdr = (struct icmphdr*)(dataBuf + pIpHdr->ihl * 4);
        #define ICMP_ECHOREPLY		0	/* Echo Reply			*/
#define ICMP_DEST_UNREACH	3	/* Destination Unreachable	*/
#define ICMP_SOURCE_QUENCH	4	/* Source Quench		*/
#define ICMP_REDIRECT		5	/* Redirect (change route)	*/
#define ICMP_ECHO		8	/* Echo Request			*/
#define ICMP_TIME_EXCEEDED	11	/* Time Exceeded		*/
#define ICMP_PARAMETERPROB	12	/* Parameter Problem		*/
#define ICMP_TIMESTAMP		13	/* Timestamp Request		*/
#define ICMP_TIMESTAMPREPLY	14	/* Timestamp Reply		*/
#define ICMP_INFO_REQUEST	15	/* Information Request		*/
#define ICMP_INFO_REPLY		16	/* Information Reply		*/
#define ICMP_ADDRESS		17	/* Address Mask Request		*/
#define ICMP_ADDRESSREPLY	18	/* Address Mask Reply		*/
#define NR_ICMP_TYPES		18
int echoreply = 0;
int destUnreach = 0;
int sourceQuench = 0;
int redirect = 0;
int echo = 0;
int timeExceeded = 0;
int parameterprob = 0;
int timestamp = 0;
int timestampReply = 0;
int infoRequest = 0;
int infoReply = 0;
int address = 0;
int addressReply = 0;
        switch(pIcmpHdr->type)
        {
            case ICMP_ECHOREPLY: ++echoreply;
            case ICMP_DEST_UNREACH: ++destUnreach;
            case ICMP_SOURCE_QUENCH: ++sourceQuench;
            case ICMP_REDIRECT: ++redirect;
            case ICMP_ECHO: ++echo;
            case ICMP_TIME_EXCEEDED: ++timeExceeded;
            case ICMP_PARAMETERPROB: ++parameterprob;
            case ICMP_INFO_REQUEST: ++parameterprob;
            case ICMP_ECHO: ++infoRequest;
            case ICMP_ECHO: ++echo;
        }
        return true;
    }else
        return false;
}
//    sniffer：输入需要捕获的协议类型：tcp，udp，icmp
int main(int argc, char* argv[])
{
//    创建原始套接字
    int sockId = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(sockId < 0)
    {
        cout<<"need root user to create sockID"<<endl;
        return 2;
    }
//    设置套接字的缓冲区大小
    int sockBufSize = 1024;
    if(setsockopt(sockId, SOL_SOCKET, SO_RCVBUF, &sockBufSize, sizeof(sockBufSize)))
    {
        cout<<"set socket buf"<<endl;
        return 2;
    }
//    接收数据
//    struct sockaddr_in recvAddr;
//    socklen_t addrLen = sizeof(recvAddr);
    char recvBuf[1024];
    int recvDataLen = 0;
    while(true)
    {
        recvDataLen = recvfrom(sockId, recvBuf, 1024, 0, NULL, NULL);
        if(recvDataLen == 0)
        {
            cout<<"system error"<<endl;
            return 2;
        }
//    分析数据
        if(!analyData(recvBuf, recvDataLen))
        {
            cout<<"recveive error data"<<endl;
            continue;
        }
    }


    return 0;
}
