#include <iostream>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netdb.h>
#include <arpa/inet.h>
#include<stdio.h>
#include<stdlib.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
using namespace std;

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
int otherType = 0;

bool isTimeOut = false;

void sigAlrm(int signo)
{
    isTimeOut = true;
}

int setPromisc(char* etherName, int sockId)
{
    struct ifreq ifr;
    strncpy(ifr.ifr_name, "eth0", strlen("eth0"));
    if(ioctl(sockId, SIOCGIFFLAGS, &ifr) == -1)
    {
        perror("can't get ethernet interface info:");
        return -1;
    }
    ifr.ifr_flags |= IFF_PROMISC;
    if(ioctl(sockId, SIOCSIFFLAGS, &ifr) == -1)
    {
        cout<<"can't set ethernet interface info\n";
        return -2;
    }
    return 0;
}

void statistics()
{
    cout<<"ICMP_ECHOREPLY: "<<echoreply<<"\n";
    cout<<"ICMP_DEST_UNREACH: "<<destUnreach<<"\n";
    cout<<"ICMP_SOURCE_QUENCH: "<<sourceQuench<<"\n";
    cout<<"ICMP_REDIRECT: "<<redirect<<"\n";
    cout<<"ICMP_ECHO: "<<echo<<"\n";
    cout<<"ICMP_TIME_EXCEEDED: "<<timeExceeded<<"\n";
    cout<<"ICMP_PARAMETERPROB: "<<parameterprob<<"\n";
    cout<<"ICMP_TIMESTAMP: "<<timestamp<<"\n";
    cout<<"ICMP_TIMESTAMPREPLY: "<<timestampReply<<"\n";
    cout<<"ICMP_INFO_REQUEST: "<<infoRequest<<"\n";
    cout<<"ICMP_INFO_REPLY: "<<infoReply<<"\n";
    cout<<"ICMP_ADDRESS: "<<address<<"\n";
    cout<<"ICMP_ADDRESSREPLY: "<<addressReply<<"\n";
    cout<<"OtherType: "<<otherType<<"\n";
}

bool analyData(char* dataBuf, int dataLen)
{
    struct iphdr* pIpHdr;
    struct icmphdr* pIcmpHdr;
    pIpHdr  = (struct iphdr*)dataBuf;
    if(((int)pIpHdr->protocol) == IPPROTO_ICMP)
    {
        pIcmpHdr = (struct icmphdr*)(dataBuf + pIpHdr->ihl * 4);
        switch(pIcmpHdr->type)
        {
            case ICMP_ECHOREPLY: ++echoreply;break;
            case ICMP_DEST_UNREACH: ++destUnreach;break;
            case ICMP_SOURCE_QUENCH: ++sourceQuench;break;
            case ICMP_REDIRECT: ++redirect;break;
            case ICMP_ECHO: ++echo;break;
            case ICMP_TIME_EXCEEDED: ++timeExceeded;break;
            case ICMP_PARAMETERPROB: ++parameterprob;break;
            case ICMP_TIMESTAMP: ++timestamp;break;
            case ICMP_TIMESTAMPREPLY: ++timestampReply;break;
            case ICMP_INFO_REQUEST: ++infoRequest;break;
            case ICMP_INFO_REPLY: ++infoReply;break;
            case ICMP_ADDRESS: ++address;break;
            case ICMP_ADDRESSREPLY: ++addressReply;break;
            default: ++otherType;break;
        }
        return true;
    }else
        return false;
}
//    sniffer：输入需要捕获的协议类型：tcp，udp，icmp
int main(int argc, char* argv[])
{
//    创建原始套接字
    int sockId;
    char recvBuf[1024];
    int recvDataLen = 0;
    int servicetime = 3600 * 24;
    fd_set inputSet;

    if(argc == 2)
    {
        servicetime = atoi(argv[1]);
    }
    sockId = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
    setPromisc("eth0", sockId);
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
    if(signal(SIGALRM, sigAlrm) == SIG_ERR)
    {
        cout<<"fail to set alarm signal function"<<"\n";
        return 2;
    }
    alarm(servicetime);
    while(!isTimeOut)
    {
        FD_ZERO(&inputSet);
        FD_SET(sockId, &inputSet);
        FD_SET(STDIN_FILENO, &inputSet);
        int maxId = max(sockId, STDIN_FILENO);
        int rt = select(maxId + 1, &inputSet, NULL, NULL, NULL);
        if(rt > 0)
        {
            if(FD_ISSET(STDIN_FILENO, &inputSet))
            {
                char c;
                cin>>c;
                if(c == 'q' || c == 'Q')
                {
                    break;
                }else
                {
                    cout<<"input \"Q\" or \"q\" to quit the process!"<<endl;
                }
            }
            if(FD_ISSET(sockId, &inputSet))
            {
                recvDataLen = recvfrom(sockId, recvBuf, 1024, 0, NULL, NULL);
                if(recvDataLen == 0)
                {
                    cout<<"system error"<<endl;
                    return 2;
                }
                analyData(recvBuf, recvDataLen);
            }
        }
    }
    statistics();
    return 0;
}
