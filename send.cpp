#define WIN32  
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include<easyx.h>
#include<iostream>
#include<fstream>
#include <sys/types.h>
#include <stdio.h>
#include<pcap/pcap.h>
#include<stdio.h>
#include<string>
#include<vector>
#include<queue>
#include<thread>
#include<mutex>
#include<bitset>
#include <winsock2.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#include<atomic>
#pragma comment(lib,"ws2_32.lib")
#pragma   comment(lib,"wpcap.lib")
struct ipv4_header
{
    u_char header_length : 4;   // 将ip_hl改为header_length
    u_char version : 4;
    u_char tos;                 //Type of service
    u_short total_length;
    u_short identification;
    u_short frag_and_flags;     //Flags (3 bits) + Fragment offset (13 bits)
    u_char ttl;
    u_char protocol;
    u_short checksum;
    struct in_addr ip_src;
    struct in_addr ip_dst;
};
struct ether_header {
    u_char ether_dhost[6];  //目标MAC地址
    u_char ether_shost[6];  //源MAC地址
    u_short ether_type;     //以太网类型
};
struct link {
    const struct pcap_pkthdr* header;   //报文头部指针
    const u_char* data;                 //报文内容指针
};
struct note {
    std::string ipv4;
    int mask;
    int port;
};
std::mutex lock_tjr;
std::queue<link*> qin1;
std::queue<link*> qin2;
std::queue<link*> qou1;
std::queue<link*> qou2;
std::vector<note*> ip;
pcap_if_t* alldevs;             //网络适配器链表头指针
pcap_if_t* d;                   //嗅探器跳转
int num4;                       //转发表大小
int dtjr_num;
char errbuf[PCAP_ERRBUF_SIZE];  //错误信息缓冲区
void device_tjr();
void load();
void sniff_tjr(int select, int inport);
void tran();
void monitor();
int classfy(link* temp);
void packprint_tjr(link* send, int outport);
void sender(int outport);
int main()
{
    int select1 = 4, select2 = 1;
    initgraph(240, 140);
    settextcolor(WHITE);
    settextstyle(16, 0, _T("宋体"));
    load();
    device_tjr();
    printf("Enter the interface number (1-%d):", dtjr_num);
    std::cin >> select1 >> select2;
    if (select1 < 1 || select1 > dtjr_num || select2 < 1 || select2 > dtjr_num || select1 == select2) {
        if (select1 == select2) printf("\nUse duplicate devices.\n");
        else    printf("\nInterface number out of range.\n");
        /* 释放设备列表 */
        pcap_freealldevs(alldevs);
        return -1;
    }
    std::thread in1_tjr(sniff_tjr, select1, 1);
    std::thread in2_tjr(sniff_tjr, select2, 2);
    std::thread transfer(tran);
    std::thread out1_tjr(sender, 1);
    std::thread out2_tjr(sender, 2);
    std::thread monite(monitor);
    in1_tjr.join();
    in2_tjr.join();
    transfer.join();
    out1_tjr.join();
    out2_tjr.join();
    monite.join();
    return 0;
}
void monitor() {
    int qin1num = 0, qin2num = 0, qout1num = 0, qout2num = 0;
    TCHAR sin1[100], sin2[100], sout1[100], sout2[100];
    while (true) {
        std::unique_lock<std::mutex> lock(lock_tjr);
        qin1num = qin1.size();
        qin2num = qin2.size();
        qout1num = qou1.size();
        qout2num = qou2.size();
        swprintf_s(sin1, _T("QUEUE input1 size:%d"), qin1num);
        swprintf_s(sin2, _T("QUEUE input2 size:%d"), qin2num);
        swprintf_s(sout1, _T("QUEUE output1 size:%d"), qout1num);
        swprintf_s(sout2, _T("QUEUE output2 size:%d"), qout2num);
        outtextxy(0, 0, sin1);
        outtextxy(0, 36, sin2);
        outtextxy(0, 72, sout1);
        outtextxy(0, 108, sout2);
    }

}
void load() {
    std::fstream fib("fib4.txt");
    std::string buf;
    int port4;
    char n;
    char mask1;
    char mask2;
    int len;
    while (fib >> buf)
    {
        note* m = new(note);
        m->ipv4 = buf;
        fib.get(); fib.get();//读取出文件中的两个空格
        fib.get(mask1); fib.get(mask2);
        len = 10 * (mask1 - '0') + (mask2 - '0');
        m->mask = len;
        fib.get(); fib.get();//读取出文件中的两个空格
        fib.get(n);
        port4 = n - '0';
        m->port = port4;
        ip.push_back(m);
    }
    fib.close();
    num4 = ip.size();
    note* tem = NULL;
    for (int i = 0; i < num4; i++) {
        for (int j = 0; j < num4 - i - 1; j++) {
            if (ip[j]->mask < ip[j + 1]->mask) {
                tem = ip[j];
                ip[j] = ip[j + 1];
                ip[j + 1] = tem;
            }
        }
    }
}
void sniff_tjr(int select, int inport) {
    int i;
    pcap_t* handle;
    struct bpf_program fp;
    char filter_exp[] = "ip";
    bpf_u_int32 net = 0;
    pcap_pkthdr* header = 0;
    const u_char* pkt_data = 0;
    /* 跳转到选中的适配器 */
    for (d = alldevs, i = 0; i < select - 1; d = d->next, i++);
    // 打开网卡
    handle = pcap_open_live(d->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        std::cerr << "Couldn't open device: " << errbuf << std::endl;
    }

    // 编译过滤器表达式
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        std::cerr << "Couldn't parse filter " << filter_exp << ": " << pcap_geterr(handle) << std::endl;
    }

    // 应用过滤器表达式
    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Couldn't install filter " << filter_exp << ": " << pcap_geterr(handle) << std::endl;
    }

    // 开始捕获 
    while (1) {
        if ((pcap_next_ex(handle, &header, &pkt_data)) > 0) {
            link* m = new(link);
            m->data = pkt_data;
            m->header = header;
            std::unique_lock<std::mutex> lock(lock_tjr);
            if (inport == 1)qin1.push(m);
            if (inport == 2)qin2.push(m);
        }
    }
    pcap_close(handle);
}
void tran() {
    link* temp = NULL;
    while (true) {
        std::unique_lock<std::mutex> lock(lock_tjr);
        if (!qin1.empty() || !qin2.empty()) {
            if (!qin1.empty()) {
                temp = qin1.front();
                if (classfy(temp) == 1) {
                    qou1.push(temp);
                    qin1.pop();
                }
                else {
                    qou2.push(temp);
                    qin1.pop();
                }
            }
            if (!qin2.empty()) {
                temp = qin2.front();
                if (classfy(temp) == 1) {
                    qou1.push(temp);
                    qin2.pop();
                }
                else {
                    qou2.push(temp);
                    qin2.pop();
                }
            }
        }
    }
}
int classfy(link* temp) {
    const u_char* buffer = temp->data;
    struct ipv4_header* ip_hdr;
    ip_hdr = (struct ipv4_header*)(buffer + sizeof(struct ether_header));
    //std::string buf(inet_ntoa(ip_hdr->ip_src));
    int i;
    for (i = 0; i < num4; i++) {
        const char* fib4 = (ip[i]->ipv4).c_str();
        const char* iptemp = inet_ntoa(ip_hdr->ip_dst);
        unsigned long  b0 = inet_addr(fib4);
        unsigned long  b2 = inet_addr(iptemp);
        b0 = b0 << (32 - ip[i]->mask);
        b2 = b2 << (32 - ip[i]->mask);
        if (memcmp(&b0, &b2, 32) == 0) { return ip[i]->port; }
    }
    return 2;
}
void sender(int outport) {
    link* send = NULL;
    if (outport == 1) {
        while (true) {
            std::unique_lock<std::mutex> lock(lock_tjr);
            if (!qou1.empty()) {
                send = qou1.front();
                qou1.pop();
                packprint_tjr(send, outport);
                delete send;
            }
        }
    }
    else {
        while (true) {
            std::unique_lock<std::mutex> lock(lock_tjr);
            if (!qou2.empty()) {
                send = qou2.front();
                qou2.pop();
                packprint_tjr(send, outport);
                delete send;
            }
        }
    }
}
void device_tjr() {
    /* 获取本机设备列表 */
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }
    /* 打印列表 */
    for (d = alldevs; d; d = d->next)
    {
        printf("%d. %s", ++dtjr_num, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }
    if (dtjr_num == 0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
    }
}
void packprint_tjr(link* send, int outport) {
    const u_char* buffer = send->data;
    // 解析以太网帧头部
    struct ether_header* eth_hdr;
    eth_hdr = (struct ether_header*)buffer;

    printf("Source MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2], eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);
    printf("Destination MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2], eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);

    // 解析IP数据包头部
    struct ipv4_header* ip_hdr;
    ip_hdr = (struct ipv4_header*)(buffer + sizeof(struct ether_header));
    printf("Source IP address: %s\n", inet_ntoa(ip_hdr->ip_src));
    printf("Destination IP address: %s\n", inet_ntoa(ip_hdr->ip_dst));
    printf("Packlength:%d\n", ((send->header)->caplen));
    printf("Port:%d\n", outport);
    for (bpf_u_int32 i = 0; i < (send->header)->caplen; ++i) {
        if (0 < i && 0 == i % 16) printf("\n");
        printf("%2x ", (send->data)[i]);
    }
    printf("\n=======================================================\n");
}