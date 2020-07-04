#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h>
#include <pthread.h>
#include "netutil.h" /* ネットワーク関連用関数プロトタイプ */
#include "base.h"
#include "ip2mac.h" /* IPアドレスとMACアドレスの関連付け関連の関数プロトタイプ */
#include "sendBuf.h" /* 送信待ちデータ関連の関数プロトタイプ */

typedef struct {
    char *Device1;
    char *Device2;
    int DebugOut;
    char *NextRouter;
} PARAM;

PARAM Param = {
    "eth1",
    "eth2",
    0,
    "192.168.0.254"
}

struct in_addr NextRouter; /* 上位ルータのIPアドレスを保持 */
DEVICE Device[2]; /* 2つのネットワークインタフェースのソケットディスクリプタを保持 */
int EndFlag = 0; /* 終了シグナルの状態用 */

int DebugPrintf(char *fmt, ...) {
    if (Param.DebugOut) {
        va_list args;
        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        va_end(args);
    }

    return (0);
}

int DebugPerror(char *msg) {
    if (Param.DebugOut) {
        fprintf(stderr, "%s : %s\n", msg, strerror(errno));
    }

    return (0);
}

/**
 * ICMP Time Exceeded を送信するための関数
 */
int SendIcmpTimeExceeded(int deviceNo, struct ether_header *eh, struct iphdr *iphdr, u_char *data, int size) {
    struct ether_header reh; /* 返却するパケットの Ethernetヘッダ */
    struct iphdr rih; /* 返却するパケットのipヘッダ */
    struct icmp icmp;
    u_char *ipptr;
    u_char *ptr, buf[1500];
    int len;

    /* 返却するEtherパケットの送信先は元のパケットの送信元のMACアドレス, 送信元は受け取ったNICのMACアドレス */
    memcpy(reh.ether_dhost, eh->ether_shost, 6);
    memcpy(reh.ether_shost, Device[deviceNo].hwaddr, 6);
    reh.ether_type = htons(ETHERTYPE_IP);

    rih.version = 4;
    rih.ihl = 20/4; /* ヘッダ長 (バイト数 / 4) */
    rih.tos = 0;
    rih.tot_len = htons(sizeof(struct icmp) + 64);
    rih.id = 0;
    irh.frag_off = 0;
    rih.ttl = 64;
    rih.protocol = IPPROTO_ICMP;
    rih.check = 0; /* 一旦チェックサムの値はダミーにしておく */
    /* 返却するIPパケットの送信先は元のパケットの送信元のIPアドレス, 送信元は受け取ったNICのIPアドレス */
    rih.saddr = Device[deviceNo].addr.s_addr;
    rih.daddr = iphdr->saddr;

    rih.check = checksum((u_char *)&rih, sizeof(struct iphdr));

    icmp.icmp_type = ICMP_TIME_EXCEEDED;
    icmp.icmp_code = ICMP_TIMXCEED_INTRANS;
    icmp.icmp_cksum = 0;
    icmp.icmp_void = 0;

    /* ipパケット先頭を指すポインタ */
    ipptr = data + sizeof(struct ether_header);

    icmp.icmp_cksum = checksum2((u_char *)&icmp, 8, ipptr, 64); /* TODO */

    ptr = buf;
    memcpy(ptr, &reh, sizeof(struct ether_header));
    ptr += sizeof(struct ether_header);
    memcpy(ptr, &rih, sizeof(struct iphdr));
    ptr += sizeof(struct iphdr);
    memcpy(ptr, &icmp, 8);
    ptr += 8;
    memcpy(ptr, ipptr, 64);
    ptr += 64;
    len = ptr - buf;

    DebugPrintf("write:SendIcmpTimeExceeded:[%d] %dbytes\n", deviceNo, len);
    write(Device[deviceNo].soc, buf, len);

    return (0);
}

int AnalyzePacket(int deviceNo, u_char *data, int size) {
    u_char *ptr;
    int lest;
    struct ether_header *eh;
    char buf[80];
    int tno;
    u_char hwaddr[6];

    ptr = data;
    lest = size;

    if (lest < sizeof(struct ether_header)) {
        DebugPrintf("[%d]:lest(%d) < sizeof(struct ether_header)\n", deviceNo, lest);
        return (-1);
    }

    eh = (struct ether_header *ptr);
    ptr += sizeof(struct ether_header);
    lest -= sizeof(struct ether_header);

    if (memcmp(&eh->ether_dhost, Device[deviceNo].hwaddr, 6) != 0) {
        DebugPrintf("[%d]:dhost not match %s\n", deviceNo, my_ether_ntoa_r((u_char *)&eh->ether_dhost, buf, sizeof(buf)));
        return (-1);
    }

    if (ntohs(eh->ether_type) == ETHERTYPE_ARP) {
        struct ether_arp *arp;

        if (lest < sizeof(struct ether_arp)) {
            DebugPrintf("[%d]:lest(%d) < sizeof(struct ether_arp)\n", deviceNo, lest);
            return (-1);
        }

        arp = (struct ether_arp *)ptr;
        ptr += sizeof(struct ether_arp);
        lest -= sizeof(struct ether_arp);

        if (arp->arp_op == htons(ARPOP_REQUEST)) {
            DebugPrintf("[%d]recv:ARP REQUEST:%dbytes\n", deviceNo, size);
            Ip2Mac(deviceNo, *(in_addr_t *)arp->arp_spa, arp->arp_sha);
        }
        if (arp->arp_op == htons(ARPOP_REPLY)) {
            DebugPrintf("[%d]recv:ARP REPLY:%dbytes\n", deviceNo, size);
            Ip2Mac(deviceNo, *(in_addr_t *)arp->arp_spa, arp->arp_sha);
        } 
    } else if (ntohs(eh->ether_type) == ETHERTYPE_IP) {
        struct iphdr *iphdr;
        u_char option[1500];
        int optionLen;

        if (lest < sizeof(struct iphdr)) {
            DebugPrintf("[%d]:lest(%d) < sizeof(struct iphdr)\n", deviceNo, lest);
            return (-1);
        }

        iphdr = (struct iphdr *)ptr;
        ptr += sizeof(struct iphdr);
        lest -= sizeof(struct iphdr);

        optionLen = iphdr->ihl * 4 - sizeof(struct iphdr);
        if (optionLen > 0) {
            if (optionLen >= 1500) {
                DebugPrintf("[%d]:IP optionLen(%d):too big\n", deviceNo, optionLen);
                return (-1);
            }
            memcpy(option, ptr, optionLen);
            ptr += optionLen;
            lest -= optionLen;
        }

        if (checkIPchecksum(iphdr, option, optionLen) == 0) {
            DebugPrintf("[%d]:bad ip checksum\n", deviceNo);
            return (-1);
        }

        if (iphdr->ttl - 1 == 0) {
            DebugPrintf("[%d]:iphdr->ttl == 0 error\n", deviceNo);
            SendIcmpTimeExceeded(deviceNo, eh, iphdr, data, size);
            return (-1);
        }

        tno = (!deviceNo);

        if ((iphdr->daddr & Device[tno].netmask.s_addr) == Device[tno].subnet.s_addr) {
            /* パケットの送信先が送信側のデバイスのネットワーク内の場合 */
            IP2MAC *ip2mac;

            DebugPrintf("[%d]:%s to TargetSegment\n", deviceNo, in_addr_t2str(iphdr->daddr, buf, sizeof(buf)));

            /* パケットの送信先が送信側のデバイス自体だった場合 */
            if (iphdr->daddr == Device[tno].addr.s_addr) {
                DebugPrintf("[%d]:recv:myaddr\n", deviceNo);
                return (1);
            }

            /* 宛先のIPアドレスからMACアドレスを解決 */
            ip2mac = Ip2Mac(tno, iphdr->daddr, NULL);
            if (ip2mac->flag == FLAG_NG || ip2mac->sd.dno != 0) {
                DebugPrintf("[%d]:Ip2Mac:error or sending\n", deviceNo);
                /* 送信待ちバッファに格納 */
                AppendSendData(ip2mac, 1, iphdr->daddr, data, size);
                return (-1);
            } else {
                /* MACアドレスが取得できたら hwaddr に保存 */
                memcpy(hwaddr, ip2mac->hwaddr, 6);
            }
        } else {
            /* パケットの送信先が別のネットワークの場合 */
            IP2MAC *ip2mac;

            DebugPrintf("[%d]:%s to NextRouter\n", deviceNo, in_addr_t2str(iphdr->daddr, buf, sizeof(buf)));

            /* パケットをルータに送るため、ルータのMACアドレスを解決 */
            ip2mac = Ip2Mac(tno, NextRouter.s_addr, NULL);
            if (ip2mac->flag == FLAG_NG || ip2mac->sd.dno != 0) {
                DebugPrintf("[%d]:Ip2Mac:error or sending\n", deviceNo);
                /*  */
                AppendSendData(ip2mac, 1, NextRouter.s_addr, data, size);
                return (-1);
            } else {
                /* MACアドレスが取得できたら hwaddr に保存 */
                memcpy(hwaddr, ip2mac->hwaddr, 6);
            }
        }

        /* Ethernetヘッダの送信先を hwaddr に書き換え */
        memcpy(eh->ether_dhost, hwaddr, 6);
        /* Ethernetヘッダの送信元を 送信側のデバイスのMACアドレスに書き換え */
        memcpy(eh->ether_shost, Device[tno].hwaddr, 6);

        /* ttlとチェックサムを更新 */
        iphdr->ttl--;
        iphdr->check=0;
        iphdr->check = checksum((u_char *)iphdr, sizeof(struct iphdr), option, optionLen);

        /* 送信側デバイスへ送信 */
        write(Device[tno].soc, data, size);
    }

    return (0);    
}

int Router() {
    struct pollfd targets[2];
    int nready, i, size;
    u_char buf[2048];

    targets[0].fd = Device[0].soc;
    targets[0].events = POLLIN | POLLERR;
    targets[1].fd = Device[1].soc;
    targets[1].events = POLLIN | POLLERR;

    while (EndFlag == 0) {
        switch (nready = poll(targets, 2, 100)) {
            case -1:
                if (errno != EINTR) {
                    DebugPerror("poll");
                }
                break;
            case 0:
                break;
            default:
                for (i = 0; i < 2; i++) {
                    if (targets[1].revents & (POLLIN | POLLERR)) {
                        if ((size = read(Device[i].soc, buf, sizeof(buf))) <= 0) {
                            DebugPerror("read");
                        } else {
                            AnalyzePacket(i, buf, size);
                        }
                    }
                }
                break;
        }
    }

    return (0);    
}

int DisableIpForward() {
    FILE *fp;

    if ((fp = fopen("/proc/sys/net/ipv4/ip_forward", "w")) == NULL) {
        DebugPrintf("cannot write /proc/sys/net/ipv4/ip_forward\n");
        return (-1);
    }
    fputs("0", fp);
    fclose(fp);

    return (0);
}


/* 送信待ちバッファの処理をバックグラウンドで並列処理させるためのスレッド */
void *BufThread(void *arg) {
    BufferSend();

    return (NULL);
}

void EndSignal(int sig) {
    EndFlag = 1;
}

pthread_t BufTid;

int main(int argc, char *argv[], char *envp[]) {
    char buf[80];
    pthread_attr_t attr;
    int status;

    inet_aton(Param.NextRouter, &NextRouter);
    DebugPrintf("NextRouter=%s\n", my_inet_ntoa_r(&NextRouter, buf, sizeof(buf)));

    if (GetDeviceInfo(Param.Device1, Device[0].hwaddr, &Device[0].addr, &Device[0].subnet, &Device[0].netmask) == -1) {
        DebugPrintf("GetDeviceInfo:error:%s\n", Param.Device1);
        return (-1);
    }
    if ((Device[0].soc = InitRaawSocket(Param.Device1, 0, 0)) == -1) {
        DebugPrintf("InitRawSocket:error:%s\n", Param.Device1);
        return (-1);
    }
    DebugPrintf("%s OK\n", Param.Device1);
    DebugPrintf("addr=%s\n", my_inte_ntoa_r(&Device[0].addr, buf, sizeof(buf)));
    DebugPrintf("subnet=%s\n", my_inet_ntoa_r(&Device[0].subnet, buf, sizeof(buf)));
    DebugPrintf("netmask=%s\n", my_inet_ntoa_r(&Device[0].netmask, buf, sizeof(buf)));

    if (GetDeviceInfo(Param.Device2, Device[1].hwaddr, &Device[1].addr, &Device[1].subnet, &Device[1].netmask) == -1) {
        DebugPrintf("GetDeviceInfo:error:%s\n", Param.Device2);
        return (-1);
    }
    if ((Device[1].soc = InitRaawSocket(Param.Device2, 0, 0)) == -1) {
        DebugPrintf("InitRawSocket:error:%s\n", Param.Device2);
        return (-1);
    }
    DebugPrintf("%s OK\n", Param.Device2);
    DebugPrintf("addr=%s\n", my_inte_ntoa_r(&Device[1].addr, buf, sizeof(buf)));
    DebugPrintf("subnet=%s\n", my_inet_ntoa_r(&Device[1].subnet, buf, sizeof(buf)));
    DebugPrintf("netmask=%s\n", my_inet_ntoa_r(&Device[1].netmask, buf, sizeof(buf)));    

    DisableIpForward();

    pthread_attr_init(&attr);
    if ((status = pthread_create(&BufTid, &attr, BufThread, NULL)) != 0) {
        DebugPrintf("pthread_create:%s\n", strerror(status));
    }

    signal(SIGINT, EndSignal);
    signal(SIGTERM, EndSignal);
    signal(SIGQUIT, EndSignal);

    signal(SIGPIPE, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
    signal(SIGTTOU, SIG_IGN);

    DebugPrintf("router start\n");
    Router();
    DebugPrintf("router end\n");

    pthread_join(BufTid, NULL);

    close(Device[0].soc);
    close(Device[1].soc);

    return (0);
}