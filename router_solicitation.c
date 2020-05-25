/*
 *##############################################################################################
 *
 *         ICMPv6 Router solicitation Multicast Message C program  
 *
 *##############################################################################################
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           /* close() */
#include <string.h>           /* strcpy, memset(), and memcpy() */

#include <netdb.h>            /* struct addrinfo */
#include <sys/types.h>        /* needed for socket(), uint8_t, uint16_t */
#include <sys/socket.h>       /* needed for socket() */
#include <netinet/in.h>       /* IPPROTO_ICMPV6, INET6_ADDRSTRLEN */
#include <netinet/ip.h>       /* IP_MAXPACKET (which is 65535) */
#include <netinet/ip6.h>      /* struct ip6_hdr */
#include <netinet/icmp6.h>    /* struct icmp6_hdr and ICMP6_ECHO_REQUEST */
#include <arpa/inet.h>        /* inet_pton() and inet_ntop() */
#include <sys/ioctl.h>        /* macro ioctl is defined */
#include <bits/ioctls.h>      /* defines values for argument "request" of ioctl. */
#include <net/if.h>           /* struct ifreq */
#include <linux/if_ether.h>   /* ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD */
#include <linux/if_packet.h>  /* struct sockaddr_ll (see man 7 packet) */
#include <net/ethernet.h>

#include <errno.h>            /* errno, perror() */

/* Various Header Lengths  */
#define ETH_HDRLEN            14      /* Ethernet header length */
#define IPV6_HDRLEN           40      /* IPv6 header length */
#define ICMPV6_RS_HDRLEN          8      /* ICMPv6 header length for router solicitation */
#define ICMPV6_OPTION_HDLEN    8      /* ICMPv6 option header length for router solicitation */

/* 
 * Function prototypes
 */ 
uint16_t checksum(uint16_t *, int);
uint16_t icmp6_checksum(struct ip6_hdr, 
                         struct nd_router_solicit, 
                         uint8_t *, 
                         int);
char *allocate_strmem(int);
uint8_t *allocate_ustrmem(int);


/*
 *#####################################################################################
 *                            MAIN FUNCTION STARTS HERE 
 *#####################################################################################
 */
int main (int argc, char **argv)
{
    int i, status, datalen, frame_length, sd, bytes;
    uint8_t *src_mac = NULL, 
            *dst_mac = NULL, 
            *ether_frame = NULL;

    struct addrinfo hints;
    
    char *interface = NULL, 
         *src_ip = NULL, 
         *multicast_icmpv6_dest_ipaddr = NULL;

    struct sockaddr_in6 dest_ipv6_header_multicast;
    struct sockaddr_in6 *dest_ipv6_header_multicast_ptr;

    struct sockaddr_ll device;
    void *tmp;
   
    struct ifreq ifr;
    char dest_mac_in_str[24] = {0};    

    /*
     * Structures for ipv6 , icmpv6 router Solicitation and 
     * icmpv6 options header.  
     */
    struct ip6_hdr ipv6_hdr;
    struct icmp6_hdr icmphdr;
    struct nd_router_solicit rs;
    unsigned char icmpv6_option1[ICMPV6_OPTION_HDLEN]={0};    

    /*
     * argv[1]: Outgoing Interface
     * argv[2]: source ipv6 address
     * argv[3]: destination ipv6 address
     */
    if (argc != 3) {
        printf("Invalid input : %d\n", argc);
        printf("Help section\n"
                "=====================================\n"
                "Enter 2 arguments:\n"
                "1. Outgoing Interface Name\n"
                "2. Source IPV6 Address\n"
              );
        printf("Input Arguments: %s %s\n", argv[1], argv[2]);
        return -1;
    }


    /* 
     * Allocate memory for various arrays.
     */
    src_mac     = allocate_ustrmem(6);
    dst_mac     = allocate_ustrmem(6);
    ether_frame = allocate_ustrmem(IP_MAXPACKET);
    interface   = allocate_strmem(40);
    src_ip      = allocate_strmem(INET6_ADDRSTRLEN);
    multicast_icmpv6_dest_ipaddr = allocate_strmem(INET6_ADDRSTRLEN);

    /*
     *****************************************************************************
     *   INTERFACE, SOURCE IPV6 ADDRESS, DESTINATION IPV6 ADDRESS, 
     *   DESTINATION MAC ADDRESS  AND SOURCE MAC ADDRESS
     *****************************************************************************
     * */

    /* Interface to send packet through.  */
    strcpy(interface, argv[1]);

    /* Source IPv6 address: you need to fill this out */
    strcpy(src_ip, argv[2]);

    /* All Router Address  */
    strcpy(multicast_icmpv6_dest_ipaddr, "ff02::2");

    /* Set destination MAC address: you need to fill these out */
    strcpy(dest_mac_in_str, "33:33:00:00:00:02");
    sscanf(dest_mac_in_str, "%x:%x:%x:%x:%x:%x", 
           (unsigned int *) &dst_mac[0],
           (unsigned int *) &dst_mac[1],
           (unsigned int *) &dst_mac[2],
           (unsigned int *) &dst_mac[3],
           (unsigned int *) &dst_mac[4],
           (unsigned int *) &dst_mac[5]);

    /* Submit request for a socket descriptor to look up interface.  */
    if ((sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("socket() failed to get socket descriptor for using ioctl() ");
        exit (EXIT_FAILURE);
    }

    /* Use ioctl() to look up interface name and get its MAC address.  */
    memset(&ifr, 0, sizeof (ifr));
    snprintf(ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
    if (ioctl(sd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl() failed to get source MAC address ");
        return (EXIT_FAILURE);
    }
    close(sd);

    /* Copy source MAC address.  */
    memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));
    /* 
     * Print Source MAC address of source interface from which the 
     * packet will go out. 
     */
    printf("MAC address for interface %s is ", interface);
    for(i=0; i<5; i++) {
        printf ("%02x:", src_mac[i]);
    }
    printf("%02x\n", src_mac[5]);
    /******************************************************************************/

    /* 
     * Find interface index from interface name and store index in
     * struct sockaddr_ll device, 
     * which will be used as an argument of sendto().
     */
    memset(&device, 0, sizeof (device));
    if ((device.sll_ifindex = if_nametoindex(interface)) == 0) {
        perror("if_nametoindex() failed to obtain interface index ");
        exit(EXIT_FAILURE);
    }
    printf("Index for interface %s is %i\n", interface, device.sll_ifindex);

   /* 
    *#################################################################################
    *          THE ACTUAL ICMPV6 PACKET HEADER FORMATION BEGINS FROM THIS PLACE
    *#################################################################################
    */
    /* Fill out sockaddr_ll.   */
    device.sll_family = AF_PACKET;
    memcpy (device.sll_addr, src_mac, 6 * sizeof (uint8_t));
    device.sll_halen = 6;

    /*
     *
     *Frame 4282: 86 bytes on wire (688 bits), 86 bytes captured (688 bits) on interface 0
      @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
      @                                 L2 Ethernet header
      @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
      Ethernet II, Src: IntelCor_19:8e:f8 (7c:b0:c2:19:8e:f8), Dst: IPv6mcast_ff:11:aa:6e (33:33:ff:11:aa:6e)
        Destination: IPv6mcast_ff:11:aa:6e (33:33:ff:11:aa:6e)
        Address: IPv6mcast_ff:11:aa:6e (33:33:ff:11:aa:6e)
        .... ..1. .... .... .... .... = LG bit: Locally administered address (this is NOT the factory default)
        .... ...1 .... .... .... .... = IG bit: Group address (multicast/broadcast)
        Source: IntelCor_19:8e:f8 (7c:b0:c2:19:8e:f8)
        Address: IntelCor_19:8e:f8 (7c:b0:c2:19:8e:f8)
        .... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)
        .... ...0 .... .... .... .... = IG bit: Individual address (unicast)
        Type: IPv6 (0x86dd)
      @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
      @                                 L3 IPV6 header  
      @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
      Internet Protocol Version 6, Src: fe80::ad6:3956:56b0:97d7, Dst: ff02::1:ff00:1
        0110 .... = Version: 6
        .... 0000 0000 .... .... .... .... .... = Traffic Class: 0x00 (DSCP: CS0, ECN: Not-ECT)
        .... 0000 00.. .... .... .... .... .... = Differentiated Services Codepoint: Default (0)
        .... .... ..00 .... .... .... .... .... = Explicit Congestion Notification: Not ECN-Capable Transport (0)
        .... .... .... 0000 0000 0000 0000 0000 = Flow Label: 0x00000
        Payload Length: 32
        Next Header: ICMPv6 (58)
        Hop Limit: 255
        Source: fe80::ad6:3956:56b0:97d7
        Destination: ff02::1:ff00:1
     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
     @                                 ICMPV6 header   (24 bytes) 
     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
      Internet Control Message Protocol v6
        Type: router Solicitation (135)
        Code: 0
        Checksum: 0x7c24 [correct]
        [Checksum Status: Good]
        Reserved: 00000000
        Target Address: fe80::1
     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
     @                                 ICMPV6 option header  (8 bytes) 
     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
      ICMPv6 Option (Source link-layer address : 7c:b0:c2:19:8e:f8)
        Type: Source link-layer address (1)
        Length: 1 (8 bytes)
        Link-layer address: IntelCor_19:8e:f8 (7c:b0:c2:19:8e:f8)
    */

    /*          
     *@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@          
     *                                  IPV6 HEADER  
     *@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
     */
    /*  
     * 0 and 1)  IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)  = [32 bits or 4 bytes]
     * 2) Payload length = ICMP header(24 bytes) + ICMP option header(8 bytes)        =  [32 bytes]
     * 3) Next header (8 bits): 58 for ICMP                                           = [1 byte]
     * 4) Hop limit (8 bits): default to maximum value                                = [1 byte] 
     * 5) Source IPv6 address (128 bits)                                              = [16 bytes] 
     * 6) Destination IPv6 address (128 bits)                                          = [16 bytes]
     */
    ipv6_hdr.ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);
    ipv6_hdr.ip6_plen = htons(ICMPV6_RS_HDRLEN + ICMPV6_OPTION_HDLEN);
    ipv6_hdr.ip6_nxt = IPPROTO_ICMPV6;
    ipv6_hdr.ip6_hops = 255;
    if ((status = inet_pton(AF_INET6, src_ip, &(ipv6_hdr.ip6_src))) != 1) {
        fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
        exit (EXIT_FAILURE);
    }
    if ((status = inet_pton(AF_INET6, multicast_icmpv6_dest_ipaddr, &(ipv6_hdr.ip6_dst))) != 1) {
        fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
        exit (EXIT_FAILURE);
    }


    /*
     *@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
     *                                ICMPV6 HEADER 
     *@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
     */
    /*  Populate icmp6_hdr portion of router solicit struct. */
    memset(&rs, 0, sizeof(rs));
    rs.nd_rs_hdr.icmp6_type = ND_ROUTER_SOLICIT;                     /* 133 (RFC 4861) */
    rs.nd_rs_hdr.icmp6_code = 0;                                     /* zero for router solicitation (RFC 4861) */
    rs.nd_rs_hdr.icmp6_cksum = htons(0);                             /* zero when calculating checksum */
    rs.nd_rs_reserved = htonl(0);                                    /* Reserved - must be set to zero (RFC 4861) */

    /*
     *@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                    
     *                             ICMPV6 OPTIONS HEADER                 
     *@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                    
     */
    icmpv6_option1[0] = 1;                        /* Option Type - "source link layer address" (Section 4.6 of RFC 4861) */
    icmpv6_option1[1] = ICMPV6_OPTION_HDLEN/8;    /* Option Length - units of 8 octets (RFC 4861) */
    for (i = 0; i < 6; i++) {
        icmpv6_option1[i+2] = (uint8_t) src_mac[i];
    }

    /* 
     *@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                    
     *                              Ethernet frame header.
     *@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                    
     */

    #define ETH_DEST_MAC_OFFSET       0
    #define ETH_DEST_MAC_LEN          6    
    #define ETH_SRC_MAC_OFFSET        (ETH_DEST_MAC_OFFSET + ETH_DEST_MAC_LEN)
    #define ETH_SRC_MAC_LEN           6
    #define ETH_ETHERTYPE_LB_OFFSET   (ETH_SRC_MAC_OFFSET + ETH_SRC_MAC_LEN)
    #define ETH_ETHERTYPE_UB_OFFSET   (ETH_ETHERTYPE_LB_OFFSET + 1)
    #define ETHER_TYPE_LEN            2

    /* 
     * Ethernet frame length = 
     * ethernet header (MAC + MAC + ether type) + IP6 header + ICMPV6 header + ICMPV6 OPTIONS header
     */
    frame_length = ETH_DEST_MAC_LEN + ETH_SRC_MAC_LEN + 
                   ETHER_TYPE_LEN + IPV6_HDRLEN + ICMPV6_RS_HDRLEN + ICMPV6_OPTION_HDLEN;

    /* Destination and Source MAC addresses */
    memcpy (ether_frame, dst_mac, ETH_DEST_MAC_LEN * sizeof (uint8_t));
    memcpy (ether_frame + ETH_SRC_MAC_OFFSET, src_mac, ETH_SRC_MAC_LEN * sizeof (uint8_t));

    /* 
     * Next is ethernet type code (ETH_P_IPV6 for IPv6).
     * http://www.iana.org/assignments/ethernet-numbers
     */
    ether_frame[ETH_ETHERTYPE_LB_OFFSET] = ETH_P_IPV6 / 256;
    ether_frame[ETH_ETHERTYPE_UB_OFFSET] = ETH_P_IPV6 % 256;

    /* Next is ethernet frame data (IPv6 header + ICMPV6 header + ICMPV6 option header). */

    /* IPv6 header */
    memcpy (ether_frame + ETH_HDRLEN, 
            &ipv6_hdr, IPV6_HDRLEN * sizeof (uint8_t));

    struct nd_router_solicit *ns_ptr = NULL;
    /* ICMPV6 header */
    memcpy (ether_frame + ETH_HDRLEN + IPV6_HDRLEN, 
            &rs, ICMPV6_RS_HDRLEN * sizeof (uint8_t));


    /* ICMPV6 Option header */
    memcpy(ether_frame + ETH_HDRLEN + IPV6_HDRLEN + ICMPV6_RS_HDRLEN, 
           icmpv6_option1, ICMPV6_OPTION_HDLEN * sizeof (uint8_t));

    /* 
     * In order to update the checksum, retrieve the location of checksum 
     * from the packet 
     */
    ns_ptr = (struct nd_router_solicit *)(ether_frame + ETH_HDRLEN + IPV6_HDRLEN);
  
    ns_ptr->nd_rs_hdr.icmp6_cksum = icmp6_checksum(ipv6_hdr,       /* ipv6 header structure     */ 
                                                   rs,             /* icmpv6 RS header structure */
                                                   icmpv6_option1, /* icmpv6 options header */        
                                                   ICMPV6_OPTION_HDLEN);
 
    /*  
     *  Create a raw socket to put the packet on the Wire. 
     */
    if ((sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("socket() failed ");
        exit (EXIT_FAILURE);
    }

    /* Send ethernet frame to socket. */
    if ((bytes = sendto(sd, ether_frame, frame_length, 0, 
                        (struct sockaddr *) &device, 
                        sizeof (device))) <= 0) {
        perror("sendto() failed");
        exit(EXIT_FAILURE);
    }

    /* Close socket descriptor. */
    close (sd);

    /* Free allocated memory. */
    free (src_mac);
    free (dst_mac);
    free (ether_frame);
    free (interface);
    free (multicast_icmpv6_dest_ipaddr);
    free (src_ip);

    return (EXIT_SUCCESS);
}

/* Computing the internet checksum (RFC 1071). */
/* Note that the internet checksum does not preclude collisions. */
uint16_t checksum(uint16_t *addr, int len)
{
    int count = len;
    register uint32_t sum = 0;
    uint16_t answer = 0;

    /* Sum up 2-byte values until none or only one byte left. */
    printf("The are bytes from the packets for calculating the checksum:\n");
    printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
    while (count > 1) {
        printf("%x ", htons(*addr));
        sum += *(addr++);
        count -= 2;
    }
    printf("\n@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
    printf("\n");

    /* Add left-over byte, if any. */
    if (count > 0) {
        sum += *(uint8_t *)addr;
    }

    /* 
     * Fold 32-bit sum into 16 bits; we lose information by doing this,
     * increasing the chances of a collision.
     * sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
    */
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    printf("sum: %x\n", sum);

    /* Checksum is one's compliment of sum. */
    answer = ~sum;
    printf("1's complement of sum is answer(Final Checksum): %x\n", answer);

    return (answer);
}

/* Build IPv6 ICMP pseudo-header and call checksum function (Section 8.1 of RFC 2460). */
uint16_t icmp6_checksum (struct ip6_hdr ipv6_hdr, 
                         struct nd_router_solicit nd, 
                         uint8_t *payload, int payloadlen)
{
    char buf[IP_MAXPACKET] = {0};
    char *ptr = NULL;
    int chksumlen = 0;
    int i = 0;

    /* ptr points to beginning of buffer buf */
    ptr = &buf[0]; 

    /* Copy source IP address into buf (128 bits) */
    memcpy (ptr, &ipv6_hdr.ip6_src.s6_addr, sizeof (ipv6_hdr.ip6_src.s6_addr));
    ptr += sizeof (ipv6_hdr.ip6_src);
    chksumlen += sizeof (ipv6_hdr.ip6_src);

    /* Copy destination IP address into buf (128 bits) */
    memcpy (ptr, &ipv6_hdr.ip6_dst.s6_addr, sizeof (ipv6_hdr.ip6_dst.s6_addr));
    ptr += sizeof (ipv6_hdr.ip6_dst.s6_addr);
    chksumlen += sizeof (ipv6_hdr.ip6_dst.s6_addr);

    /*  
     * Copy Upper Layer Packet length into buf (32 bits).
     * Should not be greater than 65535 (i.e., 2 bytes).
     */
    *ptr = 0; ptr++;
    *ptr = 0; ptr++;
    *ptr = (ICMPV6_RS_HDRLEN + payloadlen) / 256;
    ptr++;
    *ptr = (ICMPV6_RS_HDRLEN + payloadlen) % 256;
    ptr++;
    chksumlen += 4;

    /* Copy zero field to buf (24 bits) */
    *ptr = 0; ptr++;
    *ptr = 0; ptr++;
    *ptr = 0; ptr++;
    chksumlen += 3;

    /* Copy next header field to buf (8 bits) */
    memcpy (ptr, &ipv6_hdr.ip6_nxt, sizeof (ipv6_hdr.ip6_nxt));
    ptr += sizeof (ipv6_hdr.ip6_nxt);
    chksumlen += sizeof (ipv6_hdr.ip6_nxt);

    /* Copy ICMPv6 type to buf (8 bits) */
    memcpy (ptr, &nd.nd_rs_hdr.icmp6_type, sizeof (nd.nd_rs_hdr.icmp6_type));
    ptr += sizeof (nd.nd_rs_hdr.icmp6_type);
    chksumlen += sizeof (nd.nd_rs_hdr.icmp6_type);

    /* Copy ICMPv6 code to buf (8 bits) */
    memcpy (ptr, &nd.nd_rs_hdr.icmp6_code, sizeof (nd.nd_rs_hdr.icmp6_code));
    ptr += sizeof (nd.nd_rs_hdr.icmp6_code);
    chksumlen += sizeof (nd.nd_rs_hdr.icmp6_code);

    /* Copy ICMPv6 ID to buf (16 bits) */
    memcpy (ptr, &nd.nd_rs_hdr.icmp6_id, sizeof (nd.nd_rs_hdr.icmp6_id));
    ptr += sizeof (nd.nd_rs_hdr.icmp6_id);
    chksumlen += sizeof (nd.nd_rs_hdr.icmp6_id);

    /* Copy ICMPv6 sequence number to buff (16 bits) */
    memcpy (ptr, &nd.nd_rs_hdr.icmp6_seq, sizeof (nd.nd_rs_hdr.icmp6_seq));
    ptr += sizeof (nd.nd_rs_hdr.icmp6_seq);
    chksumlen += sizeof (nd.nd_rs_hdr.icmp6_seq);

    /* 
     * Copy ICMPv6 checksum to buf (16 bits)
     * Zero, since we don't know it yet.
     */
    *ptr = 0; ptr++;
    *ptr = 0; ptr++;
    chksumlen += 2;

    /* Copy ICMPv6 payload to buf */
    memcpy (ptr, payload, payloadlen * sizeof (uint8_t));
    ptr += payloadlen;
    chksumlen += payloadlen;

    /* Pad to the next 16-bit boundary */
    for (i=0; i<payloadlen%2; i++, ptr++) {
        *ptr = 0;
        ptr += 1;
        chksumlen += 1;
    }

    return checksum ((uint16_t *) buf, chksumlen);
}

/* 
 * Allocate memory for an array of chars.
 */
char *allocate_strmem(int len)
{
    void *tmp = NULL;

    if (len <= 0) {
        fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
        exit (EXIT_FAILURE);
    }

    tmp = (char *) malloc (len * sizeof (char));
    if (tmp != NULL) {
        memset (tmp, 0, len * sizeof (char));
        return (tmp);
    } else {
        fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
        exit (EXIT_FAILURE);
    }
}

/* Allocate memory for an array of unsigned chars. */
uint8_t *allocate_ustrmem(int len)
{
    void *tmp = NULL;

    if (len <= 0) {
        fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
        exit (EXIT_FAILURE);
    }

    tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
    if (tmp != NULL) {
        memset (tmp, 0, len * sizeof (uint8_t));
        return (tmp);
    } else {
        fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
        exit (EXIT_FAILURE);
    }
}
