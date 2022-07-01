
#ifndef __DHCP_PACKET__
#define __DHCP_PACKET__

#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#define MAGIC_COOKIE    0x63825363

#define CHADDR_SIZE             16
#define CHADDR_PADDING_SIZE     10
#define SNAME_SIZE              64
#define BOOTP_SIZE             128

#define DHCP_OPTIONS_BUFFER_SIZE      1024

//struct dhcp_option_data {

//    u_int8_t                option;
//    u_int8_t                len;
//    void                    *data;
//    struct dhcp_option_data *next;

//};


// RFC 2131
struct dhcp_packet {

    u_int8_t         op;
    u_int8_t         htype;
    u_int8_t         hlen;
    u_int8_t         hops;
    u_int32_t        xid;
    u_int16_t        secs;
    u_int16_t        flags;

    // in_addr.s_addr is uint32_t
    struct in_addr   ciaddr;
    struct in_addr   yiaddr;
    struct in_addr   siaddr;
    struct in_addr   giaddr;

    union {
        char              chaddr_bfr[CHADDR_SIZE];
        struct ether_addr chaddr;
    } chaddr;
    char             sname[SNAME_SIZE];
    union {
        char         file[BOOTP_SIZE];
        char         bootp[BOOTP_SIZE];
    };

    union {

        u_int8_t        options[DHCP_OPTIONS_BUFFER_SIZE];
        u_int32_t       magic_cookie;

    };

};

#define OP_NET_SUBMASK           1
#define OP_TIME_OFFSET           2

#define OP_HOSTNAME             12

#define OP_MESSAGE_TYPE         53
#define OP_PARAMETER_LIST       55

#define OP_END                 255


#endif

