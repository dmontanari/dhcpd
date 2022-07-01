

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <errno.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include <netinet/ether.h>

#include "dhcp_server.h"
#include "dhcp_packet.h"

struct dhcp_server_data   *server = NULL;

void dhcpd_start() {

    if ( server ) {
        fprintf(stderr, "Oops... server already initialized?\n");
        exit(EXIT_FAILURE);
    }

    server = (struct dhcp_server_data *)malloc(sizeof(struct dhcp_server_data));
    if ( !server ) {
        fprintf(stderr, "Oops... malloc fail to allocate server data...\n");
        perror("start_dhcpd: ");
        exit(EXIT_FAILURE);
    }

    //////////////////////////////////////////////////////////////////////
    //
    //                  Open the server port
    //
    struct sockaddr_in serverAddr;

    server->socketFD = socket(AF_INET, SOCK_DGRAM, 0);

    memset(&serverAddr, 0, sizeof(serverAddr));     // clear data structure
    serverAddr.sin_family = AF_INET;                // internet addr family
    serverAddr.sin_port = htons(DHCP_SERVER_PORT);  // port number

    // TODO: Serve only on a specific address
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY); // any incoming address

    

    int enable = 1;
    setsockopt(server->socketFD, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
    setsockopt(server->socketFD, SOL_SOCKET, SO_BROADCAST, &enable, sizeof(int));

    int result = bind(server->socketFD, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
    if (result < 0)
    {
        // bind failed
        perror("Error binding socket");
        close(server->socketFD);
        exit(EXIT_FAILURE);
    }

    server->running = 1;

}

void dhcpd_stop() {

    if ( !server )
        return;

    close( server->socketFD );
    free(server);
    server = NULL;


}

// Helper to read socket
int receive(void *to, int len) {

    struct sockaddr_in clientAddr;
    socklen_t addrLen = sizeof(struct sockaddr_in);
    int result = -1;

    result = recvfrom(server->socketFD, to, len, 0, (struct sockaddr *)&clientAddr, &addrLen);
    if ( result < 0 ) {
        fprintf(stderr, "Error errno %i\n", errno);
        perror("Receive packet error... ");
        return 0;
    }

    return result;
}

// Helper to receive data
int receive_packet(struct dhcp_packet *packet) {

    struct dhcp_packet dhcpPacket;
    int read_len = 0;

    memset(&dhcpPacket, 0, sizeof(struct dhcp_packet));
    read_len = receive(&dhcpPacket, sizeof( struct dhcp_packet));

    printf("---------- NEW DATA -----------\n");
    printf("---[ Received %i bytes - sizeof struct %lu bytes\n", read_len, sizeof(struct dhcp_packet));

    // TODO: Receive options

    // if ( clientAddr.sin_port != 68)
    // {
    //     return;
    // }

    // Converting from network byte order to host byte order
    packet->op          = dhcpPacket.op;
    packet->htype       = dhcpPacket.htype;
    packet->hlen        = dhcpPacket.hlen;
    packet->hops        = dhcpPacket.hops;
    packet->xid         = ntohl(dhcpPacket.xid);
    packet->secs        = ntohs(dhcpPacket.secs);
    packet->flags       = ntohs(dhcpPacket.flags);

    packet->ciaddr.s_addr   = ntohl(dhcpPacket.ciaddr.s_addr);
    packet->yiaddr.s_addr   = ntohl(dhcpPacket.yiaddr.s_addr);
    packet->siaddr.s_addr   = ntohl(dhcpPacket.siaddr.s_addr);
    packet->giaddr.s_addr   = ntohl(dhcpPacket.giaddr.s_addr);

    // No need to converting chaddr from 
    //  network byte order to host byte order
    //
    //  * The struct ether_addr is 6 bytes (48 bits see ethernet.h)
    //  * DHCP protocol uses 16 bytes for chaddr
    //  * first 6 bytes = client MAC address in NBO
    //  * next 10 bytes = padding
    //
    memcpy(packet->chaddr.chaddr_bfr, dhcpPacket.chaddr.chaddr_bfr, CHADDR_SIZE);

    memcpy(packet->sname, dhcpPacket.sname, SNAME_SIZE);
    memcpy(packet->bootp, dhcpPacket.bootp, BOOTP_SIZE);


    // Options - magic cookie
    packet->magic_cookie = ntohl(dhcpPacket.magic_cookie);

    memcpy(packet->options, dhcpPacket.options, DHCP_OPTIONS_BUFFER_SIZE);

    // Options - next values

    return 1;

}



void dump_dhcp_packet(struct dhcp_packet *packet) {

    printf("%s ", ether_ntoa(&packet->chaddr.chaddr));

    if ( packet->op & 0x01)
      printf(" BOOTREQUEST ");
    else
      printf(" BOOTREPLY   ");

    printf(" HTYPE 0x%X ", packet->htype);
    printf(" HLEN 0x%X ",  packet->hlen);
    printf(" HOPS 0x%X ",  packet->hops);
    printf(" XID 0x%X ",   packet->xid);
    printf(" SECS %u ",    packet->secs);
    printf(" FLAGS %u ",   packet->flags);

    printf(" MC 0x%X ", packet->magic_cookie);

    printf("\n");

}

struct dhcp_option_data *parse_options(void *options) {

    void        *aux    =   NULL;
    u_int8_t    *cmd    =   NULL;
    u_int8_t    *len    =   0;

    struct dhcp_option_data *opts = NULL,
                            *opts_next = NULL;

    aux = options;

    do {
        cmd = (u_int8_t *)aux;
        len = (u_int8_t *)(aux+1);

        if ( !opts )
        {
            opts = (struct dhcp_option_data *)malloc(sizeof(struct dhcp_option_data));
            opts_next = opts;
        }
        else
        {
            //
            opts_next->next = (struct dhcp_option_data *)malloc(sizeof(struct dhcp_option_data));
            opts_next = opts_next->next;
        }
        opts_next->option = *cmd;
        opts_next->len = *len;
        opts_next->data = malloc(opts->len+1);
        memset(opts_next->data, 0, opts_next->len+1);
        memcpy(opts_next->data, aux+2, opts_next->len);

        switch (*cmd) {

            case OP_HOSTNAME:
                printf("Option 12 - Hostname %s (len %u)\n", (char *)opts_next->data, opts_next->len);
                break;

            case OP_MESSAGE_TYPE:
                printf("Option 53 - MESSAGE TYPE %u - len %u\n", *(char *)opts_next->data, opts_next->len);
                break;

           case OP_PARAMETER_LIST:
                printf("Option 55 - Parameters List len %u\n", opts_next->len);
                for (int i=0; i<opts_next->len; i++)
                {
                    u_int8_t *parm = (unsigned char *)(opts_next->data + i);

                    printf("Request parameter %u\n", *parm);
                }

                break;
        }

        aux +=  (2 + opts_next->len);

    } while (*cmd != OP_END);

    return opts;
}

void release_options(struct dhcp_option_data *opts) {

    struct dhcp_option_data *aux = NULL;

    do {
        if (opts)
        {
            aux = opts->next;
            free(opts->data);
            free(opts);
            opts = aux;
        }

    } while (opts);

}

void dhcpd_serve() {

    struct dhcp_packet packet;

    fprintf(stdout, "Server on\n");

    while (server->running) {

        if (receive_packet(&packet)) {

//            receive_options( &options );
            dump_dhcp_packet(&packet);
            struct dhcp_option_data *p = parse_options( (void *)packet.options);
            release_options(p);

        }

    }


}

