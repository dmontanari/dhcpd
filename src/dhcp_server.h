#ifndef __DHCP_SERVER_H__
#define __DHCP_SERVER_H__

#define DHCP_SERVER_PORT        67

struct dhcp_server_data {

    int     socketFD;
    int     running;

};

void dhcpd_start();
void dhcpd_stop();

void dhcpd_serve();

#endif
