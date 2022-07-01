
#include "dhcp_server.h"
#include "dhcp_packet.h"


int main(void) {

  dhcpd_start();
  dhcpd_serve();
  dhcpd_stop();  

  return 0;

}


