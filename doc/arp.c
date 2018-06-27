#define ETH_ADD_LEN         6   /* Ethernet Address Length     */ 
#define ARP_ETH_PADDING    18   /* 18 bytes ethernet padding   */ 
#define ARP_ETH_ADDR_SPACE  6   /* Ethernet Address Space      */ 
#define ARP_IP_ADDR_SPACE   4   /* IP Address Space            */ 

struct arppkt 
{ 
   // Ethernet Header 
   unsigned char    eth_daddr[ETH_ADD_LEN];   /* +00 - Destination ethernet address   */ 
   unsigned char   eth_saddr[ETH_ADD_LEN];   /* +06 - Source ethernet address      */ 
   unsigned short   eth_type;            /* +12 - EtherType                  */ 

   // ARP Header 
   unsigned short   ar_hrd;               /* +14 - Hardware address space         */ 
   unsigned short   ar_pro;               /* +16 - Protocol address space         */ 
   unsigned char   ar_hln;               /* +18 - Length of hardware address      */ 
   unsigned char   ar_pln;               /* +19 - Length of protocol address      */ 
   unsigned short   ar_op;               /* +20 - ARP opcode (command)         */ 
   unsigned char   ar_sha[ETH_ADD_LEN];   /* +22 - Source Hardware address      */ 
   IPAddr         ar_sip;               /* +28 - Source Protocol address      */ 
   unsigned char   ar_tha[ETH_ADD_LEN];   /* +32 - Destination Hardware address   */ 
   IPAddr         ar_tip;               /* +38 - Destination Protocol address   */ 
                                 /*               42 bytes            */ 

   /* Ethernet padding */ 
   //unsigned char eth_pad[ARP_ETH_PADDING];   /* Ethernet padding                     */ 
};  // End of arppkt 