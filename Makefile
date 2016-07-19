send_arp: send_arp.c
	gcc -o send_arp send_arp.c -lpcap -lnet -lpthread

clean: 
	rm -f send_arp
