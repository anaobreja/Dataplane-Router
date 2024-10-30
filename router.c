#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <string.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ROUTE_ENTRIES 	100000
#define ARP_TYPE		0x0806
#define IP_TYPE		0x0800
#define ECHO_REPLY			0
#define DEST_UNREACHABLE 	3
#define TIMEOUT				11
#define MAX_ARP_ENTRIES		100
#define ARP_REQUEST			1
#define ARP_REPLY			2
#define MAC_LEN 6
#define HTYPE 1
#define HLEN 6
#define PLEN 4
#define TTL 64
#define PROTOCOL 1
#define CODE 0

struct route_table_entry *rtable;
size_t rtable_len;

struct arp_table_entry *arp_table;
size_t arp_table_len;

queue arp_queue;


struct route_table_entry *get_best_entry(struct iphdr *iphdr) {

	int left = 0, right = rtable_len - 1;
    struct route_table_entry *best_entry = NULL;

    while (left <= right) {
        int mid = left + (right - left) / 2;

        uint32_t ip_dest_prefix =
            ntohl(iphdr->daddr & rtable[mid].mask);

        uint32_t ip_searched_prefix =
            ntohl(rtable[mid].prefix & rtable[mid].mask);

        if (ip_searched_prefix == ip_dest_prefix) {
            if (!best_entry ||
                rtable[mid].mask > best_entry->mask) {
                best_entry = &rtable[mid];
            }
            
            left = mid + 1;
        } else if (ip_searched_prefix > ip_dest_prefix) {
            right = mid - 1;
        } else {
            left = mid + 1;
        }
	}

		return best_entry;
}


struct arp_table_entry *search_arp_entry (struct route_table_entry *route_entry)
{
	struct arp_table_entry *arp_entry = NULL;
	for (int i = 0; i < arp_table_len; i++)
		if (arp_table[i].ip == route_entry->next_hop)
			arp_entry = &arp_table[i];

	return arp_entry;
}


void send_icmp_packet(int interface, char *buf, uint8_t type) {
	uint32_t ip;
	ip = inet_addr(get_interface_ip(interface));

	uint8_t mac[MAC_LEN];
	get_interface_mac(interface, mac);

	struct ether_header *eth_hdr = (struct ether_header *) buf;
	memcpy(eth_hdr->ether_shost, mac, HLEN);
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, HLEN);

	uint16_t check;

	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
	size_t len = sizeof(struct ether_header) + 
				sizeof(struct iphdr) +
				sizeof(struct icmphdr) + 8;

	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->saddr = ip;
	ip_hdr->tot_len = len;
	ip_hdr->ttl = TTL;

	ip_hdr->check = 0;
	check = htons(checksum((u_int16_t *)ip_hdr, sizeof(struct iphdr)));
	ip_hdr->check = check;
	ip_hdr->protocol = PROTOCOL;


	struct icmphdr *icmp_hdr = (struct icmphdr *)
	(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
	icmp_hdr->checksum = 0;
	check = htons(checksum((u_int16_t *)icmp_hdr, sizeof(struct icmphdr)));
	icmp_hdr->checksum = check;
	icmp_hdr->type = type;
	icmp_hdr->code = CODE;


	send_to_link(interface, buf, len);
}



void add_arp_entry(uint8_t mac_addr[6], uint32_t ip_addr) {
	struct arp_table_entry new_entry;
	new_entry.ip = ip_addr;
	memcpy(new_entry.mac, mac_addr, MAC_LEN);
	arp_table[arp_table_len++] = new_entry;
}

void broadcast(struct route_table_entry *best_entry, struct ether_header *eth_hdr)
{
	struct packet new_packet;
	struct arp_header *arp_hdr;

	eth_hdr = (struct ether_header *) new_packet.buf;
	arp_hdr = (struct arp_header *)
		(new_packet.buf + sizeof(struct ether_header) );

	uint8_t mac[MAC_LEN];
	get_interface_mac(best_entry->interface, mac);
	
	memcpy(eth_hdr->ether_shost, mac, MAC_LEN);
	memset(eth_hdr->ether_dhost, 0xff, MAC_LEN);
	eth_hdr->ether_type = htons(ARP_TYPE);

	arp_hdr->htype = htons(HTYPE);
	arp_hdr->ptype = htons(IP_TYPE);
	arp_hdr->hlen = HLEN;
	arp_hdr->plen = PLEN;
	arp_hdr->op = htons(ARP_REQUEST);
	memcpy(arp_hdr->sha, eth_hdr->ether_shost, MAC_LEN);
	arp_hdr->spa = inet_addr(get_interface_ip(best_entry->interface));
	memset(arp_hdr->tha, 0, MAC_LEN);
	arp_hdr->tpa = best_entry->next_hop;

	new_packet.len = sizeof(struct ether_header) + sizeof(struct arp_header);
	send_to_link(best_entry->interface, new_packet.buf, new_packet.len);
}

void send_arp_broadcast(struct route_table_entry *best_entry, char* buf,
		size_t len, struct ether_header* eth_hdr) {
	struct packet *buf_packet = malloc(sizeof(struct packet));
	DIE(rtable == NULL, "memory");

	buf_packet->len = len;
	memcpy(buf_packet->buf, buf, len);

	queue_enq(arp_queue, buf_packet);

	broadcast(best_entry, eth_hdr);
}



void ip_packet_manage(int interface, size_t len, char *buf, struct ether_header* eth_hdr) {

	struct iphdr *iphdr = (struct iphdr *)(buf + sizeof(struct ether_header));

	uint16_t check = ntohs(iphdr->check);
    iphdr->check = 0;

    iphdr->check =
        checksum ((uint16_t *) iphdr, sizeof(struct iphdr));

    if (check != iphdr->check) {
        return;
	}

	if (iphdr->ttl == 0 || iphdr->ttl == 1) {
		send_icmp_packet(interface, buf, TIMEOUT);
		return;
	}

	iphdr->ttl--;
	iphdr->check = 0;
	iphdr->check = htons(checksum((uint16_t *)iphdr, sizeof(struct iphdr)));

	if (inet_addr(get_interface_ip(interface)) == iphdr->daddr) {
			send_icmp_packet(interface, buf, ECHO_REPLY);
			return;
	}

	struct route_table_entry *best_entry = get_best_entry(iphdr);

	if (!best_entry) {
		send_icmp_packet(interface, buf, DEST_UNREACHABLE);
		return;
	}

	struct arp_table_entry *arp_entry = search_arp_entry(best_entry);

	if (!arp_entry) {
		send_arp_broadcast(best_entry, buf, len, eth_hdr);
		return;
	}

	uint8_t mac[MAC_LEN];
	get_interface_mac(best_entry->interface, mac);

	memcpy(eth_hdr->ether_dhost, arp_entry->mac, MAC_LEN);
	memcpy(eth_hdr->ether_shost, mac, MAC_LEN);

	send_to_link(best_entry->interface, buf, len);

}



void arp_request(char *buf, int interface, struct ether_header* eth_hdr,
	struct arp_header* arp_hdr) {
	uint8_t mac[MAC_LEN];
    get_interface_mac(interface, mac);

    uint32_t ip;
    ip = inet_addr(get_interface_ip (interface));

    if (ip != arp_hdr->tpa)
        return;

    memcpy(arp_hdr->tha, arp_hdr->sha, MAC_LEN);
    memcpy(arp_hdr->sha, mac, MAC_LEN);
    arp_hdr->op = htons(ARP_REPLY);
	ip = arp_hdr->tpa;
    arp_hdr->tpa = arp_hdr->spa;
    arp_hdr->spa = ip;

	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, MAC_LEN);
    memcpy(eth_hdr->ether_shost, mac, MAC_LEN);

    size_t len = sizeof(struct ether_header) + sizeof(struct arp_header);
    send_to_link(interface, buf, len);
}



void arp_reply(struct ether_header* eth_hdr, struct arp_header *arp_hdr) {

	add_arp_entry(arp_hdr->sha, arp_hdr->spa);

	while (!queue_empty(arp_queue)) {
		struct packet *packet = queue_deq(arp_queue);

		struct iphdr *ip_hdr = (struct iphdr *)(packet->buf + sizeof(struct ether_header));

		struct route_table_entry *best_entry = get_best_entry(ip_hdr);

		uint8_t mac[MAC_LEN];
		get_interface_mac(best_entry->interface, mac);


		struct arp_table_entry *arp_entry = search_arp_entry(best_entry);

		eth_hdr = (struct ether_header *) (packet->buf);
		memcpy(eth_hdr->ether_shost, mac, MAC_LEN);
		memcpy(eth_hdr->ether_dhost, arp_entry->mac, MAC_LEN);
		
		send_to_link(best_entry->interface, packet->buf, packet->len);
		free(packet);
	}
}

void arp_packet_manage(int interface, size_t len, char *buf, struct ether_header *eth_hdr)
{
    struct arp_header *arp_hdr = (struct arp_header *)(buf + (sizeof (struct ether_header)));

    switch (ntohs(arp_hdr->op)) {
        case ARP_REQUEST: arp_request(buf, interface, eth_hdr, arp_hdr);
        case ARP_REPLY: arp_reply(eth_hdr, arp_hdr);
        default: return;
    }
}

int compare(const void* p, const void* q) {

	const struct route_table_entry *a, *b;

	a = (const struct route_table_entry*)p;
	b = (const struct route_table_entry*)q;

	uint32_t a_prefix = ntohl(a->prefix);
	uint32_t b_prefix = ntohl(b->prefix);

	uint32_t a_mask = ntohl(a->mask);
	uint32_t b_mask = ntohl(b->mask);

 	if (a_prefix == b_prefix)
 		return a_mask - b_mask;

	return a_prefix - b_prefix;
}


int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	init(argc - 2, argv + 2);

	struct route_table_entry *rtable_filtered;
	size_t rtable_filtered_len;

	rtable = malloc(sizeof(struct route_table_entry) * MAX_ROUTE_ENTRIES);
	rtable_len = read_rtable(argv[1], rtable);
	DIE(rtable == NULL, "memory");

	
	arp_table = malloc(sizeof(struct arp_table_entry) * MAX_ARP_ENTRIES);
	arp_table_len = 0;
	DIE(rtable == NULL, "memory");

 	rtable_filtered = malloc(sizeof(struct route_table_entry) * MAX_ROUTE_ENTRIES);
	rtable_filtered_len = 0;
	DIE(rtable == NULL, "memory");

	for (int i = 0; i < rtable_len; ++i)
		if (ntohl(rtable[i].prefix) == ntohl(rtable[i].prefix & rtable[i].mask)) {
			rtable_filtered[rtable_filtered_len++] = rtable[i];
		} else
			i++;

	rtable = rtable_filtered;
	rtable_len = rtable_filtered_len;

	qsort(rtable, rtable_len, sizeof(struct route_table_entry), compare);

	arp_queue = queue_create();

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");


		struct ether_header *eth_hdr = (struct ether_header *) buf;

		uint16_t ether_type = ntohs(eth_hdr->ether_type);

		switch (ether_type) {
            case IP_TYPE:
                ip_packet_manage(interface, len, buf, eth_hdr);
             case ARP_TYPE:
                arp_packet_manage(interface, len, buf, eth_hdr);
            default:
                fprintf(stderr, "Invalid packet");
        }
	}

	free(rtable);
	free(arp_table);
	free(rtable_filtered);
}
