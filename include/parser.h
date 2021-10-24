#pragma once
#include <stdio.h>
#include <unistd.h>

struct route_table {
	__uint32_t prefix;
	__uint32_t next_hop;
	__uint32_t mask;
	int interface;
} __attribute__((packed));

int read_rtable(struct route_table *rTable);
