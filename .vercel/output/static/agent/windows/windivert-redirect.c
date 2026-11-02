/*
 * WinDivert redirect sketch. This file is not compiled into the package.
 * WinDivert.dll and the signed driver are not included, and this source was not run.
 *
 * Build only on Windows with the WinDivert SDK:
 *   cl /W4 windivert-redirect.c WinDivert.lib
 * Then place lexis-windivert.exe next to apply-forward.ps1.
 *
 * The filter keeps the agent's own gate connections out by destination (argv[2..]). Replies from 127.0.0.1:proxy
 * are restored from a small table. Checksums are recomputed for IPv4 only.
 */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "windivert.h"

#define TABLE 4096

typedef struct {
  uint32_t client;
  uint16_t sport;
  uint32_t dest;
  uint16_t dport;
  int used;
} Row;

static Row table[TABLE];

static uint16_t checksum(const uint8_t *data, int len, uint32_t sum) {
  for (int i = 0; i + 1 < len; i += 2) sum += (uint32_t)((data[i] << 8) | data[i + 1]);
  if (len & 1) sum += (uint32_t)(data[len - 1] << 8);
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return (uint16_t)(~sum);
}

static int slot(uint32_t client, uint16_t sport) {
  uint32_t h = (client ^ ((uint32_t)sport * 0x9e3779b1u)) % TABLE;
  for (int n = 0; n < TABLE; n += 1) {
    int i = (int)((h + (uint32_t)n) % TABLE);
    if (!table[i].used || (table[i].client == client && table[i].sport == sport)) return i;
  }
  return 0;
}

int main(int argc, char **argv) {
  int proxy = argc > 1 ? atoi(argv[1]) : 12345;
  /*
   * argv[2..] are IPv4 gate endpoints. The network layer has no process id, so the
   * agent's own tunnel connection is kept out by destination address; without this
   * the dial to the gate is diverted back into 127.0.0.1:proxy and loops.
   */
  char filter[4096];
  int used = snprintf(filter, sizeof(filter), "outbound and ip and tcp and not loopback and tcp.DstPort != %d", proxy);
  for (int a = 2; a < argc && used > 0 && used < (int)sizeof(filter) - 64; a += 1) {
    int ok = 1;
    for (const char *c = argv[a]; *c; c += 1) if (!((*c >= '0' && *c <= '9') || *c == '.')) ok = 0;
    if (!ok) continue;
    used += snprintf(filter + used, sizeof(filter) - (size_t)used, " and ip.DstAddr != %s", argv[a]);
  }
  HANDLE handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
  if (handle == INVALID_HANDLE_VALUE) {
    fprintf(stderr, "WinDivertOpen failed %lu\n", GetLastError());
    return 1;
  }
  unsigned char packet[65535];
  UINT len = 0;
  WINDIVERT_ADDRESS addr;
  while (WinDivertRecv(handle, packet, sizeof(packet), &len, &addr)) {
    PWINDIVERT_IPHDR ip = NULL;
    PWINDIVERT_TCPHDR tcp = NULL;
    if (!WinDivertHelperParsePacket(packet, len, &ip, NULL, NULL, NULL, NULL, &tcp, NULL, NULL, NULL, NULL, NULL)) continue;
    if (!ip || !tcp || ip->Version != 4) continue;
    uint32_t src = ip->SrcAddr;
    uint32_t dst = ip->DstAddr;
    uint16_t sport = ntohs(tcp->SrcPort);
    uint16_t dport = ntohs(tcp->DstPort);
    int loop = dst == htonl(INADDR_LOOPBACK) && sport == (uint16_t)proxy;
    if (loop) {
      int i = slot(dst, dport);
      if (!table[i].used) continue;
      ip->SrcAddr = table[i].dest;
      tcp->SrcPort = htons(table[i].dport);
    } else {
      int i = slot(src, sport);
      table[i].used = 1;
      table[i].client = src;
      table[i].sport = sport;
      table[i].dest = dst;
      table[i].dport = dport;
      ip->DstAddr = htonl(INADDR_LOOPBACK);
      tcp->DstPort = htons((uint16_t)proxy);
    }
    ip->Checksum = 0;
    tcp->Checksum = 0;
    ip->Checksum = htons(checksum((uint8_t *)ip, ip->HdrLength * 4, 0));
    uint8_t pseudo[12];
    memcpy(pseudo, &ip->SrcAddr, 4);
    memcpy(pseudo + 4, &ip->DstAddr, 4);
    pseudo[8] = 0;
    pseudo[9] = 6;
    uint16_t tcp_len = htons((uint16_t)(len - ((uint8_t *)tcp - packet)));
    memcpy(pseudo + 10, &tcp_len, 2);
    uint32_t sum = 0;
    for (int i = 0; i < 12; i += 2) sum += (uint32_t)((pseudo[i] << 8) | pseudo[i + 1]);
    tcp->Checksum = htons(checksum((uint8_t *)tcp, len - (int)((uint8_t *)tcp - packet), sum));
    WinDivertHelperCalcChecksums(packet, len, &addr, 0);
    WinDivertSend(handle, packet, len, NULL, &addr);
  }
  WinDivertClose(handle);
  return 0;
}
