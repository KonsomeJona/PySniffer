#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>


int main(int argc, char *argv[])
{
  char *dev, errbuf[PCAP_ERRBUF_SIZE];

  dev = pcap_lookupdev(errbuf);
  if (dev == NULL) {
    fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
    return EXIT_FAILURE;
  }

  pcap_t *handle = pcap_create(dev, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    return EXIT_FAILURE;
  }

  if (pcap_can_set_rfmon(handle) != 1) {
    fprintf(stderr, "Device does not support monitor mode.\n");
    return EXIT_FAILURE;
  }

  pcap_set_rfmon(handle, 1);
  pcap_activate(handle);

  // Determine the datalink layer type.
  if (pcap_datalink(handle) != DLT_IEEE802_11_RADIO)
  {
    fprintf(stderr, "Only LINKTYPE_IEEE802_11_RADIOTAP LINK-LAYER HEADER TYPES is supported.\n");
    return EXIT_FAILURE;
  }

  const u_char *packet;
  struct pcap_pkthdr header;
  FILE *out = fdopen(dup(fileno(stdout)), "wb");

  /* Grab a packet */
  while(1) {
    packet = pcap_next(handle, &header);
    int32_t length = header.caplen;
    fwrite(&length, sizeof(int32_t), 1, out);
    fwrite(packet, 1, header.caplen, out);
  }

  /* And close the session */
  pcap_set_rfmon(handle, 0);
  pcap_close(handle);

  return EXIT_SUCCESS;
}
