#!/usr/bin/env python

import os
import requests
import struct
import sys
import threading
from collections import OrderedDict
from time import strftime
from subprocess import Popen, PIPE
import radiotap

MAX_TO_PRINT = 30

all_devices = dict()
devices = OrderedDict()
devices_count = 0
packets_count = 0
packets_dropped = 0


def parse_packet(packet):
    try:
        off, rt = radiotap.radiotap_parse(packet)
    except:
        global packets_dropped
        packets_dropped = packets_dropped + 1
        # TODO Why this happening?
        return

    if packet[off] == '\x80':
        # beacon frame
        return

    mac = packet[off + 4:off + 10]
    now = strftime("%Y-%m-%d %H:%M:%S")
    address = radiotap.macstr(mac)
    if not address or address == 'ff:ff:ff:ff:ff:ff':
        return

    if address not in all_devices:
        all_devices[address] = {
            'mac_address': address,
            'first_seen': now,
            'last_seen': now,
            'packets': 0,
        }

    # Use dBm: http://stackoverflow.com/questions/14777114/what-is-rssi-value-in-802-11-packet
    all_devices[address].update({
        'power': rt.get('dbm_antsignal', 0),
        'noise': rt.get('dbm_antnoise', 0),
        'last_seen': now,
        'packets': all_devices[address]['packets'] + 1,
    })

    # Only active devices matter
    # We do that because so much fake mac is appearing, wasn't happening only in C
    # Probably the python radiotap is not working well...
    # TODO why?
    if all_devices[address]['packets'] > 20:
        if address not in devices:
            global devices_count
            devices_count = devices_count + 1

            try:
                r = requests.get('http://www.macvendorlookup.com/api/v2/' + address)
                if r.status_code == 200:
                    vendor = r.json()[0]['company']
                else:
                    vendor = 'Unknown'
            except:
                vendor = 'Unknown'
            devices[address] = {
                'vendor': vendor
            }

        devices[address].update(all_devices[address])

    global packets_count
    packets_count = packets_count + 1


def print_all():
    os.system('clear')

    print 'Total devices: ', devices_count
    print 'Total packets: ', packets_count
    print 'Dropped packets: ', packets_dropped
    print ''

    print '| Address       \t| First Seen         \t| Last Seen          | Power\t| Noise\t| Packets\t| Vendor'
    print '----------------------------------------------------------------------------------------------------------------------------------------'
    to_print = devices.keys()[0:MAX_TO_PRINT]
    for address in to_print:
        data = devices[address]
        print data['mac_address'] + '\t  ' + data['first_seen'] + '\t  ' + data['last_seen'] + '\t  ' \
            + str(data['power']) + '\t  ' + str(data['noise']) + '\t  ' + str(data['packets']) + '\t\t  ' + data['vendor']
    sys.stdout.flush()

    threading.Timer(2, print_all).start()


process = Popen(['./sniffer'], stdout=PIPE)

print_all()
while True:
    length = struct.unpack("<L", process.stdout.read(4))[0]
    packet = process.stdout.read(length)
    parse_packet(packet)

process.wait()
