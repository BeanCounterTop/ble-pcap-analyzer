#!/usr/bin/env python3

import os
from scapy.all import *
import re
import subprocess
from ble_uuids import UUIDS
import argparse


parser = argparse.ArgumentParser(description='Process arguments.')
parser.add_argument('-p', '-pcap', dest='pcap_file', required=True, help='BLE pcap to parse.  This can be generated from hci_snoop.log by opening in wireshark and saving as .pcap.')
parser.add_argument('-c', '-char', dest='char_file', required=True, help='Filename to read gatttool output from or write gatttool output to.')
parser.add_argument('-t', '--mac', dest='mac', help='Query the target MAC with gatttool and store the output for future use.')
parser.add_argument('-o', '--overwrite', default=False, dest='overwrite', action='store_true', help='If output file exists and a MAC address is supplied, overwrite the file with gatttool output.')

args = parser.parse_args()

char_file = args.char_file
pcap_file = args.pcap_file
mac = args.mac
overwrite = args.overwrite

opcode_dict = {18: "write_req", 82: "write_cmd", 27: "recv_val"}

opcode_filter_list = [18, 82, 27]


def create_gatttool_output_file(gatttool_output_file, mac_address):
        try:
            with open(gatttool_output_file, 'w') as output_file:
                subprocess.call(['gatttool', '-t', 'random', '-b', mac_address, '--characteristics'], stdout=output_file)
            
            with open(gatttool_output_file, 'r') as output_file:
                return output_file.readlines()

        except Exception as e:
            print("Error while generating gatttool output.")
            print(e)
            print("Run this command and check output: gatttool -b " + mac_address + " --characteristics")
            exit(1)
        
def get_ble_data(gatttool_output_file, target_device_ble_mac_address = None, overwrite = False):
    gatttool_output = None

    if ( 
            os.path.exists(gatttool_output_file) 
            and target_device_ble_mac_address 
            and overwrite
        ) or (
            not os.path.exists(gatttool_output_file) 
            and target_device_ble_mac_address
        ):
        print("Querying " + target_device_ble_mac_address + " for BLE characteristics and storing output in " + gatttool_output_file)
        gatttool_output = create_gatttool_output_file(gatttool_output_file, target_device_ble_mac_address)
    
    if ( 
            os.path.exists(gatttool_output_file) 
            and target_device_ble_mac_address 
            and not overwrite
        ):
        print("Existing output file and overwite flag set to False. Ignoring MAC address.")

    if os.path.exists(gatttool_output_file) and not gatttool_output:
        with open(gatttool_output_file, 'r') as gatttool_file:
            print("Reading gatttool output from " + gatttool_output_file)
            gatttool_output = gatttool_file.readlines()

    if not gatttool_output:
        print ("Error getting gatttool output.")
        exit(1)
    
    print("Found " + str(len(gatttool_output_file)) + " lines of output.")

    unsorted_ble_data = []
    ble_data = []
    pattern = re.compile(r"^handle = (?P<char_handle>[x0-9a-f]+)[a-z0-9\,\=\s]+uuid = (?P<uuid>[-0-9a-f]+)")
    for uuid_line in gatttool_output:
        matches = re.search(pattern, uuid_line)
        unsorted_ble_data.append(matches.groupdict())

    sorted_ble_data = sorted(unsorted_ble_data, key=(lambda k: k['char_handle']), reverse=True)
    for ble_datum in sorted_ble_data:
        ble_data.append({'char_handle': int(ble_datum['char_handle'], 0), 'uuid': ble_datum['uuid']})

    if not ble_data:
        print("No characteristics retrieved.  Verify contents of " + gatttool_output_file)
        exit(1)

    return ble_data

def get_uuid(ble_data, handle):
    handle_int = int(handle,0)
    uuid = 0
    for item in ble_data:
        item_handle = int(item['char_handle'])
        if handle_int >= item_handle:
            uuid = item['uuid']
            break

    if uuid:
        known_uuids = dir(UUIDS)

        for known_uuid_name in known_uuids:
            known_uuid_value = str(getattr(UUIDS, known_uuid_name)).lower()
            if known_uuid_value == uuid:
                return known_uuid_name  
    return uuid


def display_hex(hex_string):
    outstring = 'b\''
    for i in range(0, len(hex_string), 2):
        outstring += '\\x' + hex_string[i] + hex_string[i+1]
    outstring += '\''
    return outstring




def get_hex_ascii(pcap, i, pkt_opcode):
    global opcode_dict
    global ble_data
    if pkt_opcode == 27:
        pcap_line = pcap[i].payload.payload.payload.payload.payload.value
    else:
        pcap_line = pcap[i].data
    pcap_line_ascii = repr_hex(pcap_line)
    pcap_line_hex = display_hex(pcap_line_ascii)
    handle = hex(pcap[i].gatt_handle)

    opcode_type = opcode_dict[pkt_opcode]

    uuid = get_uuid(ble_data, handle)

    return_dict = {
        'type': opcode_type,
        'handle': str(handle), 
        'uuid': uuid,
        'ascii': pcap_line_ascii,
        'hex' : str(pcap_line_hex)
    }
    return return_dict

def print_output_header():
    print('{:9} {:7} {:36} {:42} {:25}'.format("Type", "Handle", "UUID", "Hex", "Ascii"))
    print("-----------------------------------------------------------------------------------------------------------")

def parse_pcap(pcap):
    output = []
    for i in range(len(pcap) - 1):
        try:
            packet = pcap[i + 1]
            pkt_opcode = packet.opcode
        except:
            continue
        if pkt_opcode in opcode_filter_list:
            output.append(get_hex_ascii(pcap, i + 1, pkt_opcode))
    return output

def display_pcap_data(parsed_pcap_list):
    print_output_header()

    for item in parsed_pcap_list:
        print( '{:9} {:7} {:36} {:42} {:25}'.format(item['type'], item['handle'], item['uuid'], item['ascii'], item['hex']) )


try:
    pcap = rdpcap(args.pcap_file)
except:
    print ("Failed to import pcap.")
    exit(1)

ble_data = get_ble_data(args.char_file, args.mac, args.overwrite)

parsed_pcap_data = parse_pcap(pcap)

display_pcap_data(parsed_pcap_data)
