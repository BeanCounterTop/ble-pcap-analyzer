# ble-pcap-analyzer
Analyzes BLE .pcap files and generates a human-readable output with dereferenced UUIDs

Example:
```
$ ./analyze-ble-pcap.py -p hci.pcap -c ble_char.txt 
Reading gatttool output from ble_char.txt
Found 12 lines of output.
Type      Handle  UUID                                 Hex                                        Ascii                    
-----------------------------------------------------------------------------------------------------------
write_req 0x4e    CHARACTERISTIC_CHUNKED_TRANSFER      0100                                       b'\x01\x00'              
write_req 0x61    CHARACTERISTIC_AUTH                  0100                                       b'\x01\x00'              
write_cmd 0x60    CHARACTERISTIC_AUTH                  0100                                       b'\x01\x00'              
write_cmd 0x60    CHARACTERISTIC_AUTH                  820002                                     b'\x82\x00\x02'          
write_cmd 0x60    CHARACTERISTIC_AUTH                  8300cba1011fd5001258101b9416973c7a9d       b'\x83\x00\xce\xa1\x01\x1e\xd5\x00\x12\x58\x10\xeb\x94\x16\x97\x3c\x7a\x9d'
write_req 0x61    CHARACTERISTIC_AUTH                  0000                                       b'\x00\x00'              
write_req 0x2c    CHARACTERISTIC_CURRENT_TIME          e5070118112126000000e0                     b'\xe5\x07\x01\x18\x11\x21\x26\x00\x00\x00\xe0'
write_req 0x36    CHARACTERISTIC_CONFIGURATION         0100                                       b'\x01\x00'              
write_cmd 0x35    CHARACTERISTIC_CONFIGURATION         0c                                         b'\x0c'     


$ ./analyze-ble-pcap.py --help
usage: analyze-ble-pcap.py [-h] -p PCAP_FILE -c CHAR_FILE [-t MAC] [-o]

Process arguments.

optional arguments:
  -h, --help            show this help message and exit
  -p PCAP_FILE, -pcap PCAP_FILE
                        BLE pcap to parse. This can be generated from
                        hci_snoop.log by opening in wireshark and saving as
                        .pcap.
  -c CHAR_FILE, -char CHAR_FILE
                        Filename to read gatttool output from or write
                        gatttool output to.
  -t MAC, --mac MAC     Query the target MAC with gatttool and store the
                        output for future use.
  -o, --overwrite       If output file exists and a MAC address is supplied,
                        overwrite the file with gatttool output.
```
