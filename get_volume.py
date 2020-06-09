#! python3
"""
script to parse wireshark files for GTP' Data Record Transfer (DRTs) messages.
It calculates the total volume (DL/UL) for each DRT and (optionally) shows the difference
(delta) to the configured volume-limit
"""

import pyshark
import argparse
import glob
from functools import reduce

packets = []
gtpprime_udp_port = 3392



def get_total_volume(pkt):
    uplink_volume = reduce((lambda x,y: x+y),[x.hex_value for x in pkt.gtpprime.gprscdr_datavolumefbcuplink.all_fields]) 
    downlink_volume = reduce((lambda x,y: x+y),[x.hex_value for x in pkt.gtpprime.gprscdr_datavolumefbcdownlink.all_fields])
    imsi = pkt.gtpprime.e212_imsi
    frame_no = pkt.number

    
    packets.append({'imsi':imsi, 'total_volume':uplink_volume + downlink_volume, 'frame_no':frame_no})

# def bytes_to_kb(no_of_bytes, binary=True):
#     if binary:
#         kbsize = 1024
#     else:
#         kbsize = 1000
#     return no_of_bytes/kbsize
    

# print("bytes in binary")
# for packet in sorted_packets:
#     delta = packet['total_volume'] - limit * 1024
#     print ('{0}, {1}, {2}, {3}'.format(packet['frame_no'],packet['total_volume'],  delta/1024, packet['imsi']))
                    
                    
# # print("bytes in decimal")
# # for packet in sorted_packets:
# #     delta = packet['total_volume'] - limit * 1000
# #     print ('{0}, {1}, {2}'.format(packet['frame_no'], packet['total_volume'], delta/1000))
    
    

def key_for_cap_files(filename):
    cap = pyshark.FileCapture(filename)
    return(cap[0].sniff_timestamp)

def get_start_end_time(filename):
    cap = pyshark.FileCapture(filename)
    first_packet = cap[0]
    last_packet = cap[-1]
    return(first_packet.sniff_time, last_packet.sniff_time)

def main():

    parser = argparse.ArgumentParser(description='Get volume from DTR in cap/pcap file')    
    parser.add_argument('filenames', nargs='+',  help='list of cap/pcap files to parse')
    parser.add_argument("-l", "--limit", default = 0, type=int, help="the volume-limit set on cMG")
    parser.add_argument("-p", "--port", default = 3392 , type=int, help="the gtpprime udp port (default=3392)")

    args = parser.parse_args()

    limit = args.limit
    gtpprime_udp_port = args.port

    expanded_filenames = []
    for filename in args.filenames:
        expanded_filenames.append(glob.glob(filename))
    filenames_to_parse = list(set([item for x in expanded_filenames for item in x]))
    # sorted_filenames_to_parse = sorted(filenames_to_parse, key=key_for_cap_files)
    print ('Going to parse following files:\n', ', '.join(filenames_to_parse))
    display_filter = '(gprscdr.causeForRecClosing == 16)'
    decode_as = {'udp.port=={0}'.format(gtpprime_udp_port):'gtpprime'}

    packet_mark = 0

    for filename in filenames_to_parse:

        print("Processing: ", filename, end="...")
        cap = pyshark.FileCapture(filename, display_filter=display_filter, decode_as=decode_as)
        # print(cap[1])
        cap.apply_on_packets(get_total_volume)
        cap.close()
        print("Done!")
        sorted_packets = sorted(packets[packet_mark:],  key= lambda packet:packet['total_volume'])

        if len(sorted_packets) > 0:
            print("frame_no,\t\timsi,\t\t total_volume", end= ",\tdelta\n" if limit > 0 else "\n")
            for packet in sorted_packets:
                print ('{0},\t\t {1},\t {2}'.format(packet['frame_no'], packet['imsi'],  packet['total_volume']),end =  "\t" if limit > 0 else  "\n" )
                if limit > 0:
                    delta = packet['total_volume'] - limit
                    print(delta)
        else:
            print("no DRT packets found in trace")
        print()
        packet_mark = len(packets)


    # print("number of packets", len(packets))
    # sorted_packets = sorted(packets, key= lambda packet:packet['total_volume'])












if __name__ == '__main__':
    main()




# print biggest.data








    
   
    