#! python3

import pyshark
import argparse
import glob
from functools import reduce

packets = []
# limit = 2097152
limit = 0 
gtpprime_udp_port = 3392



def get_total_volume(pkt):
    uplink_volume = reduce((lambda x,y: x+y),[x.hex_value for x in pkt.gtpprime.gprscdr_datavolumefbcuplink.all_fields]) 
    downlink_volume = reduce((lambda x,y: x+y),[x.hex_value for x in pkt.gtpprime.gprscdr_datavolumefbcdownlink.all_fields])
    imsi = pkt.gtpprime.e212_imsi
    frame_no = pkt.number
#     print(frame_no, uplink_volume, downlink_volume)
    
    packets.append({'imsi':imsi, 'total_volume':uplink_volume + downlink_volume, 'frame_no':frame_no})

# def bytes_to_kb(no_of_bytes, binary=True):
#     if binary:
#         kbsize = 1024
#     else:
#         kbsize = 1000
#     return no_of_bytes/kbsize
    

# display_filter = '(gprscdr.causeForRecClosing == 16) && (gprscdr.chargingCharacteristics == 0b:00)'
# decode_as = {'udp.port==3392':'gtpprime'}

# print("start")
# filename1 = r'C:\Users\pallikar\OneDrive - Nokia\Documents\cMG\Cases\CMG-2565 - Volume-limit CDR triggered before the configured value\allues_200109_2202-1.pcap'
# filename2 = r'C:\Users\pallikar\OneDrive - Nokia\Documents\cMG\Cases\CMG-2565 - Volume-limit CDR triggered before the configured value\allues_200109_2202-2.pcap'
# cap1 = pyshark.FileCapture(filename1, display_filter=display_filter, decode_as=decode_as)
# cap2 = pyshark.FileCapture(filename2, display_filter=display_filter, decode_as=decode_as)
# # biggest = cap2[12301]
# first = cap2[0]
# # print(first)
# print (cap1)

# cap2.apply_on_packets(get_total_volume)
# print("number of packets:", len(packets))


# sorted_packets = sorted(packets, key= lambda packet:packet['total_volume'])
# print(sorted_packets[1])

# print("bytes in binary")
# for packet in sorted_packets:
#     delta = packet['total_volume'] - limit * 1024
#     print ('{0}, {1}, {2}, {3}'.format(packet['frame_no'],packet['total_volume'],  delta/1024, packet['imsi']))
                    
                    
# # print("bytes in decimal")
# # for packet in sorted_packets:
# #     delta = packet['total_volume'] - limit * 1000
# #     print ('{0}, {1}, {2}'.format(packet['frame_no'], packet['total_volume'], delta/1000))
    
    
# cap1.close()
# cap2.close()

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
    parser.add_argument("-l", "--limit", type=int, help="the volume-limit set on cMG")
    parser.add_argument("-p", "--port", default = 3392 , type=int, help="the gtpprime udp port (default=3392)")

    args = parser.parse_args()

    if args.limit:
        limit = args.limit
    gtpprime_udp_port = args.port

    expanded_filenames = []
    print("args filenames", args.filenames)
    for filename in args.filenames:
        # print glob.glob(filename)
        print("filename:", filename)
        print("glob:",glob.glob(filename))
        expanded_filenames.append(glob.glob(filename))
    print("filenames", args.filenames)
    filenames_to_parse = list(set([item for x in expanded_filenames for item in x]))
    # sorted_filenames_to_parse = sorted(filenames_to_parse, key=key_for_cap_files)
    print ('Going to parse following files:\n', ', '.join(filenames_to_parse))
    display_filter = '(gprscdr.causeForRecClosing == 16)'
    decode_as = {'udp.port=={0}'.format(gtpprime_udp_port):'gtpprime'}
    print("decode as ", decode_as)









if __name__ == '__main__':
    main()




# print biggest.data








    
   
    