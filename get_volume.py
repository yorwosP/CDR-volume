import pyshark
import functools

packets = []
limit = 2097152



def get_total_volume(pkt):
    uplink_volume = reduce((lambda x,y: x+y),[x.hex_value for x in pkt.gtpprime.gprscdr_datavolumefbcuplink.all_fields]) 
    downlink_volume = reduce((lambda x,y: x+y),[x.hex_value for x in pkt.gtpprime.gprscdr_datavolumefbcdownlink.all_fields])
    imsi = pkt.gtpprime.e212_imsi
    frame_no = pkt.number
#     print(frame_no, uplink_volume, downlink_volume)
    
    packets.append({'imsi':imsi, 'total_volume':uplink_volume + downlink_volume, 'frame_no':frame_no})

def bytes_to_kb(no_of_bytes, binary=True):
    if binary:
        kbsize = 1024
    else:
        kbsize = 1000
    return no_of_bytes/kbsize
    

display_filter = '(gprscdr.causeForRecClosing == 16) && (gprscdr.chargingCharacteristics == 0b:00)'
decode_as = {'udp.port==3392':'gtpprime'}

print("start")
filename1 = r'C:\Users\pallikar\OneDrive - Nokia\Documents\cMG\Cases\CMG-2565 - Volume-limit CDR triggered before the configured value\allues_200109_2202-1.pcap'
filename2 = r'C:\Users\pallikar\OneDrive - Nokia\Documents\cMG\Cases\CMG-2565 - Volume-limit CDR triggered before the configured value\allues_200109_2202-2.pcap'
cap1 = pyshark.FileCapture(filename1, display_filter=display_filter, decode_as=decode_as)
cap2 = pyshark.FileCapture(filename2, display_filter=display_filter, decode_as=decode_as)
# biggest = cap2[12301]
first = cap2[0]
# print(first)
print (cap1)

cap2.apply_on_packets(get_total_volume)
print("number of packets:", len(packets))


sorted_packets = sorted(packets, key= lambda packet:packet['total_volume'])
print(sorted_packets[1])

print("bytes in binary")
for packet in sorted_packets:
    delta = packet['total_volume'] - limit * 1024
    print ('{0}, {1}, {2}, {3}'.format(packet['frame_no'],packet['total_volume'],  delta/1024, packet['imsi']))
                    
                    
# print("bytes in decimal")
# for packet in sorted_packets:
#     delta = packet['total_volume'] - limit * 1000
#     print ('{0}, {1}, {2}'.format(packet['frame_no'], packet['total_volume'], delta/1000))
    
    
cap1.close()
cap2.close()




# print biggest.data








    
   
    