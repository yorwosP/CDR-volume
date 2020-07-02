script to parse wireshark files for GTP' Data Record Transfer (DRTs) messages.
It calculates the total volume (DL/UL) for each DRT and (optionally) shows the 
difference (delta) to the configured volume-limit

<b>Installation:</b><br>
<i>pip install -r requirements.txt</i>

<b>Usage:</b>
<pre>

get_volume.py [-h] [-l LIMIT] [-p PORT] filenames [filenames ...]

  -l LIMIT, --limit LIMIT the volume-limit set on cMG
  -p PORT, --port PORT  the gtpprime udp port (default=3392)
  
</pre>  

<b>Example:</b>

<pre>
python get_volume.py  *pcap -l 9000000

Going to parse following files:
 imsi_4247_wo_gx.pcap, imsi_238023635014839_200512_1401.pcap
Processing:  imsi_4247_wo_gx.pcap...Done!
no DRT packets found in trace

Processing:  imsi_238023635014839_200512_1401.pcap...Done!
frame_no,               imsi,            total_volume,  delta
49,              238023635014839,        12714396       3714396
69,              238023635014839,        14272236       5272236
64,              238023635014839,        15467688       6467688

</pre>
-----
<b>TODO:</b>
 - add the option to show in bytes, kbytes, mbytes <br>
 - add the option to parse files sequentally (i.e treat them as splitted files of a large cap file)
