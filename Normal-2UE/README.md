
### Normal-2UE
This set, like Normal-1UE, contains captures of varied normal traffic. Unlike the Normal-1UE set, the generated network traffic was divided between two UEs.
To reduce the number of processing difficulties, we split the total capture file into a sequential series of files. The order of these files is given by the number preceding the file extension. For example, "allcap_20220613162057_00010.pcapng" is the 10th file in the sequence.
***
**NOTE: This set does not contain explicit breakdowns for each interface to reduce the download size. The individual interfaces can be separated from the allcap file in Wireshark as follows:**
1. Add a new column to Wireshark via Edit->Preferences->Appearance->Columns and then click on '+' to add a new column.
2. Set the column 'type' as 'Custom' and the field as 'frame.interface_name'.
3. To select only a particular interface, return to the main Capture page.
4. Apply the filter 'frame.interface_name==' followed by the desired interface. 
5. Export the separated packets via File->Export Specified Packets
