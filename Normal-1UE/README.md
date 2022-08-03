# Normal-1UE
This dataset consists of normal internet traffic recorded on the same interfaces as the attack dataset. Specifically, it contains network traffic simulated on a single UE with various automated tasks including streaming YouTube videos, accessing 500 popular websites, downloading files via FTP, mounting a SAMBA share and downloading files from it, and having a conference call via Microsoft Teams.

**NOTE: This set does not contain explicit breakdowns for each interface to reduce the download size. The individual interfaces can be separated from the allcap file in Wireshark as follows:**
1. Add a new column to Wireshark via Edit->Preferences->Appearance->Columns and then click on '+' to add a new column.
2. Set the column 'type' as 'Custom' and the field as 'frame.interface_name'.
3. To select only a particular interface, return to the main Capture page.
4. Apply the filter 'frame.interface_name==' followed by the desired interface. 
5. Export the separated packets via File->Export Specified Packets
