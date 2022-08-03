
## =========================================================================== ##
#|                Written by Cooper Coldwell, July 12, 2022                    |#
#| If you need a better documented/commented version of this code, check the   |#
#| notebook titled "Data_prep.ipnyb". Everything is explained in detail there, |#
#| though it may take longer to run or require more memory. YMMV.              |#
## =========================================================================== ##

from __future__ import absolute_import, division, print_function, unicode_literals
# import cupy as cp
import numpy as np
import pandas as pd
# import cudf as cd
import os, sys
import glob as glob
import binascii
import csv
import pickle
# import PIL.Image as Image
from scapy.all import *
from pathlib import Path
from tqdm.auto import tqdm

pathToNormal = 'Normal-1UE/'
pathToNormal2UE = 'Normal-2UE/'
pathToAttack = 'Attacks/'
try:
    os.mkdir('NEW-PREPPED-DATA')
except:
    pass
processedPath = 'NEW-PREPPED-DATA/'

datasets = glob(pathToNormal+'allcap*.pcapng')
print('\nDatasets: \n',datasets,'\n')

print('Start processing normal-1ue data')
print('This could take up to an hour or more')
payloads = []
for file in tqdm(datasets):
    pcap = sniff(offline=str(file))
    for packet in pcap:
        if not Raw in packet:
            continue
        payload = binascii.hexlify(packet[Raw].original)
        payloads.append(payload)
print('\tConverted',len(payloads),'packets to strings.')
print('\tShuffling and saving to csv')
data = {'raw':payloads}
df = pd.DataFrame(data=data).sample(frac=1).reset_index(drop=True)
df.loc[:,'label'] = 'normal'
df.to_csv(f"{processedPath}normal_data.csv", index=False)
print('The first 3 processed packets look like: \n',df.head(3))

print('\n\nStart processing normal-2ue data')
print('This may take a while')
datasets = glob(pathToNormal2UE+'allcap*.pcapng')
payloads = []
for pcap in datasets:
    pcap = sniff(offline=str(file))
    for packet in pcap:
        if not Raw in packet:
            continue
        payload = binascii.hexlify(packet[Raw].original)
        payloads.append(payload)
print('\tConverted',len(payloads),'packets to strings.')
print('\tPickling to avoid data loss in the event memory runs out')
with open('2ue.p','wb') as file:
    pickle.dump(payloads,file)
    
with open('2ue.p','rb') as file:
    payloads = pickle.load(file)
print('\tShuffling and saving to csv')
data = {'raw':payloads,'label':['normal']*len(payloads)}
# print(data['label'][0])
df = pd.DataFrame(data=data).sample(frac=1).reset_index(drop=True)
df.to_csv(f"{processedPath}normal_data_2ue.csv", index=False)

print('\n\nStart processing attack data')
print('This should be quicker')

try:
    del dataset, payload, payloads, data, df
except:
    pass

sets = []
# print(os.listdir(pathToAttack))
for i in os.listdir(pathToAttack):
    dataset = glob(pathToAttack+i+'/Attacks*.pcapng')
    try:
        # print(dataset[0])
        sets.append(str(dataset[0]))
    except:
        print("Failed to find 'Attacks*.pcapng' file in folder: ", str(pathToAttack+i))
        
payloads = []
for file in sets:
    pcap = sniff(offline=str(file))
        
    for packet in pcap[Raw]:
        if not Raw in packet:
            continue
        payload = binascii.hexlify(packet[Raw].original)
        payloads.append(payload)
print('\tConverted',len(payloads),'packets to strings.')

print('\tShuffling and saving to csv')
data = {'raw':payloads}
df = pd.DataFrame(data=data)
df.loc[:,'label'] = 'attack'
df.to_csv(f"{processedPath}malicious_data.csv", index=False)


try:
    del df
except:
    pass

print('\n\nReading the data back in from the CSVs')
normal = pd.read_csv(f"{processedPath}normal_data.csv")
normal2UE = pd.read_csv(f"{processedPath}normal_data_2ue.csv")
malicious = pd.read_csv(f"{processedPath}malicious_data.csv")

print('\nCreating a data set with equal parts attack and normal')
mixed = malicious.sample(frac=1,random_state=100) #take all the malicious
mixed = pd.concat([mixed, normal.sample(frac=1,random_state=100)[0:len(malicious)//2]]) #append the first {half the length of malicious} packets from normal-1ue
mixed = pd.concat([mixed, normal2UE.sample(frac=1,random_state=100)[0:len(malicious)//2]]) #append the first {half the length of malicious} packets from normal-2ue
mixed = mixed.sample(frac=1,random_state=1) #shuffle the data before processing

## Separate the labels (important for using the mixed data to evaluate an autoencoder)
mixed_labels = mixed.pop('label')
np.save(f'{processedPath}mixed_labels.npy',mixed_labels)
del mixed_labels
print('Packets in malicious: ',len(malicious))
print('Packets in mixed: ',len(mixed))
print('Mixed set is of the expected size: ',len(malicious)*2==len(mixed))

print('\nPad the payloads to the same length, then convert to an array of bytes.')
print("The output is saved as:")
print('\t- mixed.npy')
max_packet_length = 1024
def ReshapePackets(dataFrame,saveToFilename,max_packet_length):
    '''Converts from byte strings in a DataFrame to a numpy array of bytes'''
    array = np.array(dataFrame['raw'])
    array = np.ascontiguousarray(array)
    payloads = []
    array.shape
    for i in range(array.shape[0]):
#         print(array[i])
        # Standardize the length of the strings:
        payloadStr = array[i].split('\'')[1]
        payloadStr = payloadStr.ljust(max_packet_length+2, u'0')
        payloadStr = payloadStr[0:max_packet_length]
        array[i] = payloadStr.encode('utf8')
        # Convert to array:
        array[i] = np.frombuffer(array[i],dtype=np.uint8,count=max_packet_length)
        payloads.append(np.reshape(array[i],(array[i].shape[0],1,1)))
    payloads = np.array(payloads)
    print('New data shape: ',payloads.shape)
    np.save(saveToFilename,payloads)
    
ReshapePackets(mixed,f'{processedPath}mixed.npy',max_packet_length)
del mixed

print('\nCreating a data set with equal parts normal-1ue and normal-2ue')
totalNormal = pd.concat([normal.sample(frac=1,random_state=2022),
                         normal2UE.sample(frac=1,random_state=100)[0:len(normal)]
                         ])
totalNormal = totalNormal.sample(frac=1,random_state=2022)

print("\nPad the sets' payloads, then convert them to arrays of bytes.\nThe outputs are saved as:")
print("\t- normal.npy")
print("\t- normal2UE.npy")
print("\t- total_normal.npy")
ReshapePackets(normal,f'{processedPath}normal.npy',max_packet_length)
del normal
ReshapePackets(normal2UE,f'{processedPath}normal2UE.npy',max_packet_length)
del normal2UE
ReshapePackets(totalNormal,f'{processedPath}total_normal.npy',max_packet_length)
del totalNormal
