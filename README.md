# go-routetable

Golang Fetch System Route Table

## Route Table

Fetch Route Table from System

## Implementation

Mac OS / BSD variant:

We use golang.org/x/net/route package to fetch route table.

Windows:

Use syscall to load API from dll then call.

Use GetIpForwardTable2 from IPHLPAPI.DLL to fetch route table.

Linux:

Parse /proc/net/route file.

## Note

might need root permission on Mac OS.

Tested on Windows 7,10; Linux; Mac OS Monetrery

## Usage

