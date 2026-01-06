# 6Hunter
6Hunter is an efficient IPv6 router interface discovery framework based on prefix prediction. This framework operates on GNU/Linux. By sending ICMPv6 Echo Request messages and receiving ICMPv6 error messages, 6Hunter discovers router interfaces addresses. 6Route consists of two modules, which are target generation module and  module written in Go.
## Building 6Hunter
To run 6Hunter, you need to first configure Go environment. Then, 6Hunter can be compiled by running:

`go build`
## Using 6Hunter
The parameter -i represents the interface index of your machine. The parameter -a represents the IPv6 address file. The parameter -b represents the scanning budget. The parameter -max-wildcard represents the max number of wildcard for prefix clustering. The parameter -max-cluster represents the max size of prefix cluster for prefix clustering.
The parameter -r represents the packet sending rate. The parameter -c represents the number of scanning iterations.
`./6Route -i 2 -s 2408:400a:e:8b00:363:45cc:b494:dfc -m 00:16:3e:3a:aa:85 -g ee:ff:ff:ff:ff:ff -a address_path -b 5000000 -max-wildcard 4 -min-cluster 50 -r 10000 -c 20`
