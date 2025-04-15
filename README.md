# 6Route
6Route is an efficient IPv6 topology discovery framework based on prefix prediction. Through traceroute, 6Route can discovers router interfaces and the links between them. 6Route consists of two modules, with the target generation module written in Python and the traceroute module written in Go.
## Build
go build
## Usage
### Target Generation

<<<<<<< HEAD
python target_gene.py --address_file address.txt --prefix_file prefix.txt --budget 10000000
### Traceroute

./6Route --address_file address.txt -s source_address -m source_mac -r 10000 
=======
`python target_gene.py --address_file address.txt --prefix_file prefix.txt --budget 10000000`
### Traceroute

`./6Route --address_file address.txt -s source_address -m source_mac -r 10000`
>>>>>>> c42a55ed97716a7d0d5ff6ee037896c7940f313f
