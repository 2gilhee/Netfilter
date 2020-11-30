# netfilter - basic

- libnetfilter-queue-dev is required 
- To compile you have to link **netfilter_queue** with cpp file (e.g., `g++ -o main2 main2.cpp -lnetfilter_queue`)
- To intecept incoming packets you can set ipables as NFQUEUE (e.g., ` iptables -A INPUT -j NFQUEUE`)
- To intecept incoming packets you can set ipables as NFQUEUE (e.g., ` iptables -A OUTPUT -j NFQUEUE`)
- To reset iptables, you can do ` iptables -F` 
