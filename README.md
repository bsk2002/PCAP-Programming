# TCP Packet Sniffer (PCAP 기반 구현)

## 개요
C 언어와 libpcap을 이용해 Ethernet/IP/TCP 헤더 정보를 출력하고, TCP의 일부 메시지를 출력합니다. (UDP 패킷은 무시)
<img width="841" alt="image" src="https://github.com/user-attachments/assets/6dd906ab-0d58-406a-835d-75a0ff188d50" />

## 실행 방법
```bash
gcc -o tcp_sniffer modified_sniff_improved.c -lpcap
sudo ./tcp_sniffer
