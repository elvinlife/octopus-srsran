#!/bin/bash
sudo ip netns exec ue1 iperf -s &
sleep 5
iperf -c 172.16.0.2 -t 30
