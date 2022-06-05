#!/bin/bash
sudo killall srsue
wait $!
sudo killall srsenb
wait $!
sudo killall srsepc
wait $!
