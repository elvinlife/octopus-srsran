#!/bin/bash
./clean_testbed.sh
sleep 10
sudo ip netns delete ue1
sudo ip netns add ue1
#export SRSRAN_MACPDU_TRACE="$HOME/Research/Octopus-srsRAN/config/att-srsran-pdu.trace"
#export SRSRAN_MACPDU_TRACE=$1
sudo ../build/srsepc/src/srsepc --hss.db_file=../config/user_db.csv ../config/epc.conf &
sleep 1
sudo -E ../build/srsenb/src/srsenb \
  --enb_files.sib_config=../config/sib.conf \
  --enb_files.rr_config=../config/rr.conf \
  --enb_files.drb_config=../config/drb.conf \
  ../config/enb.conf &> /dev/null &
sleep 1
sudo ../build/srsue/src/srsue --gw.netns=ue1 ../config/ue.conf &> /dev/null &
