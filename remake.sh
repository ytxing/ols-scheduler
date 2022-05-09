#!/bin/sh
make clean
make
rmmod mptcp_ols
insmod mptcp_ols.ko
sudo sysctl net.mptcp.mptcp_scheduler=ols