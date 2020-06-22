#!/bin/bash
m=ef56gh678990
edpsk=jhfjftjfgdkyusgcilagsdiulgchilusdcgilusgvkjh
echo ${m} User-Password:=${m}$'\n\t'Ruckus-Dpsk=0x00${edpsk} >> data.txt
#ef56gh678990 User-Password:=ef56gh678990

sed -i "/${m} User-Password:=/,+2d" data.txt
#sed -i -e '$d' data.txt

