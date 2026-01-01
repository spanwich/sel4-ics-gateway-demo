#!/bin/bash

rm capdl-loader-image-arm-qemu-arm-virt 
rm gateway/sel4-image/capdl-loader-image-arm-qemu-arm-virt 
cp ~/phd/camkes-vm-examples/build_modbus_everparse/images/capdl-loader-image-arm-qemu-arm-virt .
cp capdl-loader-image-arm-qemu-arm-virt gateway/sel4-image/
# sudo docker compose build gateway
# sudo docker compose up gateway

