#!/bin/bash

TOGGLE=$HOME/.toggle

if [ ! -e $TOGGLE ]; then
    touch $TOGGLE
    nvidia-settings -a DigitalVibrance=1000
else
    rm $TOGGLE
    nvidia-settings -a DigitalVibrance=100
fi
