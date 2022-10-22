#!/bin/bash

printf "Running isort\n"
isort . -v || printf "isort has not been detected\nIt can be installed with \"pip install isort\"\n"
printf "\nRunning black\n"
black . -v || printf "black has not been detected\nIt can be installed with \"pip install black\"\n"
