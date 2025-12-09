#!/bin/bash

Red="\e[31m"
Yellow="\e[33m"
Green="\e[32m"
RCol="\e[0m"

DISTRO=$(grep -oP '(?<=^NAME=).+' /etc/os-release | tr -d '"')
PASS=true

# Ubuntu
if [[ $DISTRO == "Ubuntu"* ]]; then
        declare -a NEEDED_SOFTWARE_LIST=(lshw libicu dmidecode bc)

        for SOFTWARE in ${NEEDED_SOFTWARE_LIST[@]}; do
                dpkg -l | grep -i $SOFTWARE | head -1 | if [[ "$(cut -d ' ' -f 1)" != "ii" ]]; then
                        echo -e "[ ${Red}FAILED${RCol} ]\t$SOFTWARE is NOT installed completely! Please install it...";
                        PASS=false
                fi
        done
# RedHat / CentOS / Oracle / Amazon
elif [[ $DISTRO == "Red Hat Enterprise Linux"* ]] || [[ $DISTRO == "RedHawk Linux"* ]] || [[ $DISTRO == "CentOS Linux"* ]] || [[ $DISTRO == "Oracle Linux"* ]] || [[ $DISTRO == "Amazon Linux"* ]]; then
        declare -a NEEDED_SOFTWARE_LIST=(lshw libicu dmidecode bc)

        for SOFTWARE in ${NEEDED_SOFTWARE_LIST[@]}; do
                if [[ "$(rpm -q $SOFTWARE)" == "package $SOFTWARE is not installed" ]]; then
                        echo -e "[ ${Red}FAILED${RCol} ]\t$SOFTWARE is NOT installed completely! Please install it...";
                        PASS=false
                fi
        done

        if [[ "$(rpm -qa fapolicyd)" ]]; then
                echo -e "[ ${Yellow}ALERT${RCol} ]\tfapolicyd is installed! Please ensure PowerShell is whitelisted...";
        fi
else
        echo -e "[ ${Red}FAILED${RCol} ]\tYour system is currently not supported by this script.";
        exit 1;
fi

if [[ $PASS == 'true' ]]; then
        echo -e "[ ${Green}PASSED${RCol} ]\tPrerequisites passed.";
fi