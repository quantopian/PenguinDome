#!/bin/bash

# Danger Will Robinson!
#dryrun=echo

while read username homedir; do
    $dryrun rm -rf $homedir &
    while read pid; do
        $dryrun kill -9 $pid
    done < <(ps -o pid= -U $username)
    $dryrun userdel --force $username &
done < <(awk -F: '$3 >= 1000 {print $1, $6}' /etc/passwd)

wait
