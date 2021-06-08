#!/bin/bash

# Quantopian, Inc. licenses this file to you under the Apache License, Version
# 2.0 (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
# 
#   http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

# Danger Will Robinson!
#dryrun=echo

while read username homedir; do
    while read pid; do
        $dryrun kill -9 $pid
    $dryrun shred -f $homedir &
    done < <(ps -o pid= -U $username)
    $dryrun userdel --force $username &
done < <(awk -F: '$3 >= 1000 {print $1, $6}' /etc/passwd)

wait
