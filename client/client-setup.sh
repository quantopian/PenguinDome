#!/bin/bash -e

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

# We need to start with a shell script so that we can set up the virtualenv
# before calling Python code.

venv=var/client-venv

cd "$(dirname $0)/.."

mkdir -p var

. /etc/os-release

if [ "$ID_LIKE" = "debian" ]; then
    # Ubuntu setup will probably work on Debian, though not tested.
    apt-get -qq install $(sed 's/#.*//' client/ubuntu-packages.txt)
elif [ "$ID_LIKE" = "archlinux" ]; then
    if ! pacman -S --needed --noconfirm $(sed -e 's/#.*//' -e '/\.git$/d' \
      client/arch-packages.txt) >| var/pacman.log 2>&1; then
	echo "pacman -S failed:" 1>&2
        cat var/pacman.log 1>&2
	exit 1
    fi
fi

if [ ! -d $venv ]; then
    virtualenv -p python3 $venv
fi

for dir in $(find $venv -name site-packages); do
    echo $(pwd) > $dir/qlmdm.pth
done

. $venv/bin/activate

pip install -q --upgrade pip
pip install -q -r client/requirements.txt -c client/constraints.txt

mkdir -p bin
for file in client/*.py; do
    tail=${file##*/}
    if [ $tail = "initialize.py" ]; then
        continue
    fi
    target=bin/${tail%.py}
    rm -f $target
    cat >>$target <<EOF
#!/bin/bash
. $(pwd)/$venv/bin/activate
exec python $(pwd)/$file "\$@"
EOF
    chmod +x $target
done

exec python client/initialize.py "$@"

