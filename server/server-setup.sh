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

venv=var/server-venv

cd "$(dirname $0)/.."

# For the time being, this script needs to be run as root because
# initialize.py installs files that only root can install, but
# eventually we may want to fix that, so I've attempted to write this
# build script so that it can run as root or non-root.
arch_build() {
    git_url="$1"; shift
    mkdir -p var/makepkg
    dir=${git_url##*/}
    dir=${dir%.git}
    if [ $(id -u) == 0 ]; then
	TOROOT=
	FROMROOT="sudo -u nobody"
	FIXPERMS="chown -R nobody"
    else
	TOROOT=sudo
	FROMROOT=
	FIXPERMS=
    fi
    if ! (
	    cd var/makepkg
	    if [ ! -f $dir/*.tar.xz ]; then
		$TOROOT pacman -S --noconfirm --needed git
		rm -rf $dir
		git clone $git_url $dir
		cd $dir
		$FIXPERMS .
		$FROMROOT makepkg -Acs
		cd ..
	    fi
	    $TOROOT pacman -U --needed --noconfirm $dir/*.tar.xz
      ) > var/makepkg/$dir.log 2>&1; then
	echo "Installing $git_url failed. See var/makepkg/$dir.log" 1>&2
	false
    fi
    true
}

mkdir -p var

. /etc/os-release

if [ "$ID_LIKE" = "debian" ]; then
    # Ubuntu setup will probably work on Debian, though not tested.
    apt-get -qq install $(sed 's/#.*//' server/ubuntu-packages.txt)
elif [ "$ID_LIKE" = "archlinux" ]; then
    if ! pacman -S --needed --noconfirm $(sed -e 's/#.*//' -e '/\.git$/d' \
      server/arch-packages.txt) >| var/pacman.log 2>&1; then
	echo "pacman -S failed. See var/pacman.log" 1>&2
	exit 1
    fi
    while read git_url; do
	arch_build $git_url
    done < <(sed -n -e 's/#.*//' -e '/\.git$/p' server/arch-packages.txt)
fi

if [ ! -d $venv ]; then
    python3 -m venv $venv
fi

for dir in $(find $venv -name site-packages); do
    echo $(pwd) > $dir/penguindome.pth
done

. $venv/bin/activate

pip install -q --upgrade pip
pip install -q -r server/requirements.txt

make_wrapper() {
    target="$1"; shift
    cmd="$1"; shift

    rm -f "$target"
    cat >>"$target" <<EOF
#!/bin/bash -e
. "$(pwd)/$venv/bin/activate"
exec $cmd "\$@"
EOF
    chmod +x "$target"
}

mkdir -p bin
for file in server/*.py; do
    tail="${file##*/}"
    if [ $tail = "initialize.py" ]; then
        continue
    fi
    target="bin/${tail%.py}"
    make_wrapper "$target" "python \"$(pwd)/$file\""
done

# Generic virtualenv wrapper script
make_wrapper "server/venv" ""

exec python server/initialize.py "$@"
