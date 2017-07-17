#!/bin/bash -e

# We need to start with a shell script so that we can set up the virtualenv
# before calling Python code.

venv=var/server-venv

cd "$(dirname $0)/.."

. /etc/lsb-release
if [ "$DISTRIB_ID" = "Ubuntu" ]; then
    apt-get -qq install $(sed 's/#.*//' server/ubuntu-packages.txt)
fi

mkdir -p var
if [ ! -d $venv ]; then
    virtualenv -p python3 $venv
fi

for dir in $(find $venv -name site-packages); do
    echo $(pwd) > $dir/qlmdm.pth
done

. $venv/bin/activate

pip install -q --upgrade pip
pip install -q -r server/requirements.txt -c server/constraints.txt

mkdir -p bin
for file in server/*.py; do
    tail=${file##*/}
    if [ $tail = "initialize.py" ]; then
        continue
    fi
    target=bin/${tail%.py}
    rm -f $target
    cat >>$target <<EOF
#!/bin/bash -e
. $(pwd)/$venv/bin/activate
exec python $(pwd)/$file "\$@"
EOF
    chmod +x $target
done

exec python server/initialize.py

    
