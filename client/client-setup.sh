#!/bin/bash -e

# We need to start with a shell script so that we can set up the virtualenv
# before calling Python code.

venv=var/client-venv

cd "$(dirname $0)/.."

mkdir -p var
if [ ! -d $venv ]; then
    virtualenv $venv
fi

for dir in $(find $venv -name site-packages); do
    echo $(pwd) > $dir/qlmdm.pth
done

. $venv/bin/activate

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

exec python client/initialize.py
