#!/bin/bash

set -x

sudo apt-get install libgmp-dev

if [ x${PYTHON_INTP} = "x" ]; then
	echo "Undefined python implementation"
	exit 1
fi

if [ ${PYTHON_INTP} = "pypy" ]; then
	sudo add-apt-repository -y ppa:pypy/ppa
	sudo apt-get -y update
	sudo apt-get install -y --force-yes pypy pypy-dev
elif [ x$(which ${PYTHON_INTP}) = "x" ]; then
	sudo add-apt-repository -y ppa:fkrull/deadsnakes
	sudo apt-get -y update
	sudo apt-get install ${PYTHON_INTP} ${PYTHON_INTP}-dev
fi

${PYTHON_INTP} -V

PYV=$(${PYTHON_INTP} -V 2>&1 | head -1 | sed -n 's/\w\+ \([23]\)\.\([0-9]\).*/\1\2/p')

if [ ${PYV} -ge 26 ]; then
	sudo pip install virtualenv
else
	sudo apt-get install python-virtualenv
fi

virtualenv -p ${PYTHON_INTP} .
. bin/activate

if [ ${PYV} -eq 24 ]; then
	(
	cd /tmp
	git clone https://github.com/Legrandin/ctypes
	cd ctypes
	${PYTHON_INTP} setup.py install
	)
fi

if [ x${CFFI} = "xyes" -a ${PYTHON_INTP} != "pypy" ]; then
	pip install cffi
fi

# List all installed packages
pip freeze
