# ACSAC 2017

Tools used for data processing for ACSAC 2017.

The scripts are usually directly runnable from the command line. Try invoking with `--help` option for more info.

* `censys_eco_*` scripts are related to the HTTPS Ecosystem dataset processing.
* `censys_sonarssl_*` scripts are related to the SonarSSL dataset processing.
* `censys_*` others than above are general tools related to Censys TLS scans data processing.
* `pgp_*` scripts are related to the PGP dataset processing. The main processing script is `pgp_classif.py`.

For Censys scripts you need an user account to get the data. Then you need to parse the HTML page to the JSON file
that is input to the further processing scripts (process/recode).

Some recoding scripts may need large amount of RAM (e.g., eco recode needs 80 GB RAM).

# Experiments with PBSPro

## Generate TLS fetch jobs

```
export DATADIR="/storage/praha1/home/$LOGNAME/results"
mkdir -p $DATADIR

export HOMEDIR="/storage/praha1/home/$LOGNAME"
cd $HOMEDIR

export PYENV_ROOT="$HOMEDIR/.pyenv"
export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init -)"
pyenv local 2.7.13

mkdir -p jobs
cd jobs

python cas/codesign/censys_gen_jobs.py \
    --home=$HOMEDIR \
    --wrapper ${HOMEDIR}/cas/censys_tls_wrapper.sh \
    --data=$DATADIR \
    --jobs-dir=jobs \
    ${HOMEDIR}/cas/tls_ipv4_history.json

# or
python ../cas/codesign/censys_gen_jobs.py \
    --data /storage/brno3-cerit/home/ph4r05/fulltls \
    --wrapper /storage/praha1/home/ph4r05/cas/censys_tls_wrapper.sh \
    --home  /storage/praha1/home/ph4r05/cas \
    /storage/praha1/home/ph4r05/cas/tls_ipv4_history.json
```

## Interactive job

E.g., for debugging the script / env prepare. Frontends are quite slow.

```
qsub -l select=1:ncpus=1:mem=1gb:scratch_local=1gb -l walltime=48:00:00 -I
```

## Requesting specific node

```
qsub -l select=1:ncpus=1:mem=1gb:scratch_local=1gb:vnode=tarkil3 -l walltime=48:00:00 -I
```

## Requesting specific cluster

```
qsub -l select=1:ncpus=1:mem=1gb:scratch_local=1gb:cl_tarkil=True -l walltime=48:00:00 -I
```

## Canceling jobs

```
qdel 1085540
```

## Inspect Censys data

```
curl -s https://scans.io/zsearch/data.json.lz4 2>&1 | lz4cat | head -n 1
```

For that you may need to install lz4:

```
sudo apt-get install liblz4-tool
```

## MySQL to SQLite

 - One may use export scripts, but this is a bit slower
 - Faster solution: mysqldump + sqlite import.

In the latter the schea is created by the export script.
Note the modified `mysql2sqlite` script from this repo is needed for import of hex coded blobs.

```
mysqldump --skip-extended-insert --compact --hex-blob -u codesign -p codesign \
    --tables maven_artifact maven_signature pgp_key > maven_dump.sql

./mysql2sqlite maven_dump.sql | sqlite3 maven.sqlite
```


## MySQL port forwarding

Forwarding MySQL port from one machine to another via SSH tunnel.

Please note that SSH tunnel forwarding does not allow port binding on the 0.0.0.0 / 0:: by default.

There are 2 ways to do the port binding.

 * Connecting from *Meta* to *DB server*, using local tunneling. Client is in charge. Can open as many tunnels as desired.
 * Connection from *DB server* to *Meta*, using remote tunelling. Server creates a single connection on some server hub.
 Binding on the local interface only can be mitigated by using `socat`.

### Client to DB

 * Create a new ssh key on the *Meta*, this key will be allowed to do only the port forward on the *DB server*
 * DB server `autorized_keys` record:

```
command="echo 'This account can only be used for port forward'",no-agent-forwarding,no-X11-forwarding,permitopen="localhost:3306" ssh-rsa AAAAB3NzaC1y....
```

 * Create a tunnel on the *Meta*. Ideally do that in the `screen`:

```
ssh -nNT -L 60123:localhost:3306 klivm &
```

 * Socat hack, forwarding local bound 60123 port to the global bound 60124. Ideally do that in the `screen`:
    * Socat can be found here: http://www.dest-unreach.org/socat/download/socat-1.7.3.2.tar.gz

```
socat tcp-listen:60124,reuseaddr,fork tcp:localhost:60123 &
```

 * Use 60124 port for MySQL connection

 * Alternatively you can use another SSH from worker node on *Meta* to the frontend node (benefit: encrypted connection
 from worker node to the frontend).

```
ssh -nNT -L 60125:localhost:60123 tarkil &
```

## Math modules - installation

```
#
# MPFR module load, or manual installation: http://www.mpfr.org/
#
module add mpfr-3.1.4
export CWD=$HOME

#
# install GMP https://gmplib.org/
#
wget https://gmplib.org/download/gmp/gmp-6.1.2.tar.bz2
tar -xjvf gmp-6.1.2.tar.bz2
cd gmp-6.1.2
./configure --prefix=$CWD
make && make install
cd $CWD

#
# install MPC http://www.multiprecision.org/index.php?prog=mpc&page=download
#
wget ftp://ftp.gnu.org/gnu/mpc/mpc-1.0.3.tar.gz
tar -xzvf mpc-1.0.3.tar.gz
cd mpc-1.0.3
./configure --prefix=$CWD
make && make install
cd $CWD

#
# Install gmpy2
#
env CFLAGS="-I${CWD}/include" LDFLAGS="-L${CWD}/lib" --global-option=build_ext --global-option="-I${CWD}/include" pip install gmpy2
```

# MPI

Message passing interface enables effective parallel computation

Request nodes:

```
qsub -l select=4:ncpus=1:mem=1gb:scratch_local=1gb -l walltime=1:00:00 -l place=scatter mpi-script.sh
```

The script can contain something like this:

```
mpirun -machinefile $PBS_NODEFILE python script.py
```

The `mpirun` executable will execute the script on each node in the machine file. Examples:
https://github.com/jbornschein/mpi4py-examples

## Metacentrum docs

* https://wiki.metacentrum.cz/wiki/How_to_install_an_application#Python_packages
* https://wiki.metacentrum.cz/wiki/How_to_compute/Interactive_jobs
* https://wiki.metacentrum.cz/wiki/How_to_compute
* https://wiki.metacentrum.cz/wiki/Working_with_data/Working_with_data_in_a_job
* https://wiki.metacentrum.cz/wiki/Frontend
* https://wiki.metacentrum.cz/wiki/How_to_compute/Quick_start
* https://wiki.metacentrum.cz/wiki/PBS_Professional
* https://metavo.metacentrum.cz/pbsmon2/user/user-here

# Installation

## Local install

```
pip install --upgrade --find-links=. .
```

## Dependencies

```
pip install MySql-Python
pip install SQLAlchemy
```

Ubuntu:
```
sudo apt-get install python-pip python-dev libmysqlclient-dev
sudo apt-get install libsasl2-dev python-dev libldap2-dev libssl-dev libsqlite3-dev libreadline-dev lbzip2
```

CentOS:
```
sudo yum install gcc gcc-c++ make automake autoreconf libtool
sudo yum install python python-devel mysql-devel redhat-rpm-config libxml2 libxml2-devel libxslt libxslt-devel openssl-devel sqlite-devel libpng-devel
sudo yum install python-devel openldap-devel
```

## Scipy installation with pip

```
pip install pyopenssl
pip install pycrypto
pip install git+https://github.com/scipy/scipy.git
pip install --upgrade --find-links=. .
```

## Virtual environment

It is usually recommended to create a new python virtual environment for the project:

```
virtualenv ~/pyenv
source ~/pyenv/bin/activate
pip install --upgrade pip
pip install --upgrade --find-links=. .
```

## Aura / Aisa on FI MU

```
module add cmake-3.6.2
module add gcc-4.8.2
```

## Python 2.7.13 / 3.6.2

It won't work with lower Python version. Use `pyenv` to install a new Python version.
It internally downloads Python sources and installs it to `~/.pyenv`.

```
git clone https://github.com/pyenv/pyenv.git ~/.pyenv
echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
echo 'export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(pyenv init -)"' >> ~/.bashrc
exec $SHELL
pyenv install 2.7.13
pyenv install 3.6.2
pyenv local 2.7.13
```

## Pip package fix

```
pip install -U pip setuptools twine
python setup.py sdist
twine upload dist/*
```


