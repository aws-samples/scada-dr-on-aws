#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
echo '====== Starting postgres replication script ======'>> /var/log/cloud-init-output.log

sudo yum install telnet -y

counter=0
while ([[ -z "$ONPREM_PASS" ]] || [ "null" = "$ONPREM_PASS" ]) && [ $counter -lt 1000 ]; do ONPREM_PASS=$(aws secretsmanager get-secret-value --region $2 --secret-id 'onPremDBCredentials' --output text --query 'SecretString' | jq -r '.password'); echo $counter >> /var/log/cloud-init-output.log; sleep 1;((counter++)); done
counter=0
while ([[ -z "$ONPREM_PORT" ]] || [ "null" = "$ONPREM_PORT" ]) && [ $counter -lt 1000 ]; do ONPREM_PORT=$(aws secretsmanager get-secret-value --region $2 --secret-id 'onPremDBCredentials' --output text --query 'SecretString' | jq -r '.port'); echo $counter >> /var/log/cloud-init-output.log; sleep 1;((counter++)); done
counter=0
while ([[ -z "$ONPREM_HOST" ]] || [ "null" = "$ONPREM_HOST" ]) && [ $counter -lt 1000 ]; do ONPREM_HOST=$(aws secretsmanager get-secret-value --region $2 --secret-id 'onPremDBCredentials' --output text --query 'SecretString' | jq -r '.host'); echo $counter >> /var/log/cloud-init-output.log; sleep 1;((counter++)); done
counter=0
while ([[ -z "$ONPREM_USER" ]] || [ "null" = "$ONPREM_USER" ]) && [ $counter -lt 1000 ]; do ONPREM_USER=$(aws secretsmanager get-secret-value --region $2 --secret-id 'onPremDBCredentials' --output text --query 'SecretString' | jq -r '.username'); echo $counter >> /var/log/cloud-init-output.log; sleep 1;((counter++)); done
counter=0
while ([[ -z "$ONCLOUD_PASS" ]] || [ "null" = "$ONCLOUD_PASS" ]) && [ $counter -lt 1000 ]; do ONCLOUD_PASS=$(aws secretsmanager get-secret-value --region $3 --secret-id 'onCloudDBCredentials' --output text --query 'SecretString' | jq -r '.password'); echo $counter >> /var/log/cloud-init-output.log; sleep 1;((counter++)); done
counter=0
while  ([[ -z "$ONCLOUD_PORT" ]] || [ "null" = "$ONCLOUD_PORT" ]) && [ $counter -lt 1000 ]; do ONCLOUD_PORT=$(aws secretsmanager get-secret-value --region $3 --secret-id 'onCloudDBCredentials' --output text --query 'SecretString' | jq -r '.port'); echo $counter >> /var/log/cloud-init-output.log; sleep 1;((counter++)); done
counter=0
while  ([[ -z "$ONCLOUD_HOST" ]] || [ "null" = "$ONCLOUD_HOST" ]) && [ $counter -lt 1000 ]; do ONCLOUD_HOST=$(aws secretsmanager get-secret-value --region $3 --secret-id 'onCloudDBCredentials' --output text --query 'SecretString' | jq -r '.host'); echo $counter >> /var/log/cloud-init-output.log; sleep 1;((counter++)); done
counter=0
while  ([[ -z "$ONCLOUD_USER" ]] || [ "null" = "$ONCLOUD_USER" ]) && [ $counter -lt 1000 ]; do ONCLOUD_USER=$(aws secretsmanager get-secret-value --region $3 --secret-id 'onCloudDBCredentials' --output text --query 'SecretString' | jq -r '.username'); echo $counter >> /var/log/cloud-init-output.log; sleep 1;((counter++)); done

export PGDATABASE='postgres'
export PGPASSFILE='/root/.pgpass'
touch $PGPASSFILE

if [ $1 == "onprem" ]
then

    sudo yum update -y

    # Install the needed packages to build the client libraries from source
    sudo yum install -y gcc readline-devel libicu-devel zlib-devel openssl-devel
    
    sudo chmod +x ./postgresql-16.1.tar.gz
    tar -xvzf ./postgresql-16.1.tar.gz

    cd ./postgresql-16.1

    # Set bin dir so that executables are put in /usr/bin where psql and the others are installed by RPM
    ./configure --bindir=/usr/bin --with-openssl

    sudo make -C src/bin install
    sudo make -C src/include install
    sudo make -C src/interfaces install

    echo "$ONPREM_HOST:$ONPREM_PORT:$PGDATABASE:$ONPREM_USER:$ONPREM_PASS" > $PGPASSFILE
    chmod 600 $PGPASSFILE
    export PGHOST=$ONPREM_HOST
    export PGPORT=$ONPREM_PORT
    export PGUSER=$ONPREM_USER

    (crontab -l ; echo "* * * * * su root -c '/postgres_replication.sh replica $2 $3'") | crontab -
    pg_dump --schema-only postgres > /tmp/db_old.sql
    psql -c "CREATE PUBLICATION allpubonprem FOR ALL TABLES;"
fi
if [ $1 == "cloud" ]
then

    sudo yum update -y

    # Install the needed packages to build the client libraries from source
    sudo yum install -y gcc readline-devel libicu-devel zlib-devel openssl-devel
    
    sudo chmod +x ./postgresql-16.1.tar.gz
    tar -xvzf ./postgresql-16.1.tar.gz

    cd ./postgresql-16.1

    # Set bin dir so that executables are put in /usr/bin where psql and the others are installed by RPM
    ./configure --bindir=/usr/bin --with-openssl

    sudo make -C src/bin install
    sudo make -C src/include install
    sudo make -C src/interfaces install

    echo "$ONCLOUD_HOST:$ONCLOUD_PORT:$PGDATABASE:$ONCLOUD_USER:$ONCLOUD_PASS" > $PGPASSFILE
    chmod 600 $PGPASSFILE
    export PGHOST=$ONCLOUD_HOST
    export PGPORT=$ONCLOUD_PORT
    export PGUSER=$ONCLOUD_USER

    TELNET_EXIT_CODE=0
    while [[ $TELNET_EXIT_CODE -eq 0 ]]; do
        (echo ^]; echo quit) | timeout --signal=9 5 telnet $ONPREM_HOST $ONPREM_PORT > /dev/null 2>&1
        TELNET_EXIT_CODE=$?
        echo "waiting for the database to become online: "$TELNET_EXIT_CODE >> /var/log/cloud-init-output.log
    done;

    psql -c "CREATE SUBSCRIPTION allsubcloud CONNECTION 'host=$ONPREM_HOST port=$ONPREM_PORT user=$ONPREM_USER password=$ONPREM_PASS dbname=$PGDATABASE' PUBLICATION allpubonprem WITH (origin = any, copy_data = true);"
fi
if [ $1 == "replica" ]
then
    echo "$ONPREM_HOST:$ONPREM_PORT:$PGDATABASE:$ONPREM_USER:$ONPREM_PASS" > $PGPASSFILE
    chmod 600 $PGPASSFILE
    export PGHOST=$ONPREM_HOST
    export PGPORT=$ONPREM_PORT
    export PGUSER=$ONPREM_USER
    pg_dump --schema-only postgres > /tmp/db.sql
    delta=$(diff -q /tmp/db.sql /tmp/db_old.sql)
    if [ -z "$delta" ]
    then
        echo "No changes detected" >> /var/log/cloud-init-output.log
    else
        echo "$ONCLOUD_HOST:$ONCLOUD_PORT:$PGDATABASE:$ONCLOUD_USER:$ONCLOUD_PASS" > $PGPASSFILE
        chmod 600 $PGPASSFILE
        export PGHOST=$ONCLOUD_HOST
        export PGPORT=$ONCLOUD_PORT
        export PGUSER=$ONCLOUD_USER
        psql $PGDATABASE < /tmp/db.sql
        psql -c "DROP SUBSCRIPTION allsubcloud;"
        psql -c "CREATE SUBSCRIPTION allsubcloud CONNECTION 'host=$ONPREM_HOST port=$ONPREM_PORT user=$ONPREM_USER password=$ONPREM_PASS dbname=$PGDATABASE' PUBLICATION allpubonprem WITH (origin = any, copy_data = true);"
    fi
fi