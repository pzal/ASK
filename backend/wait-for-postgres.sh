#!/bin/sh
# wait-for-postgres.sh

set -e

cmd="$@"
i=10

until PGPASSWORD=$POSTGRES_DB_PASSWORD psql -h $POSTGRES_HOST -U $POSTGRES_DB_USER -c '\q'; do
  >&2 echo "Postgres is unavailable - sleeping"
  i=`expr $i + 1`
  sleep 1

  if [ $i -gt 15 ]; then
   break
  fi
done

>&2 echo "Postgres is up - executing command"
echo $cmd
exec $cmd
