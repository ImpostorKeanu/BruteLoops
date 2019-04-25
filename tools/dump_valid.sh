#!/bin/bash

db=$1

if [ "$db" = '' ]; then
    echo "Pass an SQLITE database argument to the script"
    exit
fi

for record in $(sqlite3 $db "select usernames.value,passwords.value from usernames JOIN passwords ON usernames.last_password_id = passwords.id WHERE usernames.recovered = 1 AND usernames.last_password_id = passwords.id;"); do
    echo $(echo $record | sed -r -e 's/\|/:/')
done
