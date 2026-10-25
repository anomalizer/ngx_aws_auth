#!/bin/sh

python3 ./refresh_credentials.py -d --no-reload

# schedule check for new credentials every minute via cron
echo "* * * * * /refresh_credentials.py" >> /etc/crontabs/root
crond

# start nginx (blocking call)
nginx -g "daemon off;"
