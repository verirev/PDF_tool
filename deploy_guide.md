
#### pdftool.service
Location: `/etc/systemd/system/pdftool.service`

```
[Unit]
Description=Gunicorn instance to serve pdf tool
After=network.target

[Service]
User=root
Group=www-data
WorkingDirectory=/var/www/pdftool
Environment="PATH=/var/www/pdftool/env/bin"
ExecStart=/var/www/pdftool/env/bin/gunicorn --log-file /var/log/pdftool_guni.log --log-level DEBUG --workers 3 --bind unix:pdftool.sock -m 007 wsgi:app

[Install]
WantedBy=multi-user.target
```

#### pdftool.conf
`/etc/nginx/sites-available/pdftool.conf`
```
server {
    server_name YOUR_DOMAIN;
    error_log  /var/log/nginx/pdftool-error.log;
    access_log  /var/log/nginx/pdftool-access.log;
    client_max_body_size 64M;
    location / {
        include proxy_params;
        proxy_pass http://unix:/var/www/pdftool/pdftool.sock;
    }
}

```