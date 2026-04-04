upstream contrastapi {
    server 127.0.0.1:8002;
    keepalive 16;
}

proxy_cache_path /var/cache/nginx/contrastapi levels=1:2 keys_zone=api_cache:10m max_size=200m inactive=10m;

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name api.contrastcyber.com;

    ssl_certificate /etc/letsencrypt/live/api.contrastcyber.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.contrastcyber.com/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

    include /etc/nginx/snippets/security-headers-api.conf;
    include /etc/nginx/snippets/block-exploits.conf;

    # MCP Streamable HTTP — JSON responses, no buffering/cache
    location /mcp {
        limit_req zone=api burst=20 nodelay;
        limit_req_status 429;
        client_max_body_size 1m;
        proxy_pass http://contrastapi;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 90s;
        proxy_send_timeout 90s;
        proxy_connect_timeout 10s;
    }

    # Static files — long cache
    location /static/ {
        proxy_pass http://contrastapi;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header Connection "";
        proxy_cache api_cache;
        proxy_cache_valid 200 1h;
        expires 1h;
    }

    # CVE lookup — cache 5 min (data changes every 2h sync)
    location /v1/cve/ {
        limit_req zone=api burst=10 nodelay;
        limit_req_status 429;
        proxy_pass http://contrastapi;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";
        proxy_cache api_cache;
        proxy_cache_valid 200 5m;
        proxy_read_timeout 30s;
    }

    # POST endpoints (CodeSec) — no cache, higher body size
    location /v1/check/ {
        limit_req zone=api burst=10 nodelay;
        limit_req_status 429;
        client_max_body_size 1m;
        proxy_pass http://contrastapi;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";
        proxy_read_timeout 30s;
    }

    # All other endpoints
    location / {
        limit_req zone=api burst=20 nodelay;
        limit_req_status 429;
        proxy_pass http://contrastapi;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";
        proxy_read_timeout 30s;
    }
}

server {
    listen 80;
    listen [::]:80;
    server_name api.contrastcyber.com;
    return 301 https://$host$request_uri;
}
