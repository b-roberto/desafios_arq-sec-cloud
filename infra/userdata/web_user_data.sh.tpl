#!/usr/bin/env bash
set -euo pipefail

S3_BUCKET="${s3_bucket}"
AWS_REGION="${aws_region}"
KMS_KEY_ID="${kms_key_id}"
BACKUP_CRON="${backup_cron}"
CW_LOG_GROUP="${cw_log_group}"

log() { echo "[$(date -Is)] $*"; }

log "Updating packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y nginx unzip jq awscli auditd logrotate cron curl

log "Basic hardening..."
sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config || true
sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config || true
systemctl restart ssh || true

echo "umask 027" >> /etc/profile.d/99-umask.sh

systemctl enable auditd
systemctl start auditd

log "Configuring NGINX..."
cat >/etc/nginx/conf.d/hello.conf <<'EOF'
server {
  listen 80 default_server;
  server_name _;

  server_tokens off;

  add_header X-Frame-Options "DENY" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header Referrer-Policy "no-referrer" always;
  add_header X-XSS-Protection "1; mode=block" always;

  location / {
    return 200 "Hello World - Desafio 02\n";
  }
}
EOF

rm -f /etc/nginx/sites-enabled/default || true
nginx -t
systemctl enable nginx
systemctl restart nginx

log "Creating backup script..."
cat >/usr/local/bin/backup_web_configs.sh <<EOF
#!/usr/bin/env bash
set -euo pipefail
TS=\$(date -u +"%Y%m%dT%H%M%SZ")
HOST=\$(hostname)
ARCHIVE="/tmp/web-config-\$HOST-\$TS.tar.gz"

tar -czf "\$ARCHIVE" /etc/nginx /etc/ssh/sshd_config /etc/audit /etc/logrotate.conf /etc/logrotate.d

aws s3 cp "\$ARCHIVE" "s3://$S3_BUCKET/web-configs/\$HOST/" --region "$AWS_REGION" --sse aws:kms --sse-kms-key-id "$KMS_KEY_ID"

rm -f "\$ARCHIVE"
echo "Backup OK: \$HOST \$TS"
EOF
chmod +x /usr/local/bin/backup_web_configs.sh

log "Scheduling cron backup..."
systemctl enable cron
systemctl start cron
CRON_LINE="$BACKUP_CRON root /usr/local/bin/backup_web_configs.sh >> /var/log/backup_web_configs.log 2>&1"
grep -qF "/usr/local/bin/backup_web_configs.sh" /etc/crontab || echo "$CRON_LINE" >> /etc/crontab

log "Installing CloudWatch Agent..."
CW_DEB="/tmp/amazon-cloudwatch-agent.deb"
curl -fsSL "https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb" -o "$CW_DEB"
dpkg -i "$CW_DEB" || apt-get -f install -y

cat >/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json <<EOF
{
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          { "file_path": "/var/log/syslog", "log_group_name": "$CW_LOG_GROUP", "log_stream_name": "{instance_id}/syslog" },
          { "file_path": "/var/log/nginx/access.log", "log_group_name": "$CW_LOG_GROUP", "log_stream_name": "{instance_id}/nginx_access" },
          { "file_path": "/var/log/nginx/error.log", "log_group_name": "$CW_LOG_GROUP", "log_stream_name": "{instance_id}/nginx_error" },
          { "file_path": "/var/log/backup_web_configs.log", "log_group_name": "$CW_LOG_GROUP", "log_stream_name": "{instance_id}/backup" }
        ]
      }
    }
  }
}
EOF

/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a stop || true
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json -s

log "User-data complete."
