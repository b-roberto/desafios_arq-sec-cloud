output "alb_dns_name" {
  value = aws_lb.public.dns_name
}

output "bastion_public_ip" {
  value = aws_instance.bastion.public_ip
}

output "ssh_private_key_pem_bastion" {
  description = "Chave privada PEM do bastion (salve em arquivo e chmod 600). NÃO commitar."
  value       = tls_private_key.bastion.private_key_pem
  sensitive   = true
}

output "s3_backup_bucket" {
  value = aws_s3_bucket.backup.bucket
}

output "rds_endpoint" {
  value = aws_db_instance.mysql.address
}

output "db_secret_arn" {
  value = aws_secretsmanager_secret.db.arn
}
