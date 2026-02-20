# Desafio 02 – IaC (Terraform)

## Pré-requisitos
- AWS CLI configurado (`aws configure`)
- Terraform >= 1.6
- Região padrão: `us-east-1`

## Deploy
```bash
terraform init
terraform fmt -recursive
terraform validate
terraform apply -var="my_ip_cidr=SEU_IP/32"
```

## Chave do Bastion
```bash
terraform output -raw ssh_private_key_pem_bastion > bastion_key.pem
chmod 600 bastion_key.pem
```

## Acesso (Bastion)
```bash
ssh -i bastion_key.pem ubuntu@<BASTION_PUBLIC_IP>
```

## Teste do Web
```bash
curl -s http://<ALB_DNS_NAME>/
```

## Backup
O ASG instala e agenda:
- `/usr/local/bin/backup_web_configs.sh` (cron horário por padrão)

Para executar manualmente (em uma instância web):
```bash
sudo /usr/local/bin/backup_web_configs.sh
```

## Destroy
```bash
terraform destroy -var="my_ip_cidr=SEU_IP/32"
```


## TLS obrigatório no MySQL
Este projeto aplica um **DB Parameter Group** (`require_secure_transport=ON`) para exigir conexão MySQL via TLS.
