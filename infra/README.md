# Desafio 02 — Infra AWS com Terraform (Reprodutível + DevSecOps)

Este documento consolida toda a documentação do **Desafio 02**, cobrindo criação/remoção do ambiente, acesso, backup, decisões de segurança, premissas, reprodutibilidade e validação ponto a ponto (comandos).

---

## Conteúdo exigido pelo desafio (checklist)

Este documento contém:
- **Pré-requisitos**
- **Como criar e destruir o ambiente**
- **Como acessar (Bastion → Web)**
- **Como executar o backup**
- **Decisões de segurança**
- **Assunções (premissas adotadas)**
- **Instruções de reprodutibilidade (passo a passo claro)**
- **(Se implementado) arquivos de pipeline (Jenkinsfile ou .github/workflows/*.yml)**
- **Desejável – Pipelines de CI/CD (opcional)** com:
  - CI: `terraform fmt -check`, `terraform validate`, `terraform plan` em PR
  - Varreduras de segurança:
    - IaC: `tfsec`, `checkov`
    - Segredos: `gitleaks`, `trufflehog`
  - (Opcional) Pre-commit hooks
  - CD (opcional): `terraform apply` manual via gate (`workflow_dispatch`/aprovação)
  - Assume Role por OIDC (GitHub Actions) — evita chaves estáticas
  - Branch protegida, ambientes de aprovação

---

## Arquitetura (alto nível)

Recursos típicos criados:
- **VPC** + subnets **públicas** e **privadas**
- **ALB** (internet-facing) → **Target Group** → **Auto Scaling Group (Web)**
- **Bastion** (SSH) para administração
- **RDS MySQL** em subnets privadas (não público)
- **Secrets Manager** para segredo do DB
- **S3 bucket de backup** com:
  - Block Public Access
  - SSE-KMS (cripto em repouso)
  - Policy **DenyInsecureTransport** (HTTPS-only)
- **CloudWatch** (logs/alarms) conforme código
- (Opcional) **VPC Endpoints** (SSM/Logs/KMS/Secrets etc.), conforme implementado

---

## Pré-requisitos

### Ferramentas
- Terraform >= 1.4
- AWS CLI v2
- Git
- PowerShell (Windows) **ou** Bash (Linux/macOS)

### Conta e permissões AWS
Você precisa de credenciais válidas com permissão para criar recursos (VPC, EC2, ELB, ASG, RDS, S3, KMS, CloudWatch, IAM/SSM conforme usado).

Valide:
```bash
aws sts get-caller-identity
aws configure get region
```

> Região esperada: `us-east-1` (ou ajuste conforme variáveis do projeto).

---

## Instruções de reprodutibilidade 

Objetivo: Clonar o repo, executar, validar o ambiente e destruir.

### Passo 1 — Clonar e entrar na pasta de infra
```bash
git clone https://github.com/b-roberto/desafios_arq-sec-cloud
cd infra
```

### Passo 2 — Inicializar
```bash
terraform init
```

### Passo 3 — Aplicar (criar)
O Terraform vai pedir:
- `my_ip_cidr`: IP público em CIDR para liberar SSH no Bastion (ex.: `203.0.113.10/32`)

```bash
terraform apply
```

### Passo 4 — Validar (ponto a ponto)
Use a seção **Validação do ambiente** deste documento.

### Passo 5 — Exercitar requisitos
- Acessar Bastion → Web
- Executar backup
- Validar S3 encryption + policy HTTPS-only
- Validar RDS privado e disponível
- Validar ALB/Target Group/ASG

### Passo 6 — Destruir
```bash
terraform destroy
```

---

## Como criar e destruir o ambiente

### Criar
```bash
terraform init
terraform apply
```

### Destruir
```bash
terraform destroy
```

---

## Como acessar (Bastion → Web)

> A ideia é: você entra no Bastion (IP público) e dele acessa a instância Web (IP privado).

### 1) Descobrir IP público do Bastion
Se houver `terraform output`, use. Se não, AWS CLI (tags do projeto):
```bash
aws ec2 describe-instances \
  --filters "Name=tag:Project,Values=desafio-02" "Name=tag:Role,Values=bastion" "Name=instance-state-name,Values=running" \
  --query "Reservations[0].Instances[0].PublicIpAddress" \
  --output text
```

### 2) SSH no Bastion
```bash
ssh -i ./key.pem ubuntu@<BASTION_PUBLIC_IP>
```

### 3) Descobrir IP privado da Web (ASG)
```bash
aws ec2 describe-instances \
  --filters "Name=tag:Project,Values=desafio-02" "Name=tag:Role,Values=web" "Name=instance-state-name,Values=running" \
  --query "Reservations[].Instances[].{Id:InstanceId,Priv:PrivateIpAddress}" \
  --output table
```

### 4) SSH do Bastion para a Web
```bash
ssh ubuntu@<WEB_PRIVATE_IP>
```

**Dica rápida (mais limpa):** use `ssh -A` (agent forwarding) para não copiar chave pro Bastion.

---

## Como executar o backup

O “backup” aqui é demonstrativo para cumprir requisito: gerar artefato e enviar ao **S3 bucket de backup** com criptografia.

### Opção A — Via SSM (recomendado, sem SSH)
**PowerShell (Windows):**
```powershell
$bucket = terraform output -raw s3_backup_bucket
$instance = aws autoscaling describe-auto-scaling-groups `
  --auto-scaling-group-names "desafio-02-asg-web" `
  --query "AutoScalingGroups[0].Instances[?LifecycleState=='InService'].InstanceId | [0]" `
  --output text

$cmdId = aws ssm send-command `
  --instance-ids $instance `
  --document-name "AWS-RunShellScript" `
  --parameters ('{"commands":[
    "set -e",
    "ts=$(date +%Y%m%d-%H%M%S)",
    "sudo tar -czf /tmp/web-backup-$ts.tgz /etc /var/log || true",
    "aws s3 cp /tmp/web-backup-$ts.tgz s3://' + $bucket + '/web-backup-$ts.tgz --sse aws:kms || true",
    "ls -lh /tmp/web-backup-$ts.tgz || true"
  ]}') `
  --query "Command.CommandId" --output text

aws ssm get-command-invocation `
  --command-id $cmdId `
  --instance-id $instance `
  --query "{Status:Status,Stdout:StandardOutputContent,Stderr:StandardErrorContent}" `
  --output json
```

### Opção B — Validar que o arquivo foi para o bucket
```bash
BUCKET=$(terraform output -raw s3_backup_bucket)
aws s3 ls s3://$BUCKET/
```

---

## Decisões de segurança

### Rede e exposição
- **ALB** é o único recurso “publicamente acessível” para tráfego web.
- **Web instances** recebem tráfego HTTP **somente do SG do ALB**.
- **SSH na Web** é permitido **somente do Bastion**.
- **SSH no Bastion** é permitido **somente do IP informado em `my_ip_cidr`**.
- **RDS** é **privado** (`PubliclyAccessible=false`), em subnets privadas.

### Dados e segredos
- Credenciais de DB ficam no **AWS Secrets Manager**.
- **Sem segredo hardcoded** no repositório.
- Bucket de backup com:
  - **Block Public Access**
  - **SSE-KMS**
  - Policy **DenyInsecureTransport** (nega HTTP)

### Observabilidade e alertas
- Alarmes e logs no CloudWatch conforme implementado no Terraform (CPU/HealthyHosts/log groups etc.)

---

## Assunções (premissas adotadas)

- Região padrão de execução: `us-east-1`.
- Quem executar tem permissões para criar recursos AWS.
- Ambiente pode estar em **Free Tier** → ajustes de RDS (classe, retention) devem respeitar limites.
- Para bootstrap instalar pacotes (ex.: nginx, awscli), a instância Web precisa ter **egress** para internet.
- Tags são usadas para facilitar validação e rastreio (`Project=desafio-02`).

---

## Validação do ambiente (comandos ponto a ponto dos requisitos)

### 0) Identidade e região
```bash
aws sts get-caller-identity
aws configure get region
```

### 1) VPC
```bash
aws ec2 describe-vpcs --filters Name=tag:Project,Values=desafio-02 --query "Vpcs[].VpcId" --output text
```

### 2) Subnets (públicas x privadas)
```bash
VPC_ID=$(aws ec2 describe-vpcs --filters Name=tag:Project,Values=desafio-02 --query "Vpcs[0].VpcId" --output text)
aws ec2 describe-subnets \
  --filters Name=vpc-id,Values=$VPC_ID \
  --query "Subnets[].{Id:SubnetId,Az:AvailabilityZone,CIDR:CidrBlock,Public:MapPublicIpOnLaunch}" \
  --output table
```

### 3) Route Tables (default route via IGW)
```bash
aws ec2 describe-route-tables \
  --filters Name=vpc-id,Values=$VPC_ID \
  --query "RouteTables[].{RT:RouteTableId,IGWDefaultCount:length(Routes[?GatewayId!=null && DestinationCidrBlock=='0.0.0.0/0'])}" \
  --output table
```

### 4) ALB (DNS/estado/scheme)
```bash
aws elbv2 describe-load-balancers \
  --names desafio-02-alb \
  --query "LoadBalancers[0].{DNS:DNSName,State:State.Code,Scheme:Scheme}" \
  --output table
```

### 5) Teste HTTP no ALB
```bash
ALB_DNS=$(aws elbv2 describe-load-balancers --names desafio-02-alb --query "LoadBalancers[0].DNSName" --output text)
curl -I "http://$ALB_DNS/"
```

### 6) Target Group health
```bash
TG_ARN=$(aws elbv2 describe-target-groups --names desafio-02-tg-web --query "TargetGroups[0].TargetGroupArn" --output text)
aws elbv2 describe-target-health \
  --target-group-arn "$TG_ARN" \
  --query "TargetHealthDescriptions[].{Id:Target.Id,State:TargetHealth.State,Reason:TargetHealth.Reason}" \
  --output table
```

### 7) ASG status e instâncias
```bash
aws autoscaling describe-auto-scaling-groups \
  --auto-scaling-group-names "desafio-02-asg-web" \
  --query "AutoScalingGroups[0].{Desired:DesiredCapacity,Min:MinSize,Max:MaxSize,Instances:Instances[].{Id:InstanceId,Health:HealthStatus,LC:LifecycleState}}" \
  --output table
```

### 8) RDS (status, endpoint, privado)
```bash
aws rds describe-db-instances \
  --db-instance-identifier "desafio-02-mysql" \
  --query "DBInstances[0].{Status:DBInstanceStatus,Public:PubliclyAccessible,Endpoint:Endpoint.Address,SubnetGroup:DBSubnetGroup.DBSubnetGroupName}" \
  --output table
```

### 9) Secrets Manager (existe e não está em deleção)
```bash
SECRET_ARN=$(terraform output -raw db_secret_arn)
aws secretsmanager describe-secret --secret-id "$SECRET_ARN" \
  --query "{Name:Name,DeletedDate:DeletedDate,ARN:ARN}" --output table
```

### 10) S3 Backup bucket (existe + bloqueio público + encryption + HTTPS-only)
```bash
BUCKET=$(terraform output -raw s3_backup_bucket)

aws s3api head-bucket --bucket "$BUCKET"

aws s3api get-public-access-block --bucket "$BUCKET" \
  --query PublicAccessBlockConfiguration --output table

aws s3api get-bucket-encryption --bucket "$BUCKET" \
  --query "ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault" --output table

aws s3api get-bucket-policy --bucket "$BUCKET" --query Policy --output text
```

### 11) SSM (web instance online) + debug rápido
```bash
INSTANCE_ID=$(aws autoscaling describe-auto-scaling-groups --auto-scaling-group-names "desafio-02-asg-web" \
  --query "AutoScalingGroups[0].Instances[?LifecycleState=='InService'].InstanceId | [0]" --output text)

aws ssm describe-instance-information \
  --filters "Key=InstanceIds,Values=$INSTANCE_ID" \
  --query "InstanceInformationList[0].{Ping:PingStatus,Agent:AgentVersion,Platform:PlatformName}" \
  --output table
```

Debug (porta 80 + cloud-init):
```bash
CMD_ID=$(aws ssm send-command \
  --instance-ids "$INSTANCE_ID" \
  --document-name "AWS-RunShellScript" \
  --parameters '{"commands":[
    "set -x",
    "sudo ss -lntp | head -n 50",
    "curl -sS -o /dev/null -w \"HTTP %{http_code}\\n\" http://127.0.0.1/ || true",
    "sudo systemctl --no-pager --failed || true",
    "sudo tail -n 120 /var/log/cloud-init-output.log || true",
    "sudo tail -n 120 /var/log/cloud-init.log || true"
  ]}' \
  --query "Command.CommandId" --output text)

aws ssm get-command-invocation \
  --command-id "$CMD_ID" \
  --instance-id "$INSTANCE_ID" \
  --query "{Status:Status,Stdout:StandardOutputContent,Stderr:StandardErrorContent}" \
  --output json
```

---

## (Se implementado) arquivos de pipeline

Se você implementar pipelines, devem existir:
- **GitHub Actions:** `.github/workflows/*.yml`
- **ou Jenkins:** `Jenkinsfile`

Abaixo estão exemplos prontos para colar.

---

## Desejável – Pipelines de CI/CD (opcional)

### CI (Integração Contínua)
Requisitos:
- `terraform fmt -check`, `terraform validate`, `terraform plan` em PR
- Varreduras de segurança:
  - IaC: `tfsec`, `checkov`
  - Segredos: `gitleaks`, `trufflehog`
- (Opcional) pre-commit hooks

### CD (Entrega/Implantação Contínua) – opcional
- `terraform apply` manual via gate (ex.: `workflow_dispatch` / aprovação)
- Assume Role por OIDC (GitHub Actions) — evita chaves estáticas
- Branch protegida, ambientes de aprovação

Objetivo: demonstrar higiene de código, checagens automáticas e postura DevSecOps.

---

## Exemplo: GitHub Actions (CI)

Crie `.github/workflows/ci.yml`:

```yaml
name: CI - Terraform

on:
  pull_request:
    branches: [ "main" ]

permissions:
  contents: read

jobs:
  terraform:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: 1.6.6

      - name: Terraform Init
        working-directory: infra
        run: terraform init -input=false

      - name: Terraform Fmt (check)
        working-directory: infra
        run: terraform fmt -check -recursive

      - name: Terraform Validate
        working-directory: infra
        run: terraform validate

      - name: Terraform Plan
        working-directory: infra
        run: terraform plan -input=false -no-color

  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Gitleaks
        uses: gitleaks/gitleaks-action@v2
        with:
          args: "--no-git -v"

      - name: tfsec
        uses: aquasecurity/tfsec-action@v1.0.3
        with:
          working_directory: infra

      - name: TruffleHog (optional)
        uses: trufflesecurity/trufflehog@main
        with:
          args: --no-update --fail --only-verified .

      # - name: Checkov (optional)
      #   uses: bridgecrewio/checkov-action@v12
      #   with:
      #     directory: infra
```

---

## Exemplo: GitHub Actions (CD — apply manual + OIDC)

Crie `.github/workflows/cd-apply.yml`:

```yaml
name: CD - Terraform Apply (Manual)

on:
  workflow_dispatch:
    inputs:
      environment:
        description: "Environment name"
        required: true
        default: "dev"

permissions:
  id-token: write
  contents: read

jobs:
  apply:
    runs-on: ubuntu-latest
    environment: ${{ inputs.environment }}

    steps:
      - uses: actions/checkout@v4

      - uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: 1.6.6

      - name: Configure AWS credentials (OIDC)
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::<ACCOUNT_ID>:role/<ROLE_NAME>
          aws-region: us-east-1

      - name: Terraform Init
        working-directory: infra
        run: terraform init -input=false

      - name: Terraform Apply (manual gate)
        working-directory: infra
        run: terraform apply -auto-approve -input=false
```

> Para o gate de aprovação: configure **Environments** no GitHub e exija **reviewers**.

---

## Exemplo: Jenkinsfile (CI + CD manual)

Crie `Jenkinsfile` na raiz:

```groovy
pipeline {
  agent any

  stages {
    stage('Checkout') {
      steps { checkout scm }
    }

    stage('Terraform Init') {
      steps {
        dir('infra') { sh 'terraform init -input=false' }
      }
    }

    stage('Terraform Fmt Check') {
      steps {
        dir('infra') { sh 'terraform fmt -check -recursive' }
      }
    }

    stage('Terraform Validate') {
      steps {
        dir('infra') { sh 'terraform validate' }
      }
    }

    stage('Terraform Plan') {
      steps {
        dir('infra') { sh 'terraform plan -input=false -no-color' }
      }
    }

    stage('Security - tfsec (optional)') {
      when { expression { return fileExists('infra') } }
      steps {
        sh 'tfsec infra || true'
      }
    }

    stage('Security - gitleaks (optional)') {
      steps {
        sh 'gitleaks detect --no-git -v || true'
      }
    }

    stage('Apply (Manual Gate)') {
      when { branch 'main' }
      steps {
        input message: "Aprovar terraform apply?", ok: "Aplicar"
        dir('infra') { sh 'terraform apply -auto-approve -input=false' }
      }
    }
  }
}
```

---

## Reprodutibilidade e Documentação

Espera-se que o código entregue seja reprodutível por qualquer pessoa com conhecimento básico em AWS, sem depender de informações implícitas ou ajustes manuais não documentados.
