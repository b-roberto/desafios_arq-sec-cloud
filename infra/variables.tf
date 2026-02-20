variable "project_name" {
  type        = string
  description = "Prefixo/nome do projeto para nomear recursos."
  default     = "desafio-02"
}

variable "owner" {
  type        = string
  description = "Tag Owner (opcional)."
  default     = "bruno"
}

variable "aws_region" {
  type        = string
  description = "Região AWS."
  default     = "us-east-1"
}

variable "azs" {
  type        = list(string)
  description = "Lista de AZs para o web tier (duas AZs)."
  default     = ["us-east-1a", "us-east-1b"]
}

variable "my_ip_cidr" {
  type        = string
  description = "Seu IP público em CIDR para liberar SSH no Bastion (ex: 203.0.113.10/32)."
}

variable "instance_type_bastion" {
  type    = string
  default = "t3.micro"
}

variable "instance_type_web" {
  type    = string
  default = "t3.micro"
}

variable "desired_capacity" {
  type        = number
  description = "ASG desired. Para reduzir custo, deixe 1 e documente desired=2."
  default     = 1
}

variable "max_size" {
  type    = number
  default = 2
}

variable "min_size" {
  type    = number
  default = 1
}

variable "db_instance_class" {
  type    = string
  default = "db.t3.micro"
}

variable "db_allocated_storage" {
  type    = number
  default = 20
}

variable "db_name" {
  type    = string
  default = "appdb"
}

variable "db_username" {
  type    = string
  default = "appuser"
}

variable "enable_interface_endpoints" {
  type        = bool
  description = "Cria VPC Endpoints Interface (SSM/Logs/Secrets/KMS) para evitar NAT. Pode gerar custo por endpoint."
  default     = true
}

variable "backup_schedule_cron" {
  type        = string
  description = "Cron para backup (UTC) - exemplo: '0 * * * *' = de hora em hora."
  default     = "0 * * * *"
}
