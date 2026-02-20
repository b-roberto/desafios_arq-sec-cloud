# Desafios Técnicos – Segurança e Arquitetura em AWS

## Sobre este repositório
Este repositório contém minha entrega dos desafios propostos para a vaga de **Analista de Segurança em Nuvem**.  
O foco é demonstrar análise de riscos, redesenho de arquitetura (Security Design Review) e organização técnica dos entregáveis.

---

## Estrutura do repositório
- `desafio_01.md` — **Desafio 01 (Security Design Review)**: riscos, To‑Be, justificativas, roadmap e assunções.
- `desafio_02.md` — **Desafio 02 (IaC)**: (em construção / a preencher após finalizar o 01).
- `docs/imagens/` — diagramas `.drawio` (As‑Is e To‑Be) e imagens auxiliares (se necessário).
- `infra/` — código IaC do desafio 02 (Terraform ou equivalente), quando aplicável.

---

## ✅ Desafio 1 – Análise e Redesenho de Arquitetura (Security Design Review)
**Objetivo:** avaliar o cenário As‑Is, classificar riscos e propor uma arquitetura To‑Be mais segura e operável, incluindo conectividade privada com on‑premises, proteção de dados, governança e observabilidade mínima.

### Entregáveis do Desafio 01
- Documento: [`desafio_01.md`](./desafio_01.md)
- Diagrama As‑Is (referência): `docs/imagens/aws_diagrama.drawio`
- Diagrama To‑Be (proposto): `docs/imagens/aws_diagrama_to_be.drawio`

### Como abrir os diagramas
1. Acesse https://app.diagrams.net
2. **File → Open from → Device**
3. Selecione o arquivo `.drawio` desejado.

---

## ⚙️ Desafio 2 – Infraestrutura como Código (IaC) com AWS Free Tier
Entrega do **Desafio 02**, conforme requisitos: VPC, subnets, SG least privilege, Bastion, Web privado (ASG/ALB), RDS privado, backup em S3 com VPCE + policy `aws:sourceVpce`, KMS (rotação), Secrets Manager e observabilidade mínima.

- Documento: [`desafio_02.md`](./desafio_02.md)
- Infra: `infra/`

---

## Como enviar / validar a entrega
- O repositório contém os arquivos finais de cada desafio.
- Caso algum requisito não seja implementado, ele é registrado como **assunção** ou **evolução opcional** no respectivo Markdown.

---

## Observações rápidas (pra facilitar a avaliação)
- O Desafio 01 foi construído para manter a arquitetura **enxuta**, priorizando correção de exposição, identidade, criptografia, observabilidade e conectividade privada com on‑prem.
- A proposta evita complexidade desnecessária (ex.: múltiplas VPCs) quando subnets/SG resolvem o requisito com menor risco operacional.
