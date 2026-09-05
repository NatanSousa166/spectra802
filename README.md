# Spectra802 - Wi‑Fi Security Framework & Risk Analyzer

## Visão Geral

O **Spectra802** é um framework modular desenvolvido em Python para auditoria de segurança e análise de risco em redes sem fio IEEE 802.11. Projetado para ambientes Linux voltados à segurança ofensiva e testes autorizados, o projeto automatiza atividades de reconhecimento passivo, avaliação criptográfica, auditoria de WPS e testes contextuais de credenciais.

O objetivo do framework é fornecer uma plataforma unificada para identificação de vulnerabilidades, classificação de risco e geração de relatórios estruturados durante avaliações de segurança em redes Wi‑Fi.

---

## Principais Funcionalidades

### Gerenciamento de Interface Wireless
- Detecção e gerenciamento de interfaces sem fio.
- Alternância automática para **Modo Monitor**.
- Integração com ferramentas nativas do Linux (`iw`, `ip` e `airmon-ng`).
- Verificações de estado e compatibilidade da interface.

### Captura Passiva de Redes
- Captura de *Beacon Frames* utilizando Scapy.
- Descoberta de redes próximas sem interação ativa.
- Identificação de:
  - SSID visível e oculto;
  - BSSID;
  - Canal operacional;
  - Intensidade de sinal;
  - Tipo de criptografia.

### Análise Heurística de Risco
Classificação automática baseada nas características de segurança identificadas:

| Nível | Descrição |
|---------|---------|
| CRITICAL | Redes abertas ou com falhas graves conhecidas |
| HIGH | Configurações inseguras ou protocolos obsoletos |
| MEDIUM | Riscos moderados e dependentes de contexto |
| LOW | Configurações consideradas adequadas |

A análise considera:

- Redes abertas;
- WEP;
- WPA;
- WPA2;
- Presença de WPS;
- Evidências de vulnerabilidades conhecidas;
- Validação complementar de handshakes EAPOL via TShark.

### Auditoria de WPS
- Integração com `reaver`;
- Suporte a testes do tipo **Pixie Dust**;
- Identificação de dispositivos com WPS habilitado;
- Verificação de estado de bloqueio através do `wash`;
- Tratamento automatizado de processos conflitantes usando:
  ```bash
  airmon-ng check kill
  ```

### Ataque de Dicionário Contextual
- Geração automatizada de wordlists baseadas em contexto.
- Permutações envolvendo:
  - nomes;
  - datas;
  - padrões comuns;
  - fabricantes e provedores.
- Integração com:
  ```bash
  aircrack-ng
  ```

### Exportação de Resultados
- Geração de relatórios estruturados em JSON.
- Registro de vulnerabilidades identificadas.
- Base para integração com pipelines de auditoria.

---

## Estrutura do Projeto

```text
spectra802/
├── .env
├── .env.example
├── .gitignore
├── README.md
├── requirements.txt
├── main.py
└── spectra802/
    ├── __init__.py
    ├── core/
    │   ├── __init__.py
    │   ├── interface.py
    │   └── sniffer.py
    ├── modules/
    │   ├── __init__.py
    │   ├── bruteforce.py
    │   ├── crypto.py
    │   └── wps.py
    └── utils/
        ├── __init__.py
        ├── logger.py
        └── reporter.py
```

---

## Requisitos

### Sistema Operacional

- Kali Linux (recomendado)
- Debian, Ubuntu ou distribuições compatíveis

### Python

- Python 3.8 ou superior

### Dependências de Sistema

```bash
iw
ip
airmon-ng
aircrack-ng
reaver
wash
pixiewps
tshark
```

### Dependências Python

```text
scapy>=2.5.0
python-dotenv>=1.0.0
```

---

## Instalação

### 1. Clonar o Repositório

```bash
git clone git@github.com:NatanSousa166/spectra802.git
cd spectra802
```

### 2. Instalar Dependências do Sistema

```bash
sudo apt update
sudo apt install -y \
python3-venv \
reaver \
pixiewps \
aircrack-ng \
tshark \
iw
```

### 3. Configurar Ambiente Virtual

```bash
python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

---

## Configuração

### Configurar Variáveis de Ambiente

Crie o arquivo `.env`:

```bash
cp .env.example .env
```

Caso sua interface wireless não seja `wlan0`, altere:

```env
WIFI_INTERFACE=wlan0
```

Substitua pelo nome correto da interface utilizada durante os testes.

---

## Execução

A execução do Spectra802 requer privilégios administrativos devido à manipulação de interfaces de rede e captura de pacotes em modo monitor.

```bash
sudo .venv/bin/python3 main.py
```

---

## Fluxo de Execução

1. O framework lê a interface definida no arquivo `.env`.
2. Verifica se a interface está em Modo Monitor.
3. Oferece alternância automática caso necessário.
4. Solicita o tempo de captura passiva.
5. Realiza a descoberta das redes disponíveis.
6. Executa a classificação de risco.
7. Identifica presença de WPS.
8. Permite selecionar um alvo para auditoria.
9. Executa módulos de:
   - Auditoria WPS (Pixie Dust);
   - Ataque de Dicionário Contextual.
10. Exporta os resultados para:

```text
resultado_audit.json
```

---

## Relatórios

Exemplo de artefato gerado:

```text
resultado_audit.json
```

O relatório contém:

- Redes identificadas;
- Informações de criptografia;
- Classificação de risco;
- Resultados de auditorias;
- Evidências coletadas;
- Metadados da execução.

---

## Segurança e Limitações

- O framework depende de hardware compatível com Modo Monitor.
- Algumas funcionalidades exigem adaptadores Wi‑Fi com suporte adequado.
- O desempenho varia conforme chipset, driver e ambiente de RF.
- O uso indevido pode violar legislações locais.

---

## Isenção de Responsabilidade

Esta ferramenta foi desenvolvida exclusivamente para fins educacionais, pesquisa e testes de segurança autorizados.

O uso do Spectra802 contra redes, dispositivos ou infraestruturas sem autorização explícita pode ser ilegal em determinadas jurisdições.

O desenvolvedor não se responsabiliza por qualquer utilização indevida do software, danos diretos ou indiretos decorrentes do seu uso, nem por atividades realizadas em desacordo com a legislação aplicável.

---

