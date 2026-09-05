import subprocess
from spectra802.utils.logger import setup_logger

logger = setup_logger("crypto")

class RiskAnalyzer:
    """
    Analisador de risco de segurança para redes sem fio 802.11.
    Calcula matriz heurística de vulnerabilidade e integra validação 
    de integridade de criptografia com ferramentas do sistema (ex: tshark/wash).
    """

    def process_scan_results(self, networks: list) -> list:
        """
        Processa os dados das redes capturadas pelo Sniffer e atribui um nível de risco
        (CRITICAL, HIGH, MEDIUM, LOW) com base no algoritmo de cifra e recursos ativos.
        """
        logger.info("Processando matriz de análise de risco criptográfico das redes...")
        evaluated = []

        for net in networks:
            risk = "LOW"
            vulns = []

            crypto = net.get("crypto", "OPEN")
            wps = net.get("wps_enabled", False)

            # Classificação heurística de risco
            if crypto == "OPEN":
                risk = "HIGH"
                vulns.append("Rede aberta sem criptografia; tráfego exposto a eavesdropping/sniffing passivo.")
            elif crypto == "WEP":
                risk = "CRITICAL"
                vulns.append("Protocolo WEP obsoleto (RC4); vulnerável a injeção de pacotes e quebra estática de IVs.")
            elif crypto == "WPA":
                risk = "HIGH"
                vulns.append("Protocolo WPA1 (TKIP); suscetível a ataques de retransmissão e fraca integridade Michael MIC.")
            elif crypto == "WPA2":
                risk = "MEDIUM"
                vulns.append("WPA2-PSK (AES-CCMP); vulnerável a captura de 4-Way Handshake EAPOL e ataque de dicionário off-line.")

            if wps:
                # Eleva o risco para HIGH caso esteja habilitado
                if risk not in ["CRITICAL"]:
                    risk = "HIGH"
                vulns.append("WPS (Wi-Fi Protected Setup) ativo; suscetível a exploração de PIN (Pixie Dust / Brute-force).")

            net_copy = dict(net)
            net_copy["risk_level"] = risk
            net_copy["vulnerabilities"] = vulns
            evaluated.append(net_copy)

        return evaluated

    def check_handshake_file(self, cap_filepath: str) -> dict:
        """
        Ferramenta complementar: Valida via tshark a presença de Handshake EAPOL Válido
        no arquivo de captura .cap antes de submeter ao ataque de dicionário.
        """
        try:
            cmd = ["tshark", "-r", cap_filepath, "-Y", "eapol", "-T", "fields", "-e", "wlan.bssid"]
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            
            if res.returncode == 0 and res.stdout.strip():
                bssids = list(set(res.stdout.strip().splitlines()))
                logger.info(f"[+] Handshake EAPOL detectado no arquivo {cap_filepath} para o(s) BSSID(s): {bssids}")
                return {"valid_handshake": True, "bssids": bssids}
            else:
                logger.warning(f"[-] Nenhum frame EAPOL válido encontrado em {cap_filepath}.")
                return {"valid_handshake": False, "bssids": []}

        except FileNotFoundError:
            logger.warning("tshark não está instalado. Pulando verificação avançada de captura.")
            return {"valid_handshake": None, "error": "tshark not installed"}
        except Exception as e:
            logger.error(f"Erro ao analisar integridade da captura {cap_filepath}: {e}")
            return {"valid_handshake": False, "error": str(e)}
