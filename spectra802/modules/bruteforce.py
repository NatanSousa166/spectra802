import os
import subprocess
from spectra802.utils.logger import setup_logger

logger = setup_logger("bruteforce")

class WordlistGenerator:
    """
    Gerador contextual de dicionários de senhas.
    Permite combinar vocabulário personalizado (nomes, datas, marcas/provedores)
    com dicionários corporativos/padrão (ex: rockyou.txt).
    """

    def build_from_user_input(self, keywords_str: str = "", provider: str = "", dates_str: str = "") -> list:
        """
        Gera permutações contextuais com base nas palavras-chave fornecidas pelo usuário.
        Converte termos por separação por vírgula e aplica variações de caixa e símbolos.
        """
        words = set()
        raw_keywords = [k.strip() for k in keywords_str.split(",") if k.strip()]
        raw_dates = [d.strip() for d in dates_str.split(",") if d.strip()]

        for kw in raw_keywords:
            words.add(kw)
            words.add(kw.lower())
            words.add(kw.upper())
            words.add(kw.capitalize())

        if provider.strip():
            p = provider.strip()
            words.add(p)
            words.add(p.lower())
            words.add(p.capitalize())

        combined = set(words)
        for w in words:
            for d in raw_dates:
                combined.add(f"{w}{d}")
                combined.add(f"{w}@{d}")
                combined.add(f"{w}#{d}")
                combined.add(f"{w}_{d}")

        return list(combined)

    def combine_wordlists(self, custom_words: list, file_filepath: str = None) -> list:
        """
        Unifica a lista personalizada gerada com um dicionário estático em arquivo.
        Utiliza a estrutura de dados set() para garantir deduplicação em complexidade O(1).
        """
        final_set = set(custom_words)

        if file_filepath and os.path.exists(file_filepath):
            logger.info(f"Carregando e unificando dicionário externo: {file_filepath}...")
            try:
                with open(file_filepath, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line_str = line.strip()
                        if line_str:
                            final_set.add(line_str)
            except Exception as e:
                logger.error(f"Erro ao ler arquivo de dicionário {file_filepath}: {e}")

        return list(final_set)

class DictionaryAttacker:
    """
    Executor de testes de dicionário em redes WPA/WPA2.
    Integrado ao aircrack-ng para validação real de pacotes EAPOL (Handshake).
    """

    def __init__(self, interface: str = "wlan0"):
        self.interface = interface

    def run_aircrack_attack(self, cap_file: str, wordlist_file: str, bssid: str = None) -> dict:
        """
        Executa o aircrack-ng para testar a wordlist contra um arquivo .cap contendo o handshake.
        """
        if not os.path.exists(cap_file):
            logger.error(f"Arquivo de captura ({cap_file}) não foi localizado.")
            return {"cracked": False, "key": None, "error": "Cap file not found"}

        if not os.path.exists(wordlist_file):
            logger.error(f"Arquivo de wordlist ({wordlist_file}) não foi localizado.")
            return {"cracked": False, "key": None, "error": "Wordlist file not found"}

        cmd = ["sudo", "aircrack-ng", "-w", wordlist_file, cap_file]
        if bssid:
            cmd.extend(["-b", bssid])

        logger.info(f"Iniciando aircrack-ng para o BSSID {bssid if bssid else 'Todos'} usando {wordlist_file}...")

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            output = res.stdout

            if "KEY FOUND!" in output:
                for line in output.splitlines():
                    if "KEY FOUND!" in line:
                        key = line.split("[")[1].split("]")[0] if "[" in line else line
                        logger.info(f"[+] CHAVE ENCONTRADA: {key}")
                        return {"cracked": True, "key": key, "output": output}

            logger.warning("[-] Teste finalizado sem encontrar a chave no dicionário.")
            return {"cracked": False, "key": None, "output": output}

        except subprocess.TimeoutExpired:
            logger.warning("[-] Limite de tempo excedido para o ataque de dicionário.")
            return {"cracked": False, "key": None, "error": "Timeout"}
        except Exception as e:
            logger.error(f"[-] Erro ao executar aircrack-ng: {e}")
            return {"cracked": False, "key": None, "error": str(e)}

    def simulate_attack(self, ssid: str, wordlist: list) -> dict:
        """
        Modo de simulação em memória (validação lógica e contagem de combinações).
        """
        total = len(wordlist)
        logger.info(f"Simulando auditoria de dicionário para o SSID '{ssid}' ({total} combinações geradas).")
        return {
            "ssid": ssid,
            "total_tested": total,
            "cracked": False,
            "found_password": None
        }
