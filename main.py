import os
import sys
from dotenv import load_dotenv

from spectra802.core.interface import InterfaceManager
from spectra802.core.sniffer import WifiSniffer
from spectra802.modules.crypto import RiskAnalyzer
from spectra802.modules.wps import WPSAttacker
from spectra802.modules.bruteforce import WordlistGenerator, DictionaryAttacker
from spectra802.utils.reporter import ReportGenerator
from spectra802.utils.logger import setup_logger

load_dotenv()
logger = setup_logger("main")

def print_banner():
    print("""
    ===================================================
                   SPECTRA802 - AUDIT TOOL             
          Wi-Fi Security Framework & Risk Analyzer     
    ===================================================
    """)

def main():
    print_banner()

    # 1. Carregamento de Configurações de Ambiente
    iface = os.getenv("WIFI_INTERFACE", "wlan0")
    logger.info(f"Interface alvo configurada (.env): {iface}")

    # 2. Gerenciamento e Transição da Interface de Rede
    iface_mgr = InterfaceManager(interface=iface)
    if not iface_mgr.is_monitor_mode():
        print(f"\n[!] A interface {iface} não está operando em modo monitor.")
        opcao = input("Deseja ativar o modo monitor automaticamente? (s/n): ").strip().lower()
        if opcao == "s":
            if not iface_mgr.enable_monitor_mode():
                logger.error("Falha ao configurar modo monitor. Encerrando execução.")
                sys.exit(1)
        else:
            print("[!] Operação cancelada. A auditoria requer o modo monitor ativo.")
            sys.exit(0)

    # 3. Varredura Passiva de Pacotes 802.11
    try:
        sec_input = input("\nDigite o tempo de varredura em segundos [Padrão: 10s]: ").strip()
        timeout = int(sec_input) if sec_input.isdigit() else 10
    except ValueError:
        timeout = 10

    sniffer = WifiSniffer(interface=iface)
    logger.info(f"Iniciando escuta passiva na interface {iface} por {timeout} segundos...")
    raw_networks = sniffer.start_scan(timeout=timeout)

    if not raw_networks:
        logger.warning("Nenhuma rede sem fio foi identificada no intervalo estipulado.")
        sys.exit(0)

    # 4. Avaliação Heurística de Risco
    analyzer = RiskAnalyzer()
    evaluated_results = analyzer.process_scan_results(raw_networks)

    print(f"\n[+] Total de redes identificadas: {len(evaluated_results)}")
    print("-" * 80)
    for idx, net in enumerate(evaluated_results, 1):
        print(f"[{idx}] SSID: {net['ssid']:<20} | BSSID: {net['bssid']} | Risco: {net['risk_level']:<8} | WPS: {net['wps_enabled']}")
    print("-" * 80)

    # 5. Seleção e Auditoria Direcionada
    escolha = input("\nDigite o número da rede que deseja auditar (ou 's' para saltar): ").strip()
    
    target_net = None
    if escolha.isdigit() and 1 <= int(escolha) <= len(evaluated_results):
        target_net = evaluated_results[int(escolha) - 1]

    if target_net:
        print(f"\n[*] Alvo Selecionado: {target_net['ssid']} ({target_net['bssid']})")

        # Módulo WPS (Pixie Dust)
        if target_net["wps_enabled"]:
            exec_wps = input("\nWPS Habilitado! Deseja executar teste de vulnerabilidade Pixie Dust? (s/n): ").strip().lower()
            if exec_wps == "s":
                wps = WPSAttacker(interface=iface)
                channel = target_net.get("channel", None)
                wps_res = wps.run_pixie_dust(target_bssid=target_net["bssid"], channel=channel, timeout=120)
                target_net["wps_audit_result"] = wps_res

        # Módulo Bruteforce Contextual
        exec_brute = input("\nDeseja executar teste de dicionário/wordlist? (s/n): ").strip().lower()
        if exec_brute == "s":
            generator = WordlistGenerator()
            
            print("\n--- [ Parâmetros para Wordlist Contextual ] ---")
            nomes = input("-> Nomes/Sobrenomes/Apelidos (separados por vírgula): ")
            provedor = input("-> Provedor/Marca do Roteador (ex: Brisa, Intelbras): ")
            datas = input("-> Datas de referência (separadas por vírgula): ")

            context_words = generator.build_from_user_input(
                keywords_str=nomes,
                provider=provedor,
                dates_str=datas
            )

            default_dict = "rockyou.txt" if os.path.exists("rockyou.txt") else None
            prompt_txt = f"\n-> Caminho para arquivo de dicionário externo [Padrão: {default_dict}]: " if default_dict else "\n-> Caminho para arquivo de dicionário externo: "
            
            dic_path = input(prompt_txt).strip()
            if not dic_path and default_dict:
                dic_path = default_dict

            final_wordlist = generator.combine_wordlists(context_words, file_filepath=dic_path if dic_path else None)
            
            if final_wordlist:
                attacker = DictionaryAttacker(interface=iface)
                brute_res = attacker.simulate_attack(target_net["ssid"], final_wordlist)
                target_net["bruteforce_audit_result"] = brute_res
            else:
                logger.warning("Nenhuma palavra gerada para compor o dicionário de teste.")

    # 6. Exportação do Relatório Final
    logger.info("Consolidando relatório da auditoria...")
    reporter = ReportGenerator(evaluated_results)
    reporter.export_to_json("resultado_audit.json")
    print("\n[+] Processo de auditoria concluído. Dados exportados para 'resultado_audit.json'.")

if __name__ == "__main__":
    main()
