from scapy.all import Dot11, Dot11Beacon, Dot11Elt, sniff
from spectra802.utils.logger import setup_logger

logger = setup_logger("sniffer")

class WifiSniffer:
    """
    Capturador passivo de pacotes de rede sem fio (IEEE 802.11).
    Utiliza a biblioteca Scapy para escutar frames de gerenciamento (Beacon Frames)
    e extrair metadados como SSID, BSSID, suporte WPS, tipo de criptografia e canal.
    """

    def __init__(self, interface: str = "wlan0"):
        self.interface = interface
        self.networks = {}

    def _packet_handler(self, pkt):
        """
        Callback invocado para cada pacote capturado na interface.
        Filtra Beacon Frames (Dot11Beacon) e decodifica as extensões de informação (IE).
        """
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt[Dot11].addr2
            
            # Extração do SSID
            try:
                ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
            except Exception:
                ssid = "<Hidden>"

            if not ssid.strip():
                ssid = "<Hidden>"

            wps_enabled = False
            crypto_type = "OPEN"

            # Checagem de privacidade/criptografia no cabeçalho de capacidades
            capability = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
            if "privacy" in capability:
                crypto_type = "WPA/WPA2"

            # Varredura dos Elementos de Informação (Information Elements - IE)
            elt = pkt.getlayer(Dot11Elt)
            while elt:
                # OUI do WPS Vendor Specific: 00:50:f2:04
                if elt.ID == 221 and elt.info.startswith(b'\x00\x50\xf2\x04'):
                    wps_enabled = True
                # Elemento RSN (WPA2)
                elif elt.ID == 48:
                    crypto_type = "WPA2"
                # Elemento WPA Vendor Specific (WPA1): 00:50:f2:01
                elif elt.ID == 221 and elt.info.startswith(b'\x00\x50\xf2\x01'):
                    if crypto_type != "WPA2":
                        crypto_type = "WPA"
                elt = elt.payload.getlayer(Dot11Elt)

            # Extração do Canal Operacional
            channel = None
            try:
                channel = int(ord(pkt[Dot11Elt:3].info))
            except Exception:
                channel = None

            # Armazena ou atualiza a rede mapeada
            if bssid not in self.networks:
                self.networks[bssid] = {
                    "ssid": ssid,
                    "bssid": bssid,
                    "crypto": crypto_type,
                    "wps_enabled": wps_enabled,
                    "channel": channel
                }

    def start_scan(self, timeout: int = 10) -> list:
        """
        Inicia a captura passiva de pacotes na interface monitor durante o tempo estipulado.
        Retorna uma lista de dicionários contendo os atributos das redes mapeadas.
        """
        logger.info(f"Escutando pacotes Beacons 802.11 na interface {self.interface} por {timeout}s...")
        try:
            sniff(iface=self.interface, prn=self._packet_handler, timeout=timeout)
        except Exception as e:
            logger.error(f"Erro durante a captura de pacotes via Scapy: {e}")
            
        return list(self.networks.values())
