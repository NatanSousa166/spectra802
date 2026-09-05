import subprocess
import time
from spectra802.utils.logger import setup_logger

logger = setup_logger("interface")

class InterfaceManager:
    """
    Gerenciador de baixo nível para abstração da interface sem fio no Linux.
    Utiliza chamadas diretas às ferramentas de sistema `iw` e `ip` para consultar
    e alternar o modo de operação da placa Wi-Fi (Managed -> Monitor).
    """

    def __init__(self, interface: str = "wlan0"):
        self.interface = interface

    def is_monitor_mode(self) -> bool:
        """
        Verifica se a interface configurada já está operando em modo Monitor.
        Executa `iw dev <iface> info` e busca por 'type monitor' no output.
        """
        try:
            res = subprocess.run(
                ["iw", "dev", self.interface, "info"],
                capture_output=True,
                text=True,
                check=False
            )
            return "type monitor" in res.stdout
        except Exception as e:
            logger.error(f"Erro ao consultar o modo operacional da interface {self.interface}: {e}")
            return False

    def enable_monitor_mode(self) -> bool:
        """
        Alterna a interface para o modo Monitor utilizando a pilha `iw/ip`.
        Desativa a interface, altera o tipo para monitor e reativa a interface.
        """
        logger.info(f"Iniciando transição da interface {self.interface} para MODO MONITOR...")
        try:
            # 1. Desativa a interface de rede
            subprocess.run(["sudo", "ip", "link", "set", self.interface, "down"], check=True)
            
            # 2. Altera o modo do dispositivo para monitor
            subprocess.run(["sudo", "iw", "dev", self.interface, "set", "type", "monitor"], check=True)
            
            # 3. Reativa a interface de rede
            subprocess.run(["sudo", "ip", "link", "set", self.interface, "up"], check=True)
            
            time.sleep(1) # Intervalo para estabilização do driver no Kernel

            if self.is_monitor_mode():
                logger.info(f"Interface {self.interface} configurada em MODO MONITOR com sucesso.")
                return True
            else:
                logger.error(f"A interface {self.interface} não confirmou o estado Monitor após a alteração.")
                return False

        except subprocess.CalledProcessError as e:
            logger.error(f"Falha ao executar comandos de sistema na interface {self.interface}: {e}")
            return False
        except Exception as e:
            logger.error(f"Erro inesperado ao alterar modo da interface {self.interface}: {e}")
            return False
