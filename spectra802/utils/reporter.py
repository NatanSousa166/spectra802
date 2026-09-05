import json
from datetime import datetime
from spectra802.utils.logger import setup_logger

logger = setup_logger("reporter")

class ReportGenerator:
    """
    Gerador de relatórios para o framework Spectra802.
    Consolida os dados brutos de captura, análise de risco criptográfico e 
    resultados das auditorias WPS e dicionário em relatórios estáticos estruturados.
    """

    def __init__(self, data: list):
        self.data = data

    def export_to_json(self, filepath: str = "resultado_audit.json") -> bool:
        """
        Serializa e exporta os dados da auditoria para um arquivo JSON formatado.
        Aplica formatação ISO 8601 para carimbos de data/hora e assegura
        compatibilidade com caracteres UTF-8.
        """
        report = {
            "timestamp": datetime.now().isoformat(),
            "total_networks_evaluated": len(self.data),
            "audit_results": self.data
        }
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=4, ensure_ascii=False)
            logger.info(f"Relatório exportado com sucesso para: {filepath}")
            return True
        except Exception as e:
            logger.error(f"Erro ao gerar o relatório JSON ({filepath}): {e}")
            return False
