import logging
import sys

def setup_logger(name: str) -> logging.Logger:
    """
    Centraliza a configuração e inicialização dos loggers da aplicação.
    
    Aplica formatação padronizada com timestamp, nível do log e nome da instância,
    garantindo a prevenção de múltiplos handlers concorrentes na mesma execução.
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            '[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s',
            '%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger
