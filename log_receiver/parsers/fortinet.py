import re
from datetime import datetime
from django.utils import timezone
from dateutil.parser import parse

def parse_fortinet_syslog(log_string):
    """
    Parseia uma string Syslog gerada pelo FortiOS.
    Formato esperado: key1="value1" key2="value2" ou key1=value1
    """
    parsed_data = {}
    
    # Remove cabecalho Syslog (ex: <189>date=2024-02-23 ...) se existir
    clean_string = re.sub(r'^<\d+>', '', log_string.strip())
    
    # Regex para capturar pares de chave=valor vazios e com/sem aspas
    # Ex: user="rafaela.silva" dstip=1.1.1.1
    pattern = re.compile(r'([a-zA-Z0-9_-]+)=("([^"]*)"|([^ ]*))')
    
    for match in pattern.finditer(clean_string):
        key = match.group(1).lower()
        val_quoted = match.group(3)
        val_unquoted = match.group(4)
        
        value = val_quoted if val_quoted is not None else val_unquoted
        parsed_data[key] = value

    return parsed_data
