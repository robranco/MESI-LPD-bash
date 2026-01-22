#!/usr/bin/env bash

# Script simples para listar arquivos alterados num intervalo de datas


if [ $# -lt 2 ] || [ $# -gt 3 ]; then
	echo "Uso: $0 DATA_INICIO DATA_FIM [DIRETORIO]"
	echo "Exemplo: $0 2024-01-01 2024-01-31 /tmp"
	exit 1
fi

data_inicio="$1"
data_fim="$2"
diretorio="${3:-.}"

if [ ! -d "$diretorio" ]; then
	echo "O diretorio informado nao existe: $diretorio"
	exit 1
fi

echo "A procurar arquivos entre $data_inicio e $data_fim no diretorio $diretorio"

arquivos=$(find "$diretorio" -type f -newermt "$data_inicio 00:00:00" ! -newermt "$data_fim 23:59:59" 2>/dev/null)

if [ -z "$arquivos" ]; then
	echo "Nao encontrei arquivos alterados nesse intervalo."
	exit 0
fi

echo "Arquivos modificados:"
echo "$arquivos"
