#!/usr/bin/env bash

# Script simples para listar IPs com tentativas de login falhadas

if [ $# -gt 1 ]; then
	echo "Uso: $0 [arquivo_de_logs]"
	exit 1
fi

arquivo=""

if [ $# -eq 1 ]; then
	arquivo="$1"
else
	echo "Nao indicou arquivo. Posso usar /var/log/auth.log? (s/n)"
	read resposta
	if [ "$resposta" = "s" ] || [ "$resposta" = "S" ]; then
		arquivo="/var/log/auth.log"
	else
		echo "Informe o caminho completo do arquivo:" 
		read arquivo
	fi
fi

if [ -z "$arquivo" ]; then
	echo "Nao recebi um arquivo valido."
	exit 1
fi

if [ ! -f "$arquivo" ]; then
	echo "O arquivo nao existe: $arquivo"
	exit 1
fi

regex_linha="Failed password|authentication failure|Failed publickey"

linhas=$(grep -E "$regex_linha" "$arquivo" 2>/dev/null)

if [ -z "$linhas" ]; then
	echo "Nao encontrei tentativas falhadas neste arquivo."
	exit 0
fi

ips=$(echo "$linhas" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq)

if [ -z "$ips" ]; then
	echo "Nao consegui extrair IPs dessas linhas."
	exit 0
fi

echo "IPs com tentativas falhadas:"
echo "$ips"
