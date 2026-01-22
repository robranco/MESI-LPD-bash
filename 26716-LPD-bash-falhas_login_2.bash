#!/usr/bin/env bash

# Script simples para listar IPs com tentativas de login falhadas acima de um minimo

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

echo "Informe o numero minimo de falhas por IP:"
read minimo

case $minimo in
	''|*[!0-9]*)
		echo "Preciso de um numero inteiro para o minimo."
		exit 1
		;;
	0)
		echo "O minimo precisa ser pelo menos 1."
		exit 1
		;;
esac

ips_com_contagem=$(echo "$linhas" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c)

if [ -z "$ips_com_contagem" ]; then
	echo "Nao consegui extrair IPs dessas linhas."
	exit 0
fi

ips_filtrados=$(echo "$ips_com_contagem" | awk -v minimo="$minimo" '$1 >= minimo {print $1 " " $2}' | sort -nr)

if [ -z "$ips_filtrados" ]; then
	echo "Nenhum IP passou do limite informado."
	exit 0
fi

echo "IPs com mais de $minimo falhas:"
echo "$ips_filtrados" | awk '{printf "%-20s %6s falhas\n", $2, $1}'
