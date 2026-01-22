#!/usr/bin/env bash

# Script que repete a logica do numero 3 mas monitoriza o arquivo em tempo real

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

nome_base=$(basename "$arquivo")
relatorio="relatorio_falhas-${nome_base}.txt"
echo "Monitorando o arquivo $arquivo em tempo real. Pressione Ctrl+C para sair."

timestamp_inicio=$(date "+%Y-%m-%d %H:%M:%S")
echo "Monitorizacao iniciada em $timestamp_inicio" > "$relatorio"

tail -n0 -F "$arquivo" | while read nova_linha; do
	printf "%s\n" "$nova_linha" | grep -E "$regex_linha" >/dev/null || continue
	ip_detectado=$(printf "%s\n" "$nova_linha" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}')
	if [ -z "$ip_detectado" ]; then
		mensagem_falha="Falha detectada (IP nao identificado): $nova_linha"
	else
		mensagem_falha="Falha detectada para $ip_detectado: $nova_linha"
	fi
	carimbo_tempo=$(date "+%Y-%m-%d %H:%M:%S")
	echo "[$carimbo_tempo] $mensagem_falha"
	echo "[$carimbo_tempo] $mensagem_falha" >> "$relatorio"
done
