#!/bin/bash

echo "Verificador simples de portas com netcat"

read -p "Informe o endereço ou IP do alvo: " alvo
read -p "Informe as portas separadas por espaço (ex.: 22 80 443): " portas

if [ -z "$alvo" ] || [ -z "$portas" ]; then
	echo "Endereço e portas são obrigatórios."
	exit 1
fi

echo "Iniciando varredura em $alvo..."

for porta in $portas; do
	nc -z -v -w 2 "$alvo" "$porta" >/dev/null 2>&1
	if [ $? -eq 0 ]; then
		echo "Porta $porta aberta"
	else
		echo "Porta $porta fechada ou filtrada"
	fi
done

echo "Varredura concluída."
