#!/bin/bash

echo "Scanner de portas com threads controladas"

read -p "Informe o endereço/IP do alvo: " alvo
read -p "Informe as portas separadas por espaço: " portas
read -p "Quantas portas verificar em paralelo (ex.: 5): " limite

if [ -z "$alvo" ] || [ -z "$portas" ]; then
	echo "Alvo e portas são obrigatórios."
	exit 1
fi

if ! [[ $limite =~ ^[0-9]+$ ]] || [ "$limite" -le 0 ]; then
	limite=5
	echo "Limite inválido. Usando valor padrão: $limite"
fi

tmp_open=$(mktemp)
trap 'rm -f "$tmp_open"' EXIT

scan_porta() {
	local host="$1"
	local porta="$2"

	if nc -z -w 2 "$host" "$porta" >/dev/null 2>&1; then
		echo "Porta $porta aberta"
		echo "$porta" >>"$tmp_open"
	else
		echo "Porta $porta fechada ou filtrada"
	fi
}

echo "Iniciando varredura em $alvo com até $limite portas simultâneas..."

for porta in $portas; do
	scan_porta "$alvo" "$porta" &

	while [ "$(jobs -rp | wc -l)" -ge "$limite" ]; do
		sleep 0.2
	done
done

wait

if [ -s "$tmp_open" ]; then
	echo "Portas abertas detectadas: $(sort -n "$tmp_open" | tr '\n' ' ' )"
else
	echo "Nenhuma porta aberta encontrada."
fi

echo "Varredura concluída."
