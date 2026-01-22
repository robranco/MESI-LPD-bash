#!/usr/bin/env bash

# Monitora logins falhados e executa varreduras de portas em paralelo com nc

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

echo "Informe o numero maximo de varreduras simultaneas (threads) [3]:"
read maximo_varreduras

if [ -z "$maximo_varreduras" ]; then
	maximo_varreduras=3
fi

case $maximo_varreduras in
	''|*[!0-9]*)
		echo "Preciso de um numero inteiro para as threads."
		exit 1
		;;
	0)
		echo "Preciso de pelo menos uma thread."
		exit 1
		;;
esac

portas_sugeridas="21,22,23,25,80,443,587,1433,3389"
echo "Informe as portas para varredura (ex: $portas_sugeridas ou intervalos como 21-25,80,443) [$portas_sugeridas]:"
read portas_informadas

if [ -z "$portas_informadas" ]; then
	portas_informadas="$portas_sugeridas"
fi

descricao_portas="$portas_informadas"
portas_sanitizadas=$(echo "$portas_informadas" | tr -d '[:space:]')

if [ -z "$portas_sanitizadas" ]; then
	echo "Nao recebi portas validas para varrer."
	exit 1
fi

IFS=',' read -ra entradas_portas <<< "$portas_sanitizadas"
declare -a portas_temporarias=()
declare -A mapa_portas_unicas=()

for entrada_porta in "${entradas_portas[@]}"; do
	[ -z "$entrada_porta" ] && continue
	if echo "$entrada_porta" | grep -Eq '^[0-9]+-[0-9]+$'; then
		inicio=${entrada_porta%-*}
		fim=${entrada_porta#*-}
		if [ "$inicio" -gt "$fim" ]; then
			echo "O inicio de um intervalo nao pode ser maior que o fim ($entrada_porta)."
			exit 1
		fi
		for porta in $(seq "$inicio" "$fim"); do
			if [ -z "${mapa_portas_unicas[$porta]}" ]; then
				mapa_portas_unicas[$porta]=1
				portas_temporarias+=("$porta")
			fi
		done
	elif echo "$entrada_porta" | grep -Eq '^[0-9]+$'; then
		porta="$entrada_porta"
		if [ -z "${mapa_portas_unicas[$porta]}" ]; then
			mapa_portas_unicas[$porta]=1
			portas_temporarias+=("$porta")
		fi
	else
		echo "Entrada invalida para portas: $entrada_porta"
		exit 1
	fi
done

if [ ${#portas_temporarias[@]} -eq 0 ]; then
	echo "Nao consegui construir a lista de portas."
	exit 1
fi

mapfile -t lista_portas < <(printf "%s\n" "${portas_temporarias[@]}" | sort -n)

if ! command -v nc >/dev/null 2>&1; then
	echo "Preciso do utilitario nc (netcat) instalado para executar as varreduras."
	exit 1
fi

timestamp_iso=$(date -u "+%Y-%m-%dT%H:%M:%S.%3NZ")
nome_base="$(basename "$arquivo")-${timestamp_iso}"
relatorio="relatorio_falhas-${nome_base}.txt"
pasta_varreduras=$(mktemp -d)
declare -A ips_processados=()
declare -a tarefas_ativas=()

imprimir_resumo_varreduras() {
	echo ""
	echo "Resumo das varreduras de portas:"
	set -- "$pasta_varreduras"/*.txt
	if [ ! -e "$1" ]; then
		echo "Nenhuma varredura foi concluida."
		return
	fi
	for arquivo_relatorio_portas in "$pasta_varreduras"/*.txt; do
		[ -e "$arquivo_relatorio_portas" ] || continue
		ip_resumo=$(basename "$arquivo_relatorio_portas" .txt)
		local portas
		if [ -s "$arquivo_relatorio_portas" ]; then
			portas=$(tr '\n' ' ' < "$arquivo_relatorio_portas" | sed 's/ $//')
			echo "$ip_resumo - portas abertas: $portas"
		else
			echo "$ip_resumo - nenhuma porta aberta detectada"
		fi
	done
}

atualizar_tarefas_ativas() {
	local atualizados=()
	for pid_atual in "${tarefas_ativas[@]}"; do
		if kill -0 "$pid_atual" 2>/dev/null; then
			atualizados+=("$pid_atual")
		fi
	done
	tarefas_ativas=("${atualizados[@]}")
}

aguardar_disponibilidade() {
	while :; do
		atualizar_tarefas_ativas
		if [ ${#tarefas_ativas[@]} -lt "$maximo_varreduras" ]; then
			break
		fi
		sleep 0.2
	done
}

varrer_ip() {
	local ip=$1
	local arquivo_saida="$pasta_varreduras/$ip.txt"
	: > "$arquivo_saida"
	for porta in "${lista_portas[@]}"; do
		if nc -z -w1 "$ip" "$porta" >/dev/null 2>&1; then
			echo "$porta" >> "$arquivo_saida"
		fi
	done
	if [ -s "$arquivo_saida" ]; then
		local portas=$(tr '\n' ' ' < "$arquivo_saida" | sed 's/ $//')
		echo "[varredura] $ip - portas abertas: $portas" | tee -a "$relatorio"
	else
		echo "[varredura] $ip - nenhuma porta aberta detectada" | tee -a "$relatorio"
	fi
}

iniciar_varredura() {
	local ip=$1
	aguardar_disponibilidade
	varrer_ip "$ip" &
	tarefas_ativas+=("$!")
}

finalizar_execucao() {
	local codigo_saida=$?
	trap - EXIT
	for pid_atual in "${tarefas_ativas[@]}"; do
		wait "$pid_atual" 2>/dev/null
	done
	local resumo
	resumo=$(imprimir_resumo_varreduras)
	printf "%s\n" "$resumo" | tee -a "$relatorio"
	rm -rf "$pasta_varreduras"
	exit "$codigo_saida"
}

tratar_interrupcao() {
	echo "Interrompendo monitoracao..."
	exit 0
}

trap finalizar_execucao EXIT
trap tratar_interrupcao INT TERM

echo "A monitorar $arquivo em tempo real. Pressione Ctrl+C para sair."

timestamp_inicio=$(date "+%Y-%m-%d %H:%M:%S")
echo "Monitoracao iniciada em $timestamp_inicio" > "$relatorio"

while IFS= read -r nova_linha; do
	atualizar_tarefas_ativas
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
	if [ -n "$ip_detectado" ] && [ -z "${ips_processados[$ip_detectado]}" ]; then
		ips_processados[$ip_detectado]=1
		mensagem_varredura="Inicio de varredura de portas para $ip_detectado (configuracao: $descricao_portas)"
		echo "[$carimbo_tempo] $mensagem_varredura"
		echo "[$carimbo_tempo] $mensagem_varredura" >> "$relatorio"
		iniciar_varredura "$ip_detectado"
	fi
done < <(tail -n0 -F "$arquivo")
