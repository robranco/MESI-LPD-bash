#!/bin/bash

# Script simples para análise básica de auth.log
# Todo o texto exibido ao utilizador está em Português do Brasil.

verificar_root() {
	if [[ $(id -u) -ne 0 ]]; then
		echo "Este script precisa ser executado com sudo ou como root." >&2
		exit 1
	fi
}

criar_pasta_sessao() {
	data_iso=$(date +"%Y-%m-%dT%H:%M:%S")
	pasta_sessao="$(pwd)/${data_iso}"
	mkdir -p "$pasta_sessao"
	ficheiro_log="${pasta_sessao}/$(basename "$0")-execution.log.txt"
	ficheiro_historico="${pasta_sessao}/historico_interacoes.txt"
	: > "$ficheiro_log"
	: > "$ficheiro_historico"
	exec > >(tee -a "$ficheiro_log") 2>&1
}

iniciar_variaveis() {
	inicio_programa=$(date +%s)
	programa_encerrado=0
	ficheiro_cache_falhas="${pasta_sessao}/ips_falhas_intervalo.csv"
	ficheiro_cache_logins="${pasta_sessao}/logins_sucesso.csv"
	ficheiro_registo="./auth.log"
	if [[ ! -f "$ficheiro_registo" && -f ./relatorio_falhas-auth.log.txt ]]; then
		ficheiro_registo="./relatorio_falhas-auth.log.txt"
	fi
	ultimo_timestamp_processado=0
	ano_base=$(date +%Y)
	agora_seg=$(date +%s)
}

registar_interacao() {
	mensagem="$1"
	printf "%s - %s\n" "$(date +"%Y-%m-%d %H:%M:%S")" "$mensagem" >> "$ficheiro_historico"
}

preparar_contexto_datas() {
	ultimo_timestamp_processado=0
	ano_base=$(date +%Y)
	agora_seg=$(date +%s)
}

obter_mes_numero() {
	mes_abrev="$1"
	mes_maiusculo=$(echo "$mes_abrev" | tr '[:lower:]' '[:upper:]')
	case "$mes_maiusculo" in
		JAN) echo "01" ;;
		FEB|FEV) echo "02" ;;
		MAR) echo "03" ;;
		APR|ABR) echo "04" ;;
		MAY|MAI) echo "05" ;;
		JUN) echo "06" ;;
		JUL) echo "07" ;;
		AUG|AGO) echo "08" ;;
		SEP|SET) echo "09" ;;
		OCT|OUT) echo "10" ;;
		NOV) echo "11" ;;
		DEC|DEZ) echo "12" ;;
		*) echo "" ;;
	esac
}

converter_para_epoch() {
	mes="$1"
	dia="$2"
	hora="$3"
	mes_num=$(obter_mes_numero "$mes")
	if [[ -z "$mes_num" ]]; then
		return
	fi
	local ano_candidato=$ano_base
	local timestamp
	timestamp=$(LC_ALL=C date -d "${ano_candidato}-${mes_num}-${dia} ${hora}" +%s 2>/dev/null)
	if [[ -z "$timestamp" ]]; then
		return
	fi
	if (( timestamp > agora_seg + 3600 )); then
		ano_candidato=$((ano_candidato-1))
		timestamp=$(LC_ALL=C date -d "${ano_candidato}-${mes_num}-${dia} ${hora}" +%s 2>/dev/null)
	fi
	if (( ultimo_timestamp_processado > 0 && timestamp < ultimo_timestamp_processado )); then
		ano_candidato=$((ano_candidato+1))
		timestamp=$(LC_ALL=C date -d "${ano_candidato}-${mes_num}-${dia} ${hora}" +%s 2>/dev/null)
	fi
	ultimo_timestamp_processado=$timestamp
	echo "$timestamp"
}

converter_epoch_para_legivel() {
	epoch_valor="$1"
	if [[ -z "$epoch_valor" ]]; then
		return
	fi
	LC_ALL=C date -d "@${epoch_valor}" +"%Y-%m-%d %H:%M:%S" 2>/dev/null
}

converter_data_simples_para_epoch() {
	mes_texto="$1"
	dia_texto="$2"
	hora_base="$3"
	ano_custom="$4"
	mes_num=$(obter_mes_numero "$mes_texto")
	if [[ -z "$mes_num" ]]; then
		return
	fi
	if [[ ! "$dia_texto" =~ ^[0-9]{1,2}$ ]]; then
		return
	fi
	dia_formatado=$(printf "%02d" "$dia_texto")
	ano_utilizado="${ano_custom:-$ano_base}"
	LC_ALL=C date -d "${ano_utilizado}-${mes_num}-${dia_formatado} ${hora_base}" +%s 2>/dev/null
}

solicitar_intervalo_tempo() {
	echo "Informe as datas utilizando a abreviação do mês em inglês (ex.: Feb 04)."
	read -r -p "Data inicial (MMM DD): " intervalo_inicio_texto
	read -r -p "Data final (MMM DD): " intervalo_fim_texto
	read -r mes_inicio dia_inicio <<< "$intervalo_inicio_texto"
	read -r mes_fim dia_fim <<< "$intervalo_fim_texto"
	intervalo_inicio_seg=$(converter_data_simples_para_epoch "$mes_inicio" "$dia_inicio" "00:00:00")
	intervalo_fim_seg=$(converter_data_simples_para_epoch "$mes_fim" "$dia_fim" "23:59:59")
	if [[ -z "$intervalo_inicio_seg" || -z "$intervalo_fim_seg" ]]; then
		echo "Intervalo inválido. Utilize entradas como 'Feb 04'."
		return 1
	fi
	if (( intervalo_fim_seg < intervalo_inicio_seg )); then
		echo "A data final precisa ser posterior à inicial."
		return 1
	fi
	return 0
}

coletar_falhas_intervalo() {
	inicio_seg="$1"
	fim_seg="$2"
	arquivo_saida="$3"
	declare -A contagens_ips
	declare -A primeiras_tentativas
	declare -A ultimas_tentativas
	preparar_contexto_datas
	while IFS=' ' read -r mes dia hora restante; do
		[[ -z "$mes" ]] && continue
		tempo_seg=$(converter_para_epoch "$mes" "$dia" "$hora")
		[[ -z "$tempo_seg" ]] && continue
		if (( tempo_seg < inicio_seg || tempo_seg > fim_seg )); then
			continue
		fi
		texto_linha="$mes $dia $hora $restante"
		if echo "$texto_linha" | grep -qi "Failed password\|authentication failure"; then
			ip=$(echo "$texto_linha" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1)
			[[ -z "$ip" ]] && ip="IP_nao_identificado"
			contagens_ips[$ip]=$((contagens_ips[$ip]+1))
			registro_legivel=$(converter_epoch_para_legivel "$tempo_seg")
			if [[ -z "${primeiras_tentativas[$ip]}" ]]; then
				primeiras_tentativas[$ip]="$registro_legivel"
			fi
			ultimas_tentativas[$ip]="$registro_legivel"
		fi
	done < "$ficheiro_registo"
	: > "$arquivo_saida"
	for ip in "${!contagens_ips[@]}"; do
		printf "%s;%s;%s;%s\n" "$ip" "${contagens_ips[$ip]}" "${primeiras_tentativas[$ip]}" "${ultimas_tentativas[$ip]}" >> "$arquivo_saida"
	done
}

listar_ips_falhas_simples() {
	if [[ ! -f "$ficheiro_registo" ]]; then
		echo "Ficheiro auth.log não encontrado na pasta atual."
		return
	fi
	if ! solicitar_intervalo_tempo; then
		return
	fi
	registar_interacao "Executou 1.1 com intervalo $intervalo_inicio_texto até $intervalo_fim_texto"
	coletar_falhas_intervalo "$intervalo_inicio_seg" "$intervalo_fim_seg" "$ficheiro_cache_falhas"
	if [[ ! -s "$ficheiro_cache_falhas" ]]; then
		echo "Nenhuma tentativa falhada encontrada no intervalo informado."
		return
	fi
	echo "IPs e tentativas falhadas no intervalo:"
	printf "%-20s | %-10s\n" "Endereço IP" "Tentativas"
	printf -- "---------------------+-----------\n"
	while IFS=';' read -r ip total primeira ultima; do
		printf "%-20s | %-10s\n" "$ip" "$total"
	done < "$ficheiro_cache_falhas"
}

listar_ips_falhas_detalhado() {
	if [[ ! -f "$ficheiro_registo" ]]; then
		echo "Ficheiro auth.log não encontrado na pasta atual."
		return
	fi
	if ! solicitar_intervalo_tempo; then
		return
	fi
	registar_interacao "Executou 1.2 com intervalo $intervalo_inicio_texto até $intervalo_fim_texto"
	coletar_falhas_intervalo "$intervalo_inicio_seg" "$intervalo_fim_seg" "$ficheiro_cache_falhas"
	if [[ ! -s "$ficheiro_cache_falhas" ]]; then
		echo "Nenhum registo encontrado para o período."
		return
	fi
	echo "IPs, tentativas, primeira e última ocorrência:"
	printf "%-20s | %-10s | %-20s | %-20s\n" "IP" "Tentativas" "Primeira" "Última"
	printf -- "---------------------+-----------+----------------------+----------------------\n"
	while IFS=';' read -r ip total primeira ultima; do
		printf "%-20s | %-10s | %-20s | %-20s\n" "$ip" "$total" "$primeira" "$ultima"
	done < "$ficheiro_cache_falhas"
}

coletar_logins_sucesso() {
	: > "$ficheiro_cache_logins"
	declare -a login_usuario
	declare -a login_ip
	declare -a login_inicio
	declare -a login_fim
	declare -a login_inicio_epoch
	declare -a login_fim_epoch
	total_logins=0
	preparar_contexto_datas
	while IFS=' ' read -r mes dia hora restante; do
		[[ -z "$mes" ]] && continue
		tempo_epoch=$(converter_para_epoch "$mes" "$dia" "$hora")
		[[ -z "$tempo_epoch" ]] && continue
		tempo_legivel=$(converter_epoch_para_legivel "$tempo_epoch")
		linha="$mes $dia $hora $restante"
		if echo "$linha" | grep -q "Accepted password for"; then
			if [[ $linha =~ Accepted\ password\ for\ ([^[:space:]]+)\ from\ ([0-9.]+) ]]; then
				usuario="${BASH_REMATCH[1]}"
				ip_sucesso="${BASH_REMATCH[2]}"
				login_usuario[$total_logins]="$usuario"
				login_ip[$total_logins]="$ip_sucesso"
				login_inicio[$total_logins]="$tempo_legivel"
				login_inicio_epoch[$total_logins]="$tempo_epoch"
				login_fim[$total_logins]="Sem logout"
				login_fim_epoch[$total_logins]=""
				total_logins=$((total_logins+1))
			fi
		elif echo "$linha" | grep -q "session closed for user"; then
			if [[ $linha =~ session\ closed\ for\ user\ ([^[:space:]]+) ]]; then
				usuario_saida="${BASH_REMATCH[1]}"
				for ((i=0; i<total_logins; i++)); do
					if [[ "${login_usuario[$i]}" == "$usuario_saida" && "${login_fim[$i]}" == "Sem logout" ]]; then
						login_fim[$i]="$tempo_legivel"
						login_fim_epoch[$i]="$tempo_epoch"
						break
					fi
				done
			fi
		fi
	done < "$ficheiro_registo"
	if (( total_logins == 0 )); then
		return 1
	fi
	for ((i=0; i<total_logins; i++)); do
		printf "%s;%s;%s;%s;%s;%s\n" \
			"${login_usuario[$i]}" "${login_ip[$i]}" "${login_inicio[$i]}" "${login_fim[$i]}" \
			"${login_inicio_epoch[$i]}" "${login_fim_epoch[$i]}" >> "$ficheiro_cache_logins"
	done
	return 0
}

mostrar_logins_sucesso() {
	if [[ ! -f "$ficheiro_registo" ]]; then
		echo "Ficheiro auth.log indisponível."
		return
	fi
	registar_interacao "Executou 1.3"
	if ! coletar_logins_sucesso; then
		echo "Nenhum login com sucesso foi encontrado."
		return
	fi
	printf "%-15s | %-15s | %-20s | %-20s\n" "Usuário" "IP" "Login" "Logout"
	printf -- "----------------+----------------+----------------------+----------------------\n"
	while IFS=';' read -r usuario ip login logout inicio_epoch fim_epoch; do
		printf "%-15s | %-15s | %-20s | %-20s\n" "$usuario" "$ip" "$login" "$logout"
	done < "$ficheiro_cache_logins"
}

mostrar_logins_com_falhas() {
	if [[ ! -f "$ficheiro_registo" ]]; then
		echo "Ficheiro auth.log indisponível."
		return
	fi
	registar_interacao "Executou 1.4"
	if ! coletar_logins_sucesso; then
		echo "Não existem logins bem-sucedidos para relacionar."
		return
	fi
	declare -A falhas_por_usuario
	while IFS= read -r linha; do
		if [[ $linha =~ Failed\ password\ for\ (invalid\ user\ )?([^[:space:]]+)\ from\ ([0-9.]+) ]]; then
			usuario_falha="${BASH_REMATCH[2]}"
			ip_falha="${BASH_REMATCH[3]}"
			falhas_por_usuario[$usuario_falha]+="$ip_falha "
		fi
	done < "$ficheiro_registo"
	while IFS=';' read -r usuario ip login logout inicio_epoch fim_epoch; do
		printf "Usuário: %s | IP sucesso: %s | Login: %s | Logout: %s\n" "$usuario" "$ip" "$login" "$logout"
		if [[ -n "${falhas_por_usuario[$usuario]}" ]]; then
			printf "IPs com falha para %s: %s\n" "$usuario" "${falhas_por_usuario[$usuario]}"
		else
			echo "Sem falhas registadas para este usuário."
		fi
		echo "---------------------------------------------"
	done < "$ficheiro_cache_logins"
}

executar_portscan_ip() {
	endereco="$1"
	ficheiro_saida="${pasta_sessao}/${endereco}.txt"
	agora=$(date +%s)
	if [[ -f "$ficheiro_saida" ]]; then
		ultima_mod=$(date -r "$ficheiro_saida" +%s)
		if (( agora - ultima_mod < 36000 )); then
			echo "Scan para $endereco já foi feito há menos de 10 horas."
			return
		fi
	fi
	echo "Iniciando port scan básico no IP $endereco (portas 22,80,443,3389)."
	nc -zv -w 2 "$endereco" 22 80 443 3389 2>&1 | tee "$ficheiro_saida"
	echo "Scan finalizado para $endereco."
}

portscan_ips_falhos() {
	if [[ ! -s "$ficheiro_cache_falhas" ]]; then
		echo "Nenhum IP carregado. Execute primeiro a opção 1.1 ou 1.2."
		return
	fi
	if ! command -v nc >/dev/null 2>&1; then
		echo "netcat (nc) não está instalado no sistema."
		return
	fi
	registar_interacao "Executou 2.1"
	mapa_ips=()
	while IFS=';' read -r ip total primeira ultima; do
		[[ -z "$ip" ]] && continue
		mapa_ips+=("$ip")
	done < "$ficheiro_cache_falhas"
	if [[ ${#mapa_ips[@]} -eq 0 ]]; then
		echo "Nenhum IP disponível para scan."
		return
	fi
	limite_threads=3
	pids=()
	for endereco in "${mapa_ips[@]}"; do
		executar_portscan_ip "$endereco" &
		pids+=("$!")
		if (( ${#pids[@]} >= limite_threads )); then
			wait "${pids[0]}"
			pids=("${pids[@]:1}")
		fi
	done
	for pid in "${pids[@]}"; do
		wait "$pid"
	done
	echo "Port scans concluídos. Resultados guardados na pasta da sessão."
}

listar_ficheiros_alterados() {
	if [[ ! -s "$ficheiro_cache_logins" ]]; then
		echo "Sem informações de sessão. Execute a opção 1.3 primeiro."
		return
	fi
	registar_interacao "Executou 2.2"
	contador=1
	declare -a linhas_guardadas
	while IFS= read -r linha; do
		linhas_guardadas[$contador]="$linha"
		IFS=';' read -r usuario ip login logout inicio_epoch fim_epoch <<< "$linha"
		printf "%d - Usuário: %s | Login: %s | Logout: %s\n" "$contador" "$usuario" "$login" "$logout"
		contador=$((contador+1))
	done < "$ficheiro_cache_logins"
	read -r -p "Escolha o número da sessão para analisar: " escolha
	if [[ -z "${linhas_guardadas[$escolha]}" ]]; then
		echo "Opção inválida."
		return
	fi
	IFS=';' read -r usuario ip login logout inicio_epoch fim_epoch <<< "${linhas_guardadas[$escolha]}"
	if [[ -z "$inicio_epoch" ]]; then
		echo "Não foi possível determinar o horário da sessão."
		return
	fi
	if [[ -z "$fim_epoch" ]]; then
		fim_epoch=$(date +%s)
		logout="Sessão ainda ativa"
	fi
	read -r -p "Informe o diretório base para procurar alterações (padrão /): " diretorio_base
	[[ -z "$diretorio_base" ]] && diretorio_base="/"
	ficheiro_relatorio="${pasta_sessao}/alteracoes_${usuario}_$(date +%s).txt"
	echo "Gerando lista de ficheiros alterados entre $login e $logout..."
	find "$diretorio_base" -type f -newermt "@$inicio_epoch" ! -newermt "@$fim_epoch" -printf "%TY-%Tm-%Td %TH:%TM:%TS | %p\n" 2>/dev/null | tee "$ficheiro_relatorio"
	echo "Relatório salvo em $ficheiro_relatorio"
}

formatar_duracao() {
	segundos=$1
	horas=$((segundos/3600))
	minutos=$(((segundos%3600)/60))
	segundos=$((segundos%60))
	printf "%02d:%02d:%02d" "$horas" "$minutos" "$segundos"
}

encerrar_programa() {
	if (( programa_encerrado == 1 )); then
		exit 0
	fi
	programa_encerrado=1
	fim_programa=$(date +%s)
	duracao_total=$((fim_programa - inicio_programa))
	tempo_legivel=$(formatar_duracao "$duracao_total")
	clear
	echo "Tempo total de execução: $tempo_legivel"
	echo "Atividades registradas na sessão:"
	if [[ -s "$ficheiro_historico" ]]; then
		cat "$ficheiro_historico"
	else
		echo "Nenhuma interação foi registada."
	fi
	echo "Até breve."
	exit 0
}

mostrar_menu() {
	COR_RESET=$'\033[0m'
	COR_TITULO1=$'\033[1;36m'
	COR_OPCAO1=$'\033[0;36m'
	COR_TITULO2=$'\033[1;33m'
	COR_OPCAO2=$'\033[0;33m'
	COR_TITULO3=$'\033[1;35m'
	COR_OPCAO3=$'\033[0;35m'
	echo "=============================================="
	printf "%s1. DETEÇÃO DE INTRUSOS%s\n" "$COR_TITULO1" "$COR_RESET"
	printf "%s1.1 - Listar IPs login falhados em um intervalo de tempo%s\n" "$COR_OPCAO1" "$COR_RESET"
	printf "%s1.2 - Listar IPs login falhados em um intervalo de tempo, primeira e ultima tentativa%s\n" "$COR_OPCAO1" "$COR_RESET"
	printf "%s1.3 - Identificar logins feitos com sucesso, listar IP, utilizador, data e hora do evento (login ou logout)%s\n" "$COR_OPCAO1" "$COR_RESET"
	printf "%s1.4 - Identificar logins sucesso ou falha, listar IP, utilizador, data e hora do evento (login ou logout)%s\n" "$COR_OPCAO1" "$COR_RESET"
	echo "----------------------------------------------"
	printf "%s2 - ANALISE REATIVA%s\n" "$COR_TITULO2" "$COR_RESET"
	printf "%s2.1 - Port Scan IPs com eventos falhados%s\n" "$COR_OPCAO2" "$COR_RESET"
	printf "%s2.2 - Listar ficheiros alterados relacionados com login com sucesso%s\n" "$COR_OPCAO2" "$COR_RESET"
	echo "----------------------------------------------"
	printf "%s3 - SAIR%s\n" "$COR_TITULO3" "$COR_RESET"
	printf "%s3.1 - SAIR%s\n" "$COR_OPCAO3" "$COR_RESET"
	echo "Q - Quit / Sair"
	echo "=============================================="
}

pausa_usuario() {
	read -r -p "Pressione ENTER para voltar ao menu..." _
}

loop_menu() {
	while true; do
		clear
		mostrar_menu
		read -r -p "Escolha uma opção: " escolha_menu
		case "$escolha_menu" in
			"1.1") listar_ips_falhas_simples; pausa_usuario ;;
			"1.2") listar_ips_falhas_detalhado; pausa_usuario ;;
			"1.3") mostrar_logins_sucesso; pausa_usuario ;;
			"1.4") mostrar_logins_com_falhas; pausa_usuario ;;
			"2.1") portscan_ips_falhos; pausa_usuario ;;
			"2.2") listar_ficheiros_alterados; pausa_usuario ;;
			"3"|"3.1"|"Q"|"q"|"S"|"s") encerrar_programa ;;
			*) echo "Opção inválida."; pausa_usuario ;;
		esac
	done
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
	verificar_root
	criar_pasta_sessao
	iniciar_variaveis
	trap encerrar_programa INT TERM
	loop_menu
fi
