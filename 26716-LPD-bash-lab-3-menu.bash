#!/usr/bin/env bash

set -euo pipefail

default_log="/var/log/auth.log"
log_file="$default_log"
raiz_scripts="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mostrar_cabecalho() {
	echo -e "\033[1;34m"
	if command -v figlet >/dev/null 2>&1; then
		figlet "MESI 25/26"
	else
		echo "MESI 25/26"
	fi
	echo -e "\033[0m"
}

mostrar_menu() {
	mostrar_cabecalho
	echo "Menu de Scripts para Analise de Logs"
	echo "-------------------------------------"
	echo "Log atual: $log_file"
	echo ""
	echo "1) Executar 26716-LPD-bash-falhas_login_1.bash"
	echo "2) Executar 26716-LPD-bash-falhas_login_2.bash"
	echo "3) Executar 26716-LPD-bash-falhas_login_3.bash"
	echo "4) Executar 26716-LPD-bash-falhas_login_4.bash"
	echo "5) Executar 26716-LPD-bash-falhas_login_5.bash"
	echo "6) Executar 26716-LPD-bash-ficheiros_alterados.bash"
	echo "L) Trocar arquivo de log"
	echo -en "\033[1;31m"
	echo "Q) Sair"
	echo -e "\033[0m"
	echo
}

validar_arquivo_log() {
	if [ ! -f "$log_file" ]; then
		echo "Erro: o arquivo de log informado ($log_file) nao existe."
		return 1
	fi
	return 0
}

trocar_arquivo_log() {
	echo "Informe o caminho completo do novo arquivo de log (Enter para padrao: $default_log):"
	read -r novo_log
	if [ -z "$novo_log" ]; then
		novo_log="$default_log"
	fi
	log_file="$novo_log"
	if ! validar_arquivo_log; then
		echo "Mantendo o arquivo anterior."
		log_file="$default_log"
	fi
}

executar_script() {
	local script_rel="$1"
	local script_completo="$raiz_scripts/$script_rel"
	if [ ! -f "$script_completo" ]; then
		echo "Nao encontrei o script $script_rel"
		return
	fi
	if ! validar_arquivo_log; then
		return
	fi
	echo "\n==> Executando $script_rel com log $log_file"
	if [ -x "$script_completo" ]; then
		"$script_completo" "$log_file"
	else
		bash "$script_completo" "$log_file"
	fi
	echo "\n<== Execucao de $script_rel concluida"
}

while true; do
	mostrar_menu
	echo -n "Escolha uma opcao: "
	read -r opcao
	case ${opcao^^} in
		1)
			executar_script "26716-LPD-bash-falhas_login_1.bash"
			;;
		2)
			executar_script "26716-LPD-bash-falhas_login_2.bash"
			;;
		3)
			executar_script "26716-LPD-bash-falhas_login_3.bash"
			;;
		4)
			executar_script "26716-LPD-bash-falhas_login_4.bash"
			;;
		5)
			executar_script "26716-LPD-bash-falhas_login_5.bash"
			;;
		6)
			executar_script "26716-LPD-bash-ficheiros_alterados.bash"
			;;
		L)
			trocar_arquivo_log
			;;
		Q)
			echo "Saindo..."
			exit 0
			;;
		*)
			echo "Opcao invalida. Tente novamente."
			;;
	esac
	done
