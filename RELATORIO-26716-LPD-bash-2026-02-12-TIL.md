# Relatório do Script 26716-LPD-bash-2026-02-12-TIL

Este documento reúne a lógica aplicada, as principais decisões de implementação, as dificuldades encontradas e a lista de evidências solicitadas. O conteúdo pode ser convertido para PDF (por exemplo, usando `pandoc RELATORIO-26716-LPD-bash-2026-02-12-TIL.md -o RELATORIO-26716-LPD-bash-2026-02-12-TIL.pdf`).

## 1. Contexto do Desenvolvimento

- **Objetivo:** criar um menu interativo em Bash para analisar o ficheiro `auth.log`, executar ações reativas e gerar registos detalhados numa pasta de sessão com timestamp ISO 8601.
- **Restrições:** código simples (nível iniciante), uso de Português do Brasil para todas as interações, necessidade de sudo/root, gravação simultânea em ecrã e ficheiro via `tee`.
- **Arquivos relevantes:**
  - `26716-LPD-bash-2026-02-12-TIL.bash` (script principal)
  - `auth.log` (fonte dos eventos)
  - `relatorio_falhas-auth.log.txt` (fonte alternativa quando `auth.log` não existe)

## 2. Estrutura Geral do Script

1. **Preparação e segurança**
   - `verificar_root`: garante execução como root.
   - `criar_pasta_sessao`: cria pasta `YYYY-MM-DDTHH:MM:SS` e redireciona stdout/stderr para `<script>-execution.log.txt` com `tee`.
   - `iniciar_variaveis`: define ficheiros de cache e controla o tempo total da sessão.

2. **Gestão de datas sem ano no auth.log**
   - `preparar_contexto_datas`, `obter_mes_numero`, `converter_para_epoch` e `converter_epoch_para_legivel` reconstroem os timestamps corretos (inclusive em mudanças de ano) a partir das abreviações de mês.
   - `converter_data_simples_para_epoch` interpreta as entradas do utilizador no formato `MMM DD`.

3. **Funções da secção 1 – Deteção de Intrusos**
   - `coletar_falhas_intervalo`: filtra tentativas falhadas por intervalo escolhido no formato `MMM DD`.
   - `listar_ips_falhas_simples` (opção 1.1) e `listar_ips_falhas_detalhado` (1.2) usam o cache `ips_falhas_intervalo.csv` para acelerar consultas posteriores.
   - `coletar_logins_sucesso`: regista logins Aceitos e sessões abertas/fechadas.
   - `mostrar_logins_sucesso` (1.3) e `mostrar_logins_com_falhas` (1.4) produzem relatórios com IP, utilizador e relação com tentativas falhadas do mesmo username.

4. **Funções da secção 2 – Análise Reativa**
   - `portscan_ips_falhos` (2.1): reutiliza o cache de falhas, controla scans com `nc` e impede repetições com menos de 10 horas. Os resultados vão para `<pasta_sessao>/<IP>.txt`.
   - `listar_ficheiros_alterados` (2.2): permite escolher uma sessão gravada, define intervalo de `find` e salva o relatório em `alteracoes_<user>_<timestamp>.txt`.

5. **Secção 3 – Saída**
   - `encerrar_programa`: limpa o ecrã, mostra o tempo total em `HH:MM:SS` e imprime o histórico guardado em `historico_interacoes.txt`.
   - `trap INT TERM` garante encerramento limpo mesmo com CTRL+C.

## 3. Dificuldades e Soluções

| Desafio | Estratégia aplicada |
| --- | --- |
| **Ausência de ano nas entradas do auth.log** | Implementadas funções para inferir o ano correto, considerando ordem cronológica, ajuste futuro/prévio e suporte a abreviações PT/EN. |
| **Entrada amigável para iniciantes** | O menu solicita apenas mês/dia (ex.: `Feb 04`), enquanto as horas continuam a ser calculadas a partir do log. |
| **Sincronizar visualização e registo** | `tee` é configurado logo no início para captar todas as saídas, evitando código duplicado. |
| **Evitar scans redundantes** | Verificação de `mtime` nos ficheiros de resultados garante intervalo mínimo de 10 horas por IP. |
| **Manter simplicidade** | Comentários curtos explicam blocos mais complexos; todas as mensagens ao utilizador estão em Português do Brasil. |

## 4. Evidências de Funcionamento (printscreens sugeridos)

> Substitua os placeholders abaixo por capturas reais antes de exportar para PDF.

1. **Menu principal** – destaque para as cores e a organização das secções.  
   ![Menu principal](./evidencias/menu_principal.png)
2. **Opção 1.1** – mostrar tabela com IP e contagem dentro de um intervalo `Feb 04`–`Feb 08`.  
   ![Opção 1.1](./evidencias/opcao_11.png)
3. **Opção 1.2** – destacar primeiras/últimas tentativas.  
   ![Opção 1.2](./evidencias/opcao_12.png)
4. **Opção 1.3** – listar logins com sucesso e horários.  
   ![Opção 1.3](./evidencias/opcao_13.png)
5. **Opção 1.4** – evidenciar correlação entre logins e falhas por utilizador.  
   ![Opção 1.4](./evidencias/opcao_14.png)
6. **Opção 2.1** – screenshot do port scan em execução e ficheiros gerados.  
   ![Opção 2.1](./evidencias/opcao_21.png)
7. **Opção 2.2** – relatório de ficheiros alterados.  
   ![Opção 2.2](./evidencias/opcao_22.png)
8. **Saída (3.1)** – ecrã final com tempo total e histórico.  
   ![Opção 3.1](./evidencias/opcao_31.png)

> Nota: utilize a pasta criada automaticamente pelo script (por exemplo, `2026-02-12T14:05:21/`) para guardar os ficheiros de log e para capturar os printscreens, garantindo rastreabilidade completa.

## 5. Passos para Geração do PDF

1. Atualizar as capturas de ecrã apontadas na secção anterior.  
2. Validar ortografia e datas nos textos.  
3. Converter para PDF com a ferramenta de preferência. Exemplo usando Pandoc:
   ```bash
   pandoc RELATORIO-26716-LPD-bash-2026-02-12-TIL.md \
     -o RELATORIO-26716-LPD-bash-2026-02-12-TIL.pdf \
     --from markdown --template eisvogel
   ```
4. Verificar se as fontes, cabeçalho e paginação estão de acordo com o formato solicitado (caso exista template institucional).

---

**Conclusão:** o script atende aos requisitos funcionais (menu interativo, análise de intrusões, ações reativas e encerramento com resumo). O relatório acima consolida o raciocínio utilizado, descreve os desafios enfrentados e orienta a coleta de evidências necessárias para a entrega final em PDF.
