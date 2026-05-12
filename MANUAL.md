# 📖 Guia de Operação - Extrator de Hashes e Metadados Forenses

Este manual orienta o usuário sobre como utilizar as funcionalidades da ferramenta para garantir a integridade e a profundidade da análise pericial.

---

## 1. Processamento de Arquivos e Pastas
A forma mais rápida de utilizar o programa é através da técnica de "arrastar e soltar" (Drag & Drop).

* **Configuração:** Selecione os algoritmos de hash desejados no painel superior (SHA-256 e SHA-512 são recomendados e vêm marcados por padrão).
* **Ação:** Arraste seus arquivos ou diretórios para qualquer área da janela principal.
* **Segurança:** O software aplicará automaticamente o **File Lock** para impedir que outros processos alterem o arquivo enquanto o hash é calculado.

    <figure>
      <img src="imgs/config_drag_drop.PNG" alt="Interface principal destacando a área de seleção de configurações e a área para drag-and-drop de arquivos a serem analisados" style="border: 1px solid black;" width="100%">
      <figcaption align="center"><i>Interface principal destacando a área de seleção de configurações e a área para drag-and-drop de arquivos a serem analisados</i></figcaption>
    </figure>

<br>

---


## 2. Aquisição Forense e Hash RAW (Bit-a-Bit)
Para processar mídias físicas ou volumes lógicos em baixo nível, utilize o módulo RAW.

1.  **Acesso:** Clique em **Selecionar Unidade (RAW)**.

    <figure>
      <img src="imgs/seletor_unidade.PNG" alt="Seletor de Unidade" style="border: 1px solid black;" width="100%">
      <figcaption align="center"><i>Seletor de Unidade</i></figcaption>
    </figure>

<br>

2.  **Elevação de Privilégio:** O sistema solicitará acesso de Administrador (UAC) para interagir diretamente com o hardware.

    <figure>
      <img src="imgs/elevacao_UAC.PNG" alt="Mensagem solicitando elevação de administrador (UAC)" style="border: 1px solid black;" width="100%">
      <figcaption align="center"><i>Mensagem solicitando elevação de administrador (UAC)</i></figcaption>
    </figure>

<br>

3.  **Metodologia:** Escolha entre **Disco Físico Inteiro** (captura MBR/GPT e espaço não alocado) ou apenas o **Volume Lógico**.

    <figure>
      <img src="imgs/seletor_tipo_extracao.PNG" alt="Seletor do tipo de extração." style="border: 1px solid black;" width="100%">
      <figcaption align="center"><i>Seletor do tipo de extração.</i></figcaption>
    </figure>

<br>

4.  **Imagem Forense:** Você pode optar por gerar simultaneamente uma imagem no formato **.dd** e um log de auditoria física.

    <figure>
      <img src="imgs/hash_com_imagem.PNG" alt="Seletor para aquisição simultânea de cópia bit-bit-bit." style="border: 1px solid black;" width="100%">
      <figcaption align="center"><i>Seletor para aquisição simultânea de cópia bit-bit-bit.</i></figcaption>
    </figure>

    <br>

    <figure>
      <img src="imgs/tela_modo_admin.PNG" alt="Quando o modo administrador está ativado, há um demarcador visual para isso: interface gráfica na cor vermelha." style="border: 1px solid black;" width="100%">
      <figcaption align="center"><i>Quando o modo administrador está ativado, há um demarcador visual para isso: interface gráfica na cor vermelha.</i></figcaption>
    </figure>

<br>

---

## 3. Validação da Cadeia de Custódia
O extrator permite auditar listagens de hashes recebidas em laudos de terceiros ou documentos de custódia.

* **Como operar:** Arraste o arquivo de referência (PDF, DOCX, XLSX ou TXT) para a caixa superior "Validar Cadeia de Custódia".
* **Análise Reversa:** O software buscará automaticamente no texto o hash do arquivo que está sendo processado, ignorando artefatos de formatação e espaços invisíveis.
* **Resultado:** O log indicará **✅ CONFERE** ou emitirá alertas se o hash bater mas o nome do arquivo for divergente.

    <figure>
      <img src="imgs/validacao_cadeia_custodia.PNG" alt="Neste exemplo hipotético, o requisitante do exame enviou o arquivo 'hash_delegacia.txt' que foi arrastado e soltado na região 'Validação Cadeia de Custódia'. A extração do hash do arquivo teste.pdf foi comparada automaticamente com a referência recebida." style="border: 1px solid black;" width="100%">
      <figcaption align="center"><i>Neste exemplo hipotético, o requisitante do exame enviou o arquivo 'hash_delegacia.txt' que foi arrastado e soltado na região 'Validação Cadeia de Custódia'. A extração do hash do arquivo teste.pdf foi comparada automaticamente com a referência recebida.</i></figcaption>
    </figure>

<br>

---
    
## 4. Analisando Metadados e Alertas Periciais
Ao marcar a opção "Incluir Metadados Básicos", o programa realiza uma extração profunda através de diversas bibliotecas forenses:

* **Multimídia:** Coordenadas GPS (com link para mapas), marcas de câmeras e análise avançada de FPS (taxa de quadros) em vídeos.
* **ADS (NTFS):** O programa alerta sobre dados ocultos em fluxos de dados alternativos e fornece comandos PowerShell prontos para extração de payloads.
* **Redes Sociais:** Identifica se o arquivo foi "lavado" (*metadata stripping*) por plataformas como WhatsApp, Telegram ou Facebook.
* **Entropia:** Valores de Entropia de Shannon acima de 7.9 indicam alta probabilidade de criptografia ou arquivos *packed*.

---

## 5. Finalização e Relatórios
Ao término do processamento, revise o resumo final para consolidar a perícia:

* **Arquivos Duplicados:** O programa agrupa automaticamente arquivos idênticos baseando-se no cruzamento de hashes criptográficos.
* **Exportação:** Clique em **Salvar Relatório em TXT** para arquivar os resultados. O tempo exato de execução e o ETA são registrados no log.
* **Auditoria:** O relatório inclui a assinatura SHA-256 do código-fonte utilizado, garantindo a transparência do algoritmo.
