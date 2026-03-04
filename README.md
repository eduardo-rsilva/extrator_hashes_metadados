# Extrator de Hashes e Metadados (ERS-IC/SP-NIC) - v.4.1.1

## 📝 Descrição
**Ferramenta pericial** desenvolvida para agilizar a triagem inicial e análise de evidências digitais, além de permitir a **Aquisição Forense (Bit-a-bit)** de unidades lógicas e físicas. A ideia é ter um **"canivete suíço" offline e portátil** que faça o trabalho pesado de extração de dados de forma rápida, segura e em lote, bastando arrastar e soltar pastas ou arquivos na interface.

---

## 🛡️ Preservação e Análise de Integridade
A base da ferramenta é a geração simultânea de **múltiplos hashes** (CRC32, MD5, SHA-1, SHA-256, SHA-384, SHA-512). Para garantir a **cadeia de custódia** e a segurança forense durante a leitura, foi implementado um **File Lock** (via API do Windows): assim que o arquivo começa a ser lido, ele é travado contra qualquer tipo de modificação paralela. 

Além disso:
* Utiliza **"Seleção Literal" (Anti-Redirecionamento)**, ignorando resoluções nativas do Windows para links simbólicos e junções.
* O programa calcula a **Entropia de Shannon** de cada arquivo, ajudando a diferenciar arquivos comprimidos legítimos de dados ofuscados ou criptografados.
* Detecta automaticamente **"arquivos vazios"** baseando-se em hashes universais de 0 bytes.
* Na nova modalidade de aquisição de discos, o cálculo dos hashes selecionados ocorre simultaneamente à leitura setor-por-setor (**On-the-Fly**).

---

## 🌐 Isolamento de Nuvem e Triagem de Unidades e Aquisição RAW
Um diferencial crítico é o **bloqueio automático de arquivos "Apenas Online"** (OneDrive, Google Drive, etc.). A ferramenta detecta o atributo *Recall on Data Access* e impede a leitura desses arquivos para evitar downloads indesejados que alterariam a evidência local e o tráfego de rede. 

* **Triagem de Unidades:** Caso o usuário selecione a raiz de uma unidade (Pendrive ou HD), o programa extrai automaticamente o Rótulo (Label), o Serial do Volume e o Sistema de Arquivos (FS).
* **Proteção Anti-Thrashing (Hardware Lock):** O sistema mapeia em baixo nível a relação entre Volumes Lógicos e Discos Físicos reais. Impede ativamente que duas instâncias do programa realizem aquisições simultâneas no mesmo disco magnético ou SSD, prevenindo saturação severa de I/O e protegendo a vida útil da evidência física.
* **Aquisição RAW:** Funcionalidade de **Aquisição Bit-a-bit**, exigindo elevação de privilégios (UAC). É possível escolher entre a extração do **Disco Físico Inteiro** (MBR/GPT, espaço não alocado e partições ocultas) ou apenas do Volume Lógico.
* **Cópia Forense:** Durante essa extração, o sistema permite a geração simultânea de uma imagem **.dd**.

---

## 📸 Extração Profunda de Metadados Multimídia
Trabalhando em conjunto com o **ExifTool**, **OpenCV** e **Pillow**, a extração de mídia é agressiva:
* **Fotos e Vídeos:** Extrai resolução, FPS, fabricante/modelo, data de criação interna e **coordenadas GPS** formatadas com link direto para o Google Maps.
* **Análise de Redes Sociais:** Detecta padrões de nomes (WhatsApp, Telegram, Facebook) e emite um alerta pericial sobre o **metadata stripping** (lavagem de metadados).
* **Áudio:** Utiliza uma extração primária hiper-rápida (**TinyTag**) com fallback via ExifTool, obtendo duração exata, bitrate e artista.

---

## 📂 Análise de Artefatos do Windows, Documentos e Compactados
Para documentos (PDF e Office), extrai autoria, software criador e último usuário. Para o pacote Office atual (.docx, .xlsx, .pptx), o programa realiza a leitura direta da **estrutura XML interna** (docProps/core.xml).

### Artefatos de Sistema:
* **Executáveis (.exe, .dll, .sys):** Faz o parse do cabeçalho PE, extraindo a **data real de compilação (UTC)**, verifica assinatura digital (Authenticode) e varre tabelas de strings.
* **Atalhos (.lnk):** Extrai o caminho base local, o Rótulo do Volume, o Serial do disco de origem e o **MAC Address** da placa de rede.
* **E-mails (.eml, .msg):** Varre cabeçalhos em busca do primeiro servidor de trânsito para **rastreio de IP de origem**.
* **Fluxos Ocultos (ADS NTFS):** Varredura automática profunda por *Alternate Data Streams*. Identifica a **"Mark of the Web"** e IDs de Zona de download. Em fluxos longos ou binários ocultos (>= 50 KB), o script gera automaticamente os comandos nativos do PowerShell (`Get-Content`) para que o analista possa realizar a extração bruta e isolada do payload.

---

## ⚙️ Tratamento de Erros Transparente e Diagnóstico de Hardware
Se um arquivo estiver corrompido ou lavado, o programa avisa o motivo no relatório. Na extração RAW, conta com um tradutor de erros de baixo nível para transformar códigos do Windows em **diagnósticos forenses claros** (falhas de I/O, CRC ou violação de compartilhamento).

---

## ⏱️ Previsibilidade e UI Otimizada
Para lidar com extrações massivas (Terabytes de dados), a ferramenta foi redesenhada focando em eficiência operacional:
* **Compilação Nativa (Nuitka C++):** O núcleo da ferramenta é traduzido do Python para a linguagem C e compilado via MSVC. Essa otimização de baixo nível garante que **os tempos de processamento e extração de hashes sejam até 50% mais rápidos do que softwares periciais comerciais renomados, como o FTK Imager**, eliminando gargalos de CPU e maximizando a taxa de leitura (I/O).
* **Cronômetro e ETA Dinâmico:** Calcula com alta precisão o tempo restante e a taxa de leitura em bytes/s durante processos longos. Ao final, o tempo exato decorrido é formatado e registrado nativamente no Log de Auditoria.
* **Tolerância a Temas do S.O.:** A interface utiliza padrões universais com suporte total para rodar corretamente, seja no Modo Claro ou Escuro nativo do Windows 11.

---

## 💾 Persistência e Confiabilidade
* **Configurações:** Salva preferências do usuário de forma **criptografada**. 
* **Estabilidade:** Possui manipulador de exceções global que gera logs detalhados (**Crash Logs**). 
* **Transparência:** Software **Open Source**; permite a exportação do código-fonte em tempo real para auditoria e exibe sua própria assinatura digital (SHA-256). Adicionalmente, possui uma **Thread Assíncrona** que consulta a API do GitHub para alertar discretamente o usuário caso sua versão esteja obsoleta e insegura, sem comprometer a estabilidade (Air-gap safe).
* **Interface:** Aprimorada com um **Modo Administrador visual** (interface vermelha). As rotinas de cancelamento do RAW foram otimizadas a nível de CPU, reduzindo drasticamente as chamadas de verificação do disco.

> Tudo isso roda com barras de progresso, botão para copiar o relatório ou salvar em TXT.

---

## 🛠️ Instruções de Compilação e Ambiente (Para Desenvolvedores)

O executável oficial deste projeto é gerado utilizando o **Nuitka** com o compilador **MSVC** da Microsoft, visando estabilidade e redução drástica de falsos positivos (como o *Wacatac.C!ml*) comuns em empacotadores Python no Windows Defender.

### Pré-requisitos
- **Python:** Versão **3.12** (versões como a 3.13 podem causar instabilidade no backend em C gerado pelo Nuitka). 
- **Compilador C:** Microsoft Visual Studio Build Tools (MSVC v143 ou superior) e o Windows 11 SDK.

### Como compilar do zero
1. Crie e ative um ambiente virtual com o Python 3.12:
   ```cmd
   python3.12 -m venv venv
   venv\Scripts\activate

2. Instale as dependências atualizadas do projeto:
    ```cmd
   pip install -r requirements.txt

3. Utilize o script lançador para injetar o compilador MSVC e gerar o executável standalone:
   * Dê um duplo clique no arquivo compilar.bat (faça os ajustes necessários quanto aos caminhos do compilador MSVC e do ambiente virtual).
   * _Alternativamente:_ Abra o terminal "Developer Command Prompt for VS", ative a venv e rode:
     ```cmd
     python build.py

O Nuitka embutirá nativamente os metadados da instituição (ERS-IC/SP-NIC) na compilação, e a pasta final pronta para uso será gerada em src/extrator_hashes_metadados.dist. O uso da flag --standalone (em vez de --onefile) é intencional para evitar bloqueios heurísticos de antivírus.

---

**Feedback e sugestões de novas extensões e funcionalidades são super bem-vindos.**
