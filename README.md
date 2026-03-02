# Extrator de Hashes e Metadados (ERS-IC-NIC)

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
* **Fluxos Ocultos (ADS NTFS):** Varredura automática por Alternate Data Streams. Identifica a **"Mark of the Web"** e IDs de Zona de download.

---

## ⚙️ Tratamento de Erros Transparente e Diagnóstico de Hardware
Se um arquivo estiver corrompido ou lavado, o programa avisa o motivo no relatório. Na extração RAW, conta com um tradutor de erros de baixo nível para transformar códigos do Windows em **diagnósticos forenses claros** (falhas de I/O, CRC ou violação de compartilhamento).

---

## 💾 Persistência e Confiabilidade
* **Configurações:** Salva preferências do usuário de forma **criptografada**. 
* **Estabilidade:** Possui manipulador de exceções global que gera logs detalhados (**Crash Logs**). 
* **Transparência:** Software **Open Source**; permite a exportação do código-fonte em tempo real para auditoria e exibe sua própria assinatura digital (SHA-256). 
* **Interface:** Aprimorada com um **Modo Administrador visual** (interface vermelha) e rotinas de cancelamento seguro.

> Tudo isso roda com barras de progresso, botão para copiar o relatório ou salvar em TXT.

---

**Feedback e sugestões de novas extensões e funcionalidades são super bem-vindos.**