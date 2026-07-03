# Extrator de Hashes e Metadados (ERS-IC/SP-NIC) - v.4.6.1

🚀 **[CLIQUE AQUI PARA BAIXAR A VERSÃO MAIS RECENTE (v.4.6.1)](https://github.com/eduardo-rsilva/extrator_hashes_metadados/releases/download/v.4.6.1/Extrator_ERS-IC-SP-NIC_v4.6.1.zip)**

![Downloads Totais](https://img.shields.io/github/downloads/eduardo-rsilva/extrator_hashes_metadados/total?style=for-the-badge&color=blue&label=TOTAL%20DE%20DOWNLOADS)

> 💡 **Dúvidas de operação?** Acesse o [**Manual do Usuário (MANUAL.md)**](./MANUAL.md) para instruções com capturas de tela.

## 📝 Descrição
**Ferramenta pericial** desenvolvida para agilizar a triagem inicial e análise de evidências digitais, além de permitir a **Aquisição Forense (Bit-a-bit)** de unidades lógicas e físicas. A ideia é ter um **"canivete suíço" offline e portátil** que faça o trabalho pesado de extração de dados de forma rápida, segura e em lote, bastando arrastar e soltar pastas ou arquivos na interface.

---

## 🛡️ Preservação e Análise de Integridade
A base da ferramenta é a geração simultânea de **múltiplos hashes** (CRC32, MD5, SHA-1, SHA-256, SHA-384, SHA-512). Para garantir a **cadeia de custódia** e a segurança forense durante a leitura, foi implementado um **File Lock** (via API do Windows): assim que o arquivo começa a ser lido, ele é travado contra qualquer tipo de modificação paralela. 

Além disso:
* Utiliza **"Seleção Literal" (Anti-Redirecionamento)**, ignorando resoluções nativas do Windows para links simbólicos e junções.
* O programa calcula a **Entropia de Shannon** de cada arquivo, ajudando a diferenciar arquivos comprimidos legítimos de dados ofuscados ou criptografados.
* Detecta automaticamente **"arquivos vazios"** baseando-se em hashes universais de 0 bytes.
* **Detecção de Arquivos Duplicados (Triagem Otimizada):** Identifica e agrupa automaticamente arquivos idênticos processados no mesmo lote. A verificação prioriza a combinação de todos os algoritmos criptográficos selecionados (SHA-256, SHA-512, MD5, etc.). O CRC32 é utilizado como critério de comparação apenas em último caso (na ausência da seleção de hashes criptográficos), visando mitigar o risco de falsos positivos por colisão e garantir maior rigor técnico à triagem.
* Na nova modalidade de aquisição de discos, o cálculo dos hashes selecionados ocorre simultaneamente à leitura setor-por-setor (**On-the-Fly**).

---

## 🔗 Validação Automática da Cadeia de Custódia
* **Conferência de Listagens de Hashes:** Permite o *Drag & Drop* (arrastar e soltar) de laudos e listagens de hashes de origem (nos formatos PDF, DOCX, XLSX, TXT) ou inserção de texto livre, para auditar a extração feita pelo responsável pela coleta original dos dados e preservar intacta a Cadeia de Custódia.
* **Limpeza Forense de Texto:** Motor de extração blindado contra sujeiras de formatação e artefatos visuais de PDFs (como espaços invisíveis e quebras de linha fantasmas), garantindo a leitura exata do nome e do hash.
* **Busca Heurística Inteligente:** O algoritmo rastreia o texto (na mesma linha ou em linhas anteriores) para associar o hash ao nome correto do arquivo. Exclusivamente para laudos em PDF, a ferramenta aciona uma busca bidirecional (progressiva) para compensar quebras irregulares de página, sempre utilizando "barreiras de algoritmo" para evitar falsos positivos.
* **Rastreabilidade (A Prova da Prova):** Ao arrastar um arquivo de referência, a ferramenta calcula e registra no relatório final o hash SHA-256 do próprio documento utilizado para a conferência, amarrando a auditoria.
* **Alerta de CRC32:** Hashes CRC32 eventualmente presentes nos laudos de referência são intencionalmente ignorados no cruzamento de dados para evitar falsos positivos (por colidirem com datas ou números sequenciais em texto plano).

---

## 🌐 Isolamento de Nuvem e Triagem de Unidades e Aquisição RAW
Um diferencial crítico é o **bloqueio automático de arquivos "Apenas Online"** (OneDrive, Google Drive, etc.). A ferramenta detecta o atributo *Recall on Data Access* e impede a leitura desses arquivos para evitar downloads indesejados que alterariam a evidência local e o tráfego de rede. 

* **Triagem de Unidades:** Caso o usuário selecione a raiz de uma unidade (Pendrive ou HD), o programa extrai automaticamente o Rótulo (Label), o Serial do Volume, o Sistema de Arquivos (FS) e a **Capacidade Total** (formatada no padrão brasileiro), incluindo alertas técnicos quando mídias ópticas (CD/DVD) forem detectadas para evitar confusões em laudos.
* **Proteção Anti-Thrashing (Hardware Lock):** O sistema mapeia em baixo nível a relação entre Volumes Lógicos e Discos Físicos reais. Impede ativamente que duas instâncias do programa realizem aquisições simultâneas no mesmo disco magnético ou SSD, prevenindo saturação severa de I/O e protegendo a vida útil da evidência física.
* **Aquisição RAW:** Funcionalidade de **Aquisição Bit-a-bit**, exigindo elevação de privilégios (UAC). É possível escolher entre a extração do **Disco Físico Inteiro** (MBR/GPT, espaço não alocado e partições ocultas) ou apenas do Volume Lógico.
* **Cópia Forense:** Durante essa extração, o sistema permite a geração simultânea de uma imagem **.dd** ou **.e01**.

---

## 📸 Extração de Metadados
### 🔬 Metadados Básicos

A ativação da opção **"Incluir Metadados Básicos"** permite a extração de alguns metadados previamente definidos no código, dentre eles:

* **Fotos:** Extrai fabricante/modelo, data de criação interna, fuso horário e **coordenadas GPS** formatadas com link direto para o Google Maps.
* **Perícia Avançada em Vídeos:** Além da **Análise Avançada de Taxa de Quadros** (FPS nominal, mínimo e máximo), a ferramenta agora extrai as **Razões de Proporção (DAR/PAR)** traduzidas para formatos visuais (16:9, 4:3, Vertical), identifica pixels anamórficos, evidencia discrepâncias entre a resolução de exibição e a resolução armazenada (codificada) e detecta se o vídeo possui espelhamento horizontal ou vertical via matriz de transformação. O ExifTool complementa extraindo GPS embutido, data/hora de criação real, marca/modelo do dispositivo, software de edição (indícios), rotação, UUID de gravação, telemetria e número de série de drones, e indícios de câmeras de vigilância/DVR (Hikvision, Dahua, Intelbras). O MediaInfo detalha as trilhas de vídeo e áudio com containers, codecs, bitrates e campos customizados de fabricantes.
* **Validação de Duração:** Calcula o *FPS Matemático/Real* dividindo a quantidade exata de quadros contabilizados fisicamente no arquivo pela duração estrutural extraída em milissegundos, revelando a verdadeira fluidez do vídeo independentemente de cabeçalhos genéricos.
* **Análise de Redes Sociais:** Detecta padrões de nomes (WhatsApp, Telegram, Facebook) e emite um alerta pericial sobre o **metadata stripping** (lavagem de metadados).
* **Áudio:** Utiliza uma extração primária hiper-rápida (**TinyTag**) com fallback via ExifTool, obtendo duração exata, bitrate e artista.
* **Arquivos Geográficos / Mapas (KML, KMZ, GPX, XML):** Extração de coordenadas, pontos e vértices (com supressão inteligente de duplicatas no fecho de polígonos). Inclui interface com botões para a exportação minificada de novos mapas periciais (Pontos e Polígonos demarcados) com interface para identificação de autoria forense (Operação, Laudo e Usuário).

### 🔬 Dump Estrutural de Metadados (Raw Dump)

A ativação da opção **"Incluir TODOS os metadados (Raw Dump)"** instrui a ferramenta a contornar as camadas de sanitização da interface e realizar o *dump* literal e bruto dos dicionários e atributos retornados pelas bibliotecas subjacentes. Essa funcionalidade permite o acesso a metadados proprietários não mapeados, dados corrompidos ou telemetrias exóticas.

Abaixo estão as rotinas exatas executadas pela ferramenta para a extração estrutural:

* **📷 Imagens (JPEG, PNG, RAW, etc.):** A ferramenta executa o `ExifTool` via linha de comando para obter o JSON completo dos blocos EXIF/XMP. O módulo `Pillow (PIL)` itera sobre `img.info.items()` com uma regra de proteção: valores binários complexos (como Perfis ICC nativos) são mascarados com segurança para não corromper ou congelar a interface gráfica.
* **🎬 Vídeos (MP4, MKV, AVI):** Utiliza o `pymediainfo` para extrair os dicionários de todas as trilhas multiplexadas (General, Video, Audio) iterando sobre `track.to_data()`. O `OpenCV (cv2)` realiza a leitura bruta de propriedades diretas (CAP_PROP). O `ExifTool` é acionado paralelamente para despejar estruturas embutidas.
* **🎵 Áudios (MP3, WAV, FLAC):** O módulo `tinytag` é acionado para obter a estrutura completa do áudio convertendo os blocos lidos nativamente em um dicionário via `as_dict()`. Um dump complementar via `ExifTool` também é acionado.
* **📄 Documentos PDF:** O módulo `pypdf` extrai os objetos primários armazenados no dicionário de metadados iterando sobre `reader.metadata`.
* **📊 Office OOXML (.docx, .xlsx, .pptx):** As bibliotecas nativas `zipfile` e `xml.etree.ElementTree` executam a descompressão física da estrutura *Open XML* em memória. A ferramenta varre manualmente o *stream* `docProps/core.xml`, realizando o *dump* literal de todas as *tags* e textos contidos na árvore XML.
* **💾 Office OLE/CFBF (.doc, .xls, .ppt):** O módulo `olefile` extrai o objeto de propriedades, e o script varre iterativamente os atributos internos (`__dict__`), tratando e decodificando cadeias de bytes diretamente.
* **🔗 Atalhos do Windows (.lnk):** O módulo `LnkParse3` decodifica a estrutura binária do atalho, e a ferramenta anexa o *dump* integral via método `get_json()`.
* **⚙️ Binários PE (.exe, .dll, .sys):** O módulo `pefile` processa a estrutura executável e a ferramenta incorpora a saída integral e bruta da função `pe.dump_info()`, contemplando mapeamento de seções e cabeçalhos de compilação.
* **📧 Contêineres de E-mail:** Para arquivos `.eml`, a biblioteca nativa itera sobre o retorno `msg.items()`. Para contêineres `.msg`, o módulo `extract_msg` realiza o *dump* integral varrendo `msg.header.items()`.
* **🌍 Arquivos Geográficos (KML, KMZ, GPX, XML):** A biblioteca nativa `xml.etree.ElementTree` processa a árvore XML do mapa iterando sobre os nós, extraindo o total exato de `<coordinates>` e a totalização bruta de vértices originais mapeados no arquivo.
* **📦 Outros Formatos (Archives, Torrents, RTF):** A ferramenta delega o *dump* integral para as funções de extração JSON do `ExifTool`.

> **🛡️ Rede de Captura Universal (Fallback):** Caso a extensão do arquivo permita extração, mas o ExifTool não tenha sido acionado nas rotinas principais, o script possui uma rede de segurança no final do bloco. Ele invoca o **ExifTool** de forma complementar com parametrização estrita (`-j -G -a -ee -api largefilesupport=1`) para garantir o *dump* forçado de quaisquer propriedades identificáveis, independentemente do suporte nativo.

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

## 💻 Comandos Internos (Under the Hood)

Para fins de reprodutibilidade, transparência e auditoria pericial, abaixo estão as chamadas exatas de linha de comando (CLI) que o extrator executa em segundo plano para realizar as operações críticas:

**1. Extração de Metadados via ExifTool:**
O extrator padroniza a chamada do ExifTool para todas as mídias (Imagens, Vídeos, Áudios e Documentos) forçando a saída estruturada e a formatação de coordenadas:
`exiftool -charset filename=latin -charset utf8 -j -G -a -ee -api largefilesupport=1 -c "%+.6f" "caminho_da_evidencia.ext"`

* **`-charset`**: Força a leitura correta de caminhos e nomes de arquivos com acentuação e caracteres latinos.
* **`-j`**: Retorna a saída formatada nativamente em JSON para *parsing* seguro no Python.
* **`-G`**: Imprime o grupo estrutural ao qual o metadado pertence (ex: `QuickTime`, `EXIF`, `IFD0`).
* **`-a`**: Permite a extração de tags duplicadas (útil para trilhas de vídeo/áudio múltiplas).
* **`-ee`**: Extrai informações embutidas (*extract embedded*), vital para geolocalização dinâmica de drones e GoPros.
* **`-api largefilesupport=1`**: Habilita o suporte a vídeos e arquivos pesados com mais de 4 GB.
* **`-c "%+.6f"`**: Padroniza a saída das coordenadas geográficas em graus decimais para a geração correta dos links do Google Maps e KMLs.

**2. Aquisição de Imagem Forense (.E01) via libewf (ewfacquire):**
Executado encapsulado em uma sessão do PowerShell com elevação de privilégios (UAC) e em modo *unattended* (automação):
`ewfacquire -u -c fast -t "caminho_destino" -l "caminho_destino.ewf.log" -d sha256 -S 4G -C "Nome da Operação" -D "Descrição do Arquivo" -E "Laudo" -e "Perito" "\\.\PhysicalDrive0"`

* **`-u`**: Modo não-interativo (*unattended*), desativando os prompts do terminal original.
* **`-c fast`**: Define o nível de compressão do contêiner EWF.
* **`-t`**: Caminho alvo (*target*) sem a extensão do arquivo.
* **`-l`**: Caminho exato para a escrita espelhada do log de auditoria física nativo do ewfacquire.
* **`-d sha256`**: Força a injeção do hash SHA-256 (além do MD5 embutido por padrão) no cabeçalho dos blocos E01.
* **`-S` / `-C` / `-D` / `-E` / `-e`**: Argumentos dinâmicos preenchidos através da janela "Cabeçalho Forense" para fragmentação (ex: `4G`, `640M`) e metadados de custódia.
* **`\\.\PhysicalDrive0`**: Caminho UNC de baixo nível para o disco físico ou volume lógico alvo (ex: `\\.\E:`).

**3. Verificação de Integridade Criptográfica (ewfverify):**
Ao finalizar a aquisição de uma imagem `.E01`, o sistema valida os hashes gravados dentro do contêiner para atestar que a imagem não sofreu corrupção durante a escrita:
`ewfverify -d md5,sha256 "caminho_destino.e01"`

---

## ⚠️ Aviso Legal e Isenção de Responsabilidade (Disclaimer)

Esta é uma ferramenta desenvolvida com propósitos acadêmicos, forenses e de pesquisa. O autor **não se responsabiliza** por quaisquer danos, perdas de dados ou consequências jurídicas advindas do uso deste software. 

Se você for utilizar este extrator em investigações oficiais, auditorias ou na elaboração de laudos periciais judiciais, **a conferência e a validação técnica dos resultados gerados são de sua inteira responsabilidade**. Cabe exclusivamente ao perito, assistente técnico ou investigador atestar a exatidão das informações extraídas e garantir a correta manutenção da cadeia de custódia antes de anexar qualquer evidência a processos legais.

___

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

___

## 📝 Como citar este software (ABNT)

Se você utilizar o **Extrator de Hashes e Metadados Forenses** em trabalhos acadêmicos, laudos periciais ou pesquisas, por favor, utilize a seguinte citação:

> SILVA, Eduardo R. **Extrator de Hashes e Metadados (ERS-IC/SP-NIC)**. Versão 4.6.1. São Paulo, SP: GitHub, 2026. Disponível em: <https://github.com/eduardo-rsilva/extrator_hashes_metadados/releases>. Acesso em: [Data de Acesso].

---

## ⚖️ Licença

Este projeto é distribuído sob uma licença restrita para uso acadêmico, institucional e forense. O uso comercial, a venda ou a integração em plataformas pagas são expressamente proibidos sem autorização prévia.

Para ler os termos completos, consulte o arquivo [LICENSE](https://github.com/eduardo-rsilva/extrator_hashes_metadados?tab=License-1-ov-file).

___

**Feedback e sugestões de novas extensões e funcionalidades são super bem-vindos.**
