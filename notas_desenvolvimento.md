# 🚀 Em Desenvolvimento: Módulo de Análise de Notas Fiscais

Atendendo à excelente sugestão enviada por um usuário, informo que estou trabalhando em um novo recurso de análise estruturada de documentos fiscais para a próxima atualização.

O extrator passará a identificar e interpretar automaticamente **Notas Fiscais Eletrônicas brasileiras**, processando tanto as tags de arquivos estruturados (**XML**) quanto rastreando padrões visuais dentro de arquivos **PDF (DANFEs)**.

**📄 Tipos de Documentos que serão suportados:**
- **Padrão Nacional SEFAZ (com Chave de Acesso de 44 dígitos):** NF-e, NFC-e, CT-e, MDF-e e CF-e-SAT.
- **Documentos Municipais (NFS-e):** Devido à falta de padronização visual entre as diferentes prefeituras do país e à ausência da chave nacional, a ferramenta fará uma extração parcial (via *fallback*), tentando capturar apenas o **Número da Nota**.

**🔍 Informações detalhadas no laudo final (para o padrão SEFAZ):**
- Chave de Acesso completa
- UF do Emitente (Decodificada com a sigla e nome do Estado)
- Mês/Ano de Emissão
- CNPJ do Emitente (Formatado)
- Modelo da Nota (Decodificado, ex: 65 - NFC-e)
- Série e Número da Nota
- Código Numérico e Dígito Verificador

Essa novidade deve facilitar a triagem de evidências fiscais e poupar o perito de realizar consultas manuais aos códigos do IBGE e da Receita.

Eduardo