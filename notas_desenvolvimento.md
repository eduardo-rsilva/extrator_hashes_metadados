# Correção Crítica Disponível: Atualize para a v.7.3.1

Olá a todos!

Identifiquei e solucionei uma falha no motor de leitura que ocorria especificamente quando o extrator ou as evidências estavam localizados em pastas com **caminhos muito longos** (que ultrapassavam o limite de 260 caracteres do Windows) ou possuíam **nomes acentuados e caracteres especiais**.

Esse cenário impedia o carregamento da base de dados com extensões de arquivos, desativando a capacidade da ferramenta de inspecionar os bytes iniciais e descobrir o formato real de arquivos mascarados.

**Atenção:** Se seus relatórios de extração de metadados mostram o erro **"⚠️ Erro ao verificar Magic Bytes com libmagic: b'could not find any valid magic files!'"**, a atualização é necessária.

Recomendo que todos atualizem para a versão **7.3.1** utilizando o botão **"Verificar Atualizações"** no menu **Sobre** para garantir a estabilidade completa da ferramenta.

Eduardo
11/11/2026