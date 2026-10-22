# Minhas finanças

Aplicativo responsivo de finanças pessoais feito com Python, Streamlit e Cloud Firestore. A tela é em português e permite cadastro, login e operações de criar, consultar, editar e excluir receitas e despesas. O painel inclui resumo do período, indicador de renda comprometida, gráfico de despesas por categoria, filtros por tipo e categoria, atalhos para adicionar salário e lançamentos, e botão de saída fixo no canto inferior direito.

## Firebase

O arquivo de conta de serviço que está nesta pasta identifica o projeto Firebase `app-finaceiro-4a1c1`. O aplicativo usa o Cloud Firestore no banco padrão `(default)`. O nome de exibição do projeto não é usado pelo SDK; a conta de serviço determina o projeto conectado.

1. No Console do Firebase, habilite o Cloud Firestore na localização desejada e crie o banco de dados padrão `(default)`.
2. Use uma conta de serviço com permissão para acessar o Firestore. Mantenha o JSON privado: não o envie ao Git, não o publique e não o inclua em capturas de tela.
3. Se houver exatamente um arquivo `*firebase-adminsdk*.json` ao lado de `app.py`, o aplicativo o localizará automaticamente. Caso contrário, configure explicitamente o caminho no PowerShell:

   ```powershell
   $env:FIREBASE_CREDENTIALS = (Resolve-Path ".\app-finaceiro-4a1c1-firebase-adminsdk-fbsvc-58bffff863.json").Path
   ```

   Para persistir a variável no Windows, configure `FIREBASE_CREDENTIALS` nas variáveis de ambiente do usuário, apontando para o caminho completo do arquivo.

As credenciais não são armazenadas no código nem no `firebase.json`. O `.gitignore` também exclui arquivos de conta de serviço. Em produção, prefira um mecanismo de identidade de serviço gerenciado em vez de distribuir uma chave JSON.

### Deploy no Streamlit Community Cloud

1. No GitHub, crie um repositório **privado** e envie o app e seus arquivos de configuração. Não envie a conta de serviço JSON, `.streamlit/secrets.toml`, `.env` ou `.venv`. O arquivo `.gitignore` já protege os segredos locais.
2. No [share.streamlit.io](https://share.streamlit.io), entre com GitHub, clique em **Create app** e selecione o repositório, branch e `app.py`.
3. Abra **Advanced settings → Secrets**. Copie o conteúdo de `.streamlit/secrets.toml.example`, substitua os marcadores pelos valores do JSON da conta de serviço e cole no campo **Secrets**. Preserve as quebras de linha e os delimitadores `BEGIN/END PRIVATE KEY`.
4. Clique em **Deploy**. Depois, teste cadastro, login e lançamentos. Se alterar os Secrets, salve e reinicie o app no painel.

**Nunca** cole a chave privada no código, GitHub ou conversas. Se uma chave já foi enviada ao GitHub, revogue-a no Google Cloud IAM e gere outra. O JSON local identifica `app-finaceiro-4a1c1`; confirme que é esse o projeto que deseja usar antes de publicar.

## IA financeira

O chat usa o modelo Gemini para responder perguntas sobre o período selecionado. Para ativá-lo, crie uma chave de API no [Google AI Studio](https://aistudio.google.com/app/apikey) e configure-a sem adicioná-la ao código:

- **Execução local:** defina a variável de ambiente `GEMINI_API_KEY` no PowerShell antes de iniciar o app:

  ```powershell
  $env:GEMINI_API_KEY = "SUA_CHAVE_API"
  streamlit run app.py
  ```

- **Streamlit Community Cloud:** adicione `api_key` e, opcionalmente, `model` na seção `[gemini]` em **App settings → Secrets**, conforme `.streamlit/secrets.toml.example`.

O modelo padrão é `gemini-2.5-flash`; ele pode ser alterado pelo Secret `model` ou pela variável de ambiente `GEMINI_MODEL`. O chat envia ao Gemini os totais de receitas, despesas e saldo, além dos totais por categoria. Descrições dos lançamentos não são enviadas. As perguntas e respostas ficam apenas na sessão atual do Streamlit.

Senhas de novas contas usam PBKDF2-SHA256 da biblioteca padrão do Python; o app não precisa importar `bcrypt` para iniciar. A dependência `bcrypt` permanece no `requirements.txt` apenas para validar e migrar hashes de contas criadas por versões anteriores. Se o app mostrar mensagem de formato antigo ao entrar, confirme que `requirements.txt` está na raiz do repositório, envie-o ao GitHub e reinicie o app para instalar a dependência.

## Instalação e execução

Requer Python 3.10 ou superior.

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
streamlit run app.py
```

Para acessar pelo celular na mesma rede Wi-Fi:

```powershell
streamlit run app.py --server.address 0.0.0.0
```

Abra no navegador do celular o endereço de rede local exibido pelo Streamlit. A máquina que executa o app deve permanecer ligada e acessível.

## Dados e segurança

- Usuários ficam em `users/{uid}`; o índice `usernames/{usuario_normalizado}` garante usernames únicos. A senha é armazenada apenas como hash bcrypt.
- Lançamentos ficam em `transactions/{id}` e incluem `owner_uid`; consultas são limitadas ao UID da sessão autenticada. Edição e exclusão verificam novamente a propriedade do documento.
- Valores são armazenados como centavos inteiros, evitando erros de arredondamento de ponto flutuante.
- O arquivo `firestore.rules` nega acesso direto por clientes Firebase. O Admin SDK usado pelo Streamlit opera no servidor e ignora regras de segurança; proteja o servidor e a credencial de serviço.

Cadastro de usuário/senha é implementado pelo próprio aplicativo; não é Firebase Authentication. A sessão de login é mantida na sessão do Streamlit.

## Regras do Firestore

As regras incluídas bloqueiam leituras e gravações por SDKs de cliente. O `.firebaserc` seleciona o projeto indicado pela conta de serviço. Se usar o Firebase CLI para publicar as regras:

```powershell
firebase deploy --only firestore:rules
```

O deploy exige que o Firebase CLI esteja autenticado; confirme que a conta tem acesso ao projeto antes de publicar. A execução do app não requer o Firebase CLI.
