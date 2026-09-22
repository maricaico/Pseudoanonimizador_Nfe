# Pseudonimizador de XML de NF-e

Ferramenta desenvolvida em Python, sem dependências externas, para pseudonimizar ou suprimir dados sensíveis presentes em XMLs de Nota Fiscal Eletrônica (NF-e), preservando a estrutura e a consistência dos dados necessários para análise.

O programa pode ser utilizado com XMLs de NF-e de diferentes segmentos econômicos que adotem esse documento fiscal, pois trabalha sobre a estrutura padronizada da NF-e.

## Requisitos

- Python 3.10 ou superior
- Não requer instalação de pacotes externos

## Como executar

```bash
python pseudonimizador_nfe.py --input ./xmls_originais --output ./xmls_pseudonimizados
```

Ao executar, o programa solicita uma chave secreta, que não é exibida durante a digitação:

```text
Digite a chave secreta (não será exibida na tela):
```

A chave secreta não é gravada em arquivo ou log pelo programa. Ela é utilizada pelo HMAC-SHA256 para tornar a pseudonimização determinística.

Por isso, a mesma chave deve ser reutilizada quando for necessário manter a consistência dos identificadores pseudonimizados entre diferentes arquivos ou execuções.

### Opção adicional

| Flag | Efeito |
| --- | --- |
| `-w N` / `--workers N` | Define a quantidade de processos paralelos (padrão: até 4). Útil para pastas com muitos arquivos. |

## Dados pseudonimizados ou suprimidos

- CNPJ e CPF de emitente, destinatário e transportador
- Suporte a CNPJ alfanumérico
- Inscrição Estadual (IE), Inscrição Estadual do Substituto Tributário (IEST) e Inscrição Municipal (IM)
- Razão Social e Nome Fantasia
- Logradouro, número e complemento
- Telefone e e-mail
- Últimos 3 dígitos do CEP
- Número da nota (`nNF`)
- Código numérico da NF-e (`cNF`)
- Chave de acesso da NF-e
- Chaves de NF-e referenciadas (`refNFe` e equivalentes tratados pelo programa)
- Textos livres, como informações adicionais
- Nome/descrição do produto (`xProd`)
- NCM do produto
- Códigos de barras do produto (`cEAN`, `cEANTrib`, `cBarra` e `cBarraTrib`), quando presentes
- Outros campos definidos no programa para remoção
- Assinatura digital original, que deixa de ser válida após a alteração do conteúdo do XML

## Dados preservados para análise

Entre os dados mantidos estão:

- Valores, quantidades, alíquotas e totais
- Informações fiscais e comerciais necessárias às análises
- Código interno do produto (`cProd`)
- CFOP e CEST, quando presentes
- Município, UF e bairro
- Os 5 primeiros dígitos do CEP, preservando uma referência geográfica agregada
- Datas
- Série do documento

A preservação desses campos busca manter a utilidade analítica dos XMLs. O código interno do produto (`cProd`), as quantidades e os valores permanecem inalterados por decisão de projeto, enquanto nome/descrição, NCM e códigos de barras são pseudonimizados para reduzir a possibilidade de identificação direta ou indireta do produto.

## Consistência e integridade referencial

A pseudonimização utiliza HMAC-SHA256 de forma determinística. Assim, o mesmo identificador de entrada gera o mesmo valor pseudonimizado quando processado com a mesma chave secreta e sob a mesma regra de transformação.

Essa mesma lógica é aplicada aos identificadores de produto tratados pelo programa. Assim, o mesmo `xProd`, NCM ou código de barras original gera sempre o mesmo pseudônimo quando utilizada a mesma chave secreta. Quando os campos de código de barras não estão presentes ou estão vazios, o programa simplesmente os ignora. O literal `SEM GTIN` é preservado. Para GTINs numéricos com 8, 12, 13 ou 14 dígitos, o programa gera um valor sintético determinístico e recalcula o respectivo dígito verificador.

Os identificadores que podem possuir representações diferentes são normalizados antes do cálculo. Por exemplo, o número da NF-e (`nNF`) é padronizado para 9 dígitos, garantindo consistência entre o valor presente no campo `<nNF>` e sua representação dentro da chave de acesso.

A chave de acesso é reconstruída após a pseudonimização, com atualização do `nNF`, `cNF`, CNPJ do emitente e respectivo dígito verificador (`cDV`).

O programa também mantém a correspondência entre a chave presente em `infNFe/@Id` e `protNFe/infProt/chNFe`, além de aplicar a mesma regra às NF-e referenciadas. Isso permite preservar os relacionamentos necessários entre documentos.

## Validação

Antes da gravação do XML pseudonimizado, o programa realiza verificações de consistência, incluindo:

- validade dos CPF sintéticos;
- validade dos CNPJ sintéticos, inclusive alfanuméricos;
- estrutura e dígito verificador da nova chave de acesso;
- correspondência do `cNF` com a chave;
- correspondência do `cDV` com a chave;
- correspondência entre `infNFe/@Id` e `protNFe/infProt/chNFe`, quando houver protocolo.

## Aviso

Esta ferramenta implementa **pseudonimização determinística**, e não anonimização irreversível dos dados.

A chave secreta utilizada pelo HMAC deve ser protegida e não deve ser distribuída juntamente com os XMLs pseudonimizados.

Os XMLs resultantes são derivados e **não constituem documentos fiscais válidos para nova autorização ou transmissão à SEFAZ**, pois seus dados foram modificados e a assinatura digital original foi removida.

Campos preservados por necessidade analítica, como bairro, prefixo do CEP e código interno do produto (`cProd`), devem ser considerados na avaliação de risco do conjunto de dados, pois podem manter informações indiretas sobre localização, produtos ou contexto comercial.