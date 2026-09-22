import argparse
import hashlib
import hmac
import logging
import multiprocessing as mp
import os
import re
import sys
import xml.etree.ElementTree as ET
from concurrent.futures import ProcessPoolExecutor, as_completed
from getpass import getpass
from pathlib import Path

# ============================================================
# PSEUDONIMIZADOR DE XML NF-e / nfeProc — V6.2
# Proteção de dados e preparação analítica (DW)
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)

NFE_NS = "http://www.portalfiscal.inf.br/nfe"
DSIG_NS = "http://www.w3.org/2000/09/xmldsig#"

ET.register_namespace("", NFE_NS)


# ============================================================
# FUNÇÕES AUXILIARES
# ============================================================

def q(tag: str) -> str:
    """Retorna uma tag usando o namespace da NF-e."""
    return f"{{{NFE_NS}}}{tag}"


def local_name(tag: str) -> str:
    """Obtém o nome local de uma tag XML."""
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


# ============================================================
# HMAC DETERMINÍSTICO
# ============================================================

def _hmac_bytes(key: str, namespace: str, value: str) -> bytes:
    return hmac.new(
        key.encode("utf-8"),
        f"{namespace}:{value}".encode("utf-8"),
        hashlib.sha256
    ).digest()


def _hmac_digits(
    key: str,
    namespace: str,
    value: str,
    n: int
) -> list[int]:
    """
    Gera n dígitos determinísticos usando HMAC-SHA256.
    A mesma chave + mesmo valor original gera sempre
    o mesmo resultado.
    """

    resultado = []
    contador = 0

    while len(resultado) < n:

        digest = _hmac_bytes(
            key,
            f"{namespace}:{contador}",
            value
        )

        resultado.extend(
            str(byte % 10)
            for byte in digest
        )

        contador += 1

    return [
        int(x)
        for x in resultado[:n]
    ]


def _hmac_index(
    key: str,
    namespace: str,
    value: str,
    modulo: int
) -> int:

    digest = _hmac_bytes(
        key,
        namespace,
        value
    )

    return (
        int.from_bytes(
            digest[:8],
            "big"
        )
        % modulo
    )


# ============================================================
# DÍGITO VERIFICADOR
# ============================================================

def _dv_mod11(
    digits: list[int],
    weights: list[int]
) -> int:

    total = sum(
        d * w
        for d, w in zip(digits, weights)
    )

    resto = total % 11

    return (
        0
        if resto < 2
        else 11 - resto
    )


def _tem_padrao_repetido(
    digits: list[int]
) -> bool:

    return len(set(digits)) == 1


# ============================================================
# CNPJ SINTÉTICO
# ============================================================

def fake_cnpj(key: str, original: str) -> str:
    original_limpo = re.sub(r"[^A-Za-z0-9]", "", original or "").upper()
    alfa = bool(re.search(r"[A-Z]", original_limpo))
    for tentativa in range(100):
        if alfa:
            alfabeto = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
            base = "".join(
                alfabeto[_hmac_index(key, f"CNPJ_ALFA:{tentativa}:{i}", original_limpo, len(alfabeto))]
                for i in range(12)
            )
            if len(set(base)) == 1:
                continue
            dv1 = _dv_cnpj_alfa(base, [5,4,3,2,9,8,7,6,5,4,3,2])
            dv2 = _dv_cnpj_alfa(base + str(dv1), [6,5,4,3,2,9,8,7,6,5,4,3,2])
            candidato = base + str(dv1) + str(dv2)
        else:
            base = _hmac_digits(key, f"CNPJ:{tentativa}", original_limpo, 12)
            if _tem_padrao_repetido(base):
                continue
            dv1 = _dv_mod11(base, [5,4,3,2,9,8,7,6,5,4,3,2])
            dv2 = _dv_mod11(base + [dv1], [6,5,4,3,2,9,8,7,6,5,4,3,2])
            candidato = "".join(map(str, base + [dv1, dv2]))
        if candidato != original_limpo:
            return candidato
    raise RuntimeError("Não foi possível gerar CNPJ sintético.")


# ============================================================
# CPF SINTÉTICO
# ============================================================

def fake_cpf(
    key: str,
    original: str
) -> str:

    for tentativa in range(100):

        base = _hmac_digits(
            key,
            f"CPF:{tentativa}",
            original,
            9
        )

        if _tem_padrao_repetido(base):
            continue

        dv1 = _dv_mod11(
            base,
            [
                10, 9, 8, 7, 6,
                5, 4, 3, 2
            ]
        )

        dv2 = _dv_mod11(
            base + [dv1],
            [
                11, 10, 9, 8, 7, 6,
                5, 4, 3, 2
            ]
        )

        candidato = "".join(
            map(
                str,
                base + [dv1, dv2]
            )
        )

        original_limpo = re.sub(
            r"\D",
            "",
            original
        )

        if candidato != original_limpo:
            return candidato

    raise RuntimeError(
        "Não foi possível gerar CPF sintético."
    )


# ============================================================
# NÚMEROS GENÉRICOS
# ============================================================

def fake_numeric(
    key: str,
    namespace: str,
    original: str,
    n_digits: int
) -> str:

    digits = _hmac_digits(
        key,
        namespace,
        original,
        n_digits
    )

    return "".join(
        map(str, digits)
    )


def fake_cep(
    key: str,
    cep_original: str,
    identidade: str
) -> str:
    """
    Gera um CEP pseudonimizado mantendo o prefixo postal original
    de cinco dígitos como referência geográfica agregada e
    gerando de forma determinística os três últimos dígitos.

    O prefixo é preservado por utilidade analítica no DW/SAD,
    mas não deve ser tratado como dado totalmente anonimizado,
    pois, combinado com município/UF e outros atributos, ainda
    pode contribuir para inferir uma localização aproximada.
    """

    digitos_originais = re.sub(
        r"\D",
        "",
        cep_original or ""
    )

    if len(digitos_originais) >= 5:
        prefixo = digitos_originais[:5]
    else:
        # CEP original ausente/incompleto: gera um prefixo
        # determinístico de 5 dígitos como alternativa.
        prefixo = fake_numeric(
            key,
            "CEP_PREFIXO",
            identidade,
            5
        )

    sufixo = fake_numeric(
        key,
        "CEP_SUFIXO",
        cep_original or identidade,
        3
    )

    return prefixo + sufixo


# ============================================================
# CHAVE DE ACESSO DA NF-e
# ============================================================

def _valor_chave_nfe(c: str) -> int:
    if c.isdigit():
        return int(c)
    if "A" <= c <= "Z":
        return ord(c) - 48
    raise ValueError(f"Caractere inválido na chave de acesso: {c!r}")


def _dv_chave_nfe(corpo: str) -> int:
    pesos = []
    peso = 2
    for _ in corpo:
        pesos.insert(0, peso)
        peso = 2 if peso == 9 else peso + 1
    total = sum(_valor_chave_nfe(c) * p for c, p in zip(corpo, pesos))
    resto = total % 11
    return 0 if resto in (0, 1) else 11 - resto


def recalcula_chave_acesso(
    chave_original: str,
    novo_cnpj: str,
    key: str,
    novo_nnf: str | None = None
) -> str | None:

    """
    Recria uma chave de acesso de 44 posições, aceitando CNPJ/chave
    alfanuméricos conforme a NT 2026.004.
    """

    chave = re.sub(r"[^A-Za-z0-9]", "", chave_original or "").upper()

    if not re.fullmatch(r"[A-Z0-9]{44}", chave):
        return None

    cUF = chave[0:2]
    AAMM = chave[2:6]

    mod = chave[20:22]
    serie = chave[22:25]

    nNF = chave[25:34]
    tpEmis = chave[34:35]

    if novo_nnf is not None:

        nNF = (
            novo_nnf
            .zfill(9)
            [-9:]
        )

    novo_cNF = fake_numeric(
        key,
        "cNF",
        chave,
        8
    )

    corpo = (
        cUF
        + AAMM
        + novo_cnpj
        + mod
        + serie
        + nNF
        + tpEmis
        + novo_cNF
    )

    return (
        corpo
        + str(
            _dv_chave_nfe(corpo)
        )
    )


# ============================================================
# NOMES SINTÉTICOS
# ============================================================

EMPRESA_TIPOS = [
    "Distribuidora",
    "Comercial",
    "Atacadista",
    "Industria",
    "Grupo"
]

EMPRESA_NOMES = [
    "Aurora",
    "Vitoria",
    "Nordeste",
    "Cerrado",
    "Planalto",
    "Horizonte"
]

EMPRESA_SUFIXOS = [
    "Ltda",
    "S.A.",
    "ME"
]

NOMES = [
    "Ana",
    "Bruno",
    "Carla",
    "Daniel",
    "Elaine",
    "Fabio",
    "Gabriela",
    "Helena"
]

SOBRENOMES = [
    "Silva",
    "Souza",
    "Oliveira",
    "Santos",
    "Pereira",
    "Costa",
    "Almeida",
    "Ramos"
]


def _pick(
    key: str,
    namespace: str,
    original: str,
    values: list[str]
) -> str:

    return values[
        _hmac_index(
            key,
            namespace,
            original,
            len(values)
        )
    ]


def fake_nome_empresa(
    key: str,
    original: str
) -> str:

    return (
        f"{_pick(key, 'empresa_tipo', original, EMPRESA_TIPOS)} "
        f"{_pick(key, 'empresa_nome', original, EMPRESA_NOMES)} "
        f"{_pick(key, 'empresa_sufixo', original, EMPRESA_SUFIXOS)}"
    )


def fake_nome_pessoa(
    key: str,
    original: str
) -> str:

    return (
        f"{_pick(key, 'pessoa_nome', original, NOMES)} "
        f"{_pick(key, 'pessoa_sobrenome', original, SOBRENOMES)}"
    )


FANTASIA_TIPOS = [
    "Distrib.",
    "Atacado",
    "Center",
    "Log",
    "Express",
]


def fake_nome_fantasia(
    key: str,
    original: str
) -> str:

    return (
        f"{_pick(key, 'fantasia_nome', original, EMPRESA_NOMES)} "
        f"{_pick(key, 'fantasia_tipo', original, FANTASIA_TIPOS)}"
    )


# ============================================================
# PRODUTOS / NCM
# ============================================================

def fake_nome_produto(
    key: str,
    original: str
) -> str:
    """Gera um identificador determinístico para o nome do produto."""

    codigo = fake_numeric(
        key,
        "xProd",
        original,
        10
    )

    return f"Produto {codigo}"


def fake_ncm(
    key: str,
    original: str
) -> str:
    """Pseudonimiza o NCM preservando formato numérico de 8 dígitos."""

    return fake_numeric(
        key,
        "NCM",
        original,
        8
    )


def _dv_gtin(corpo: str) -> int:
    """Calcula o dígito verificador de um GTIN a partir do corpo sem o DV."""

    total = 0
    peso = 3

    for digito in reversed(corpo):
        total += int(digito) * peso
        peso = 1 if peso == 3 else 3

    return (10 - (total % 10)) % 10


def fake_codigo_barras(
    key: str,
    original: str
) -> str:
    """
    Pseudonimiza códigos de barras de forma determinística.

    - Preserva o literal SEM GTIN.
    - Para códigos numéricos com tamanho de GTIN (8, 12, 13 ou 14),
      gera um GTIN sintético com dígito verificador válido.
    - Para outros códigos de barras, preserva o comprimento e o tipo
      geral do conteúdo (numérico ou alfanumérico).
    """

    valor = (original or "").strip()

    if valor.upper() == "SEM GTIN":
        return "SEM GTIN"

    if valor.isdigit() and len(valor) in {8, 12, 13, 14}:

        corpo = fake_numeric(
            key,
            "COD_BARRAS_GTIN",
            valor,
            len(valor) - 1
        )

        return corpo + str(_dv_gtin(corpo))

    if valor.isdigit():

        return fake_numeric(
            key,
            "COD_BARRAS_NUM",
            valor,
            len(valor)
        )

    alfabeto = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

    return "".join(
        alfabeto[
            _hmac_index(
                key,
                f"COD_BARRAS_ALFA:{i}",
                valor,
                len(alfabeto)
            )
        ]
        for i in range(len(valor))
    )


# ============================================================
# VALIDAÇÃO DE CPF
# ============================================================

def validar_cpf(
    cpf: str
) -> bool:

    d = re.sub(
        r"\D",
        "",
        cpf or ""
    )

    if (
        len(d) != 11
        or _tem_padrao_repetido(
            [int(x) for x in d]
        )
    ):
        return False

    dv1 = _dv_mod11(
        [int(x) for x in d[:9]],
        [
            10, 9, 8, 7, 6,
            5, 4, 3, 2
        ]
    )

    dv2 = _dv_mod11(
        [int(x) for x in d[:9]]
        + [dv1],
        [
            11, 10, 9, 8, 7,
            6, 5, 4, 3, 2
        ]
    )

    return (
        d[-2:]
        == f"{dv1}{dv2}"
    )


# ============================================================
# VALIDAÇÃO DE CNPJ
# ============================================================

def _valor_cnpj_alfa(c: str) -> int:
    return int(c) if c.isdigit() else ord(c) - 48


def _dv_cnpj_alfa(base: str, pesos: list[int]) -> int:
    total = sum(_valor_cnpj_alfa(c) * p for c, p in zip(base, pesos))
    resto = total % 11
    return 0 if resto < 2 else 11 - resto


def validar_cnpj(cnpj: str) -> bool:
    d = re.sub(r"[^A-Za-z0-9]", "", cnpj or "").upper()
    if not re.fullmatch(r"[A-Z0-9]{14}", d):
        return False
    if len(set(d)) == 1:
        return False
    dv1 = _dv_cnpj_alfa(d[:12], [5,4,3,2,9,8,7,6,5,4,3,2])
    dv2 = _dv_cnpj_alfa(d[:12] + str(dv1), [6,5,4,3,2,9,8,7,6,5,4,3,2])
    return d[-2:] == f"{dv1}{dv2}"


# ============================================================
# FUNÇÕES XML
# ============================================================

def _texto(
    elem,
    tag: str
) -> str:

    child = elem.find(
        q(tag)
    )

    if child is None:
        return ""

    return (
        child.text or ""
    ).strip()


# ============================================================
# PSEUDONIMIZAÇÃO DE EMITENTE / DESTINATÁRIO
# ============================================================

def _pseudonimizar_pessoa(
    elem,
    key: str,
    cache: dict,
    stats: dict
) -> None:

    if elem is None:
        return

    cnpj_el = elem.find(
        q("CNPJ")
    )

    cpf_el = elem.find(
        q("CPF")
    )

    doc_original = None
    is_pf = False

    # -------------------------
    # CNPJ
    # -------------------------

    if (
        cnpj_el is not None
        and (cnpj_el.text or "").strip()
    ):

        doc_original = (
            cnpj_el.text.strip()
        )

        doc_original = re.sub(r"[^A-Za-z0-9]", "", doc_original).upper()
        if not re.fullmatch(r"[A-Z0-9]{14}", doc_original):
            raise ValueError(
                "CNPJ de entrada fora do formato esperado de 14 caracteres "
                f"(alfanumérico): {doc_original}"
            )

        novo = cache.setdefault(
            ("CNPJ", doc_original),
            fake_cnpj(
                key,
                doc_original
            )
        )

        cnpj_el.text = novo

        stats["CNPJ"] += 1

    # -------------------------
    # CPF
    # -------------------------

    elif (
        cpf_el is not None
        and (cpf_el.text or "").strip()
    ):

        doc_original = (
            cpf_el.text.strip()
        )

        if not re.fullmatch(r"\d{11}", doc_original):
            raise ValueError(
                "CPF de entrada fora do formato numérico de 11 dígitos: "
                f"{doc_original}"
            )

        is_pf = True

        novo = cache.setdefault(
            ("CPF", doc_original),
            fake_cpf(
                key,
                doc_original
            )
        )

        cpf_el.text = novo

        stats["CPF"] += 1

    identidade = (
        doc_original
        or _texto(elem, "xNome")
        or "SEM_DOCUMENTO"
    )

    # -------------------------
    # Nome
    # -------------------------

    xnome = elem.find(
        q("xNome")
    )

    if (
        xnome is not None
        and (xnome.text or "").strip()
    ):

        if is_pf:

            xnome.text = fake_nome_pessoa(
                key,
                identidade
            )

        else:

            xnome.text = fake_nome_empresa(
                key,
                identidade
            )

        stats["nomes"] += 1

    # -------------------------
    # Nome fantasia
    # -------------------------

    xfant = elem.find(
        q("xFant")
    )

    if (
        xfant is not None
        and (xfant.text or "").strip()
    ):

        xfant.text = fake_nome_fantasia(
            key,
            identidade
        )

        stats["xFant"] += 1

    # -------------------------
    # Endereço
    # -------------------------

    for endereco_tag in (
        "enderEmit",
        "enderDest"
    ):

        endereco = elem.find(
            q(endereco_tag)
        )

        if endereco is None:
            continue

        # ---------------------------------------------------
        # CEP: mantém os 5 primeiros dígitos como referência
        # geográfica agregada e gera de forma determinística
        # os 3 últimos dígitos. O prefixo preservado aumenta
        # a utilidade analítica, mas mantém algum risco de
        # inferência geográfica quando combinado com outros
        # atributos.
        # ---------------------------------------------------

        cep_el = endereco.find(
            q("CEP")
        )

        if (
            cep_el is not None
            and (cep_el.text or "").strip()
        ):

            cep_el.text = fake_cep(
                key,
                cep_el.text.strip(),
                identidade
            )

            stats["endereco"] += 1

        # ---------------------------------------------------
        # Logradouro, número, complemento e telefone apontam
        # para o endereço exato: continuam suprimidos.
        # ---------------------------------------------------

        for tag in (
            "xLgr",
            "nro",
            "xCpl",
            "fone"
        ):

            el = endereco.find(
                q(tag)
            )

            if (
                el is not None
                and (el.text or "").strip()
            ):

                el.text = (
                    "DADO_SUPRIMIDO"
                )

                stats["endereco"] += 1

        # O bairro permanece como no original para preservar
        # utilidade analítica no DW/SAD. Em conjunto com
        # município/UF e o prefixo de 5 dígitos do CEP, ele permite
        # análises geográficas mais detalhadas, enquanto o
        # logradouro, número e complemento continuam suprimidos.


# ============================================================
# PSEUDONIMIZAÇÃO DE PRODUTOS
# ============================================================

def _pseudonimizar_produtos(
    root,
    key: str,
    cache: dict,
    stats: dict
) -> None:

    for prod in root.findall(f".//{q('det')}/{q('prod')}"):

        xprod = prod.find(q("xProd"))

        if (
            xprod is not None
            and (xprod.text or "").strip()
        ):
            original = xprod.text.strip()

            xprod.text = cache.setdefault(
                ("xProd", original),
                fake_nome_produto(
                    key,
                    original
                )
            )

            stats["produtos"] += 1

        ncm = prod.find(q("NCM"))

        if (
            ncm is not None
            and (ncm.text or "").strip()
        ):
            original = ncm.text.strip()

            ncm.text = cache.setdefault(
                ("NCM", original),
                fake_ncm(
                    key,
                    original
                )
            )

            stats["NCM"] += 1

        # ----------------------------------------------------
        # Códigos de barras do produto.
        # cEAN/cEANTrib representam GTIN; cBarra/cBarraTrib
        # podem conter outros padrões de código de barras.
        # Se a tag não existir ou estiver vazia, nada é alterado.
        # O código interno do produto (cProd), quantidades e
        # valores permanecem exatamente como no XML original.
        # ----------------------------------------------------

        for tag_codigo_barras in (
            "cEAN",
            "cEANTrib",
            "cBarra",
            "cBarraTrib"
        ):

            codigo_barras = prod.find(
                q(tag_codigo_barras)
            )

            if (
                codigo_barras is None
                or not (codigo_barras.text or "").strip()
            ):
                continue

            original = codigo_barras.text.strip()

            if original.upper() == "SEM GTIN":
                continue

            codigo_barras.text = cache.setdefault(
                ("COD_BARRAS", original),
                fake_codigo_barras(
                    key,
                    original
                )
            )

            stats["codigos_barras"] += 1


# ============================================================
# SANITIZAÇÃO DE TEXTOS
# ============================================================

FREE_TEXT_TAGS = {
    "infCpl",
    "infAdFisco",
    "infAdProd",
    "xTexto",
    "xEnder",
}


def _sanitizar_textos(
    root,
    stats: dict
) -> None:
    """Suprime textos livres e dados de contato sem valor analítico."""

    for el in root.iter():
        tag = local_name(el.tag)

        if (
            tag in FREE_TEXT_TAGS
            and el.text
            and el.text.strip()
        ):
            el.text = "[TEXTO SUPRIMIDO]"
            stats["texto_livre"] += 1

        elif tag in ("email", "fone"):
            if el.text and el.text.strip():
                el.text = "[SUPRIMIDO]"
                stats["contato"] += 1



# ============================================================
# REMOÇÃO DE GRUPOS SEM UTILIDADE ANALÍTICA
# ============================================================

def _remover_nos_sem_utilidade_analitica(
    root,
    stats: dict
) -> None:
    """Remove grupos que não participam do modelo analítico."""

    for parent in root.iter():
        for child in list(parent):
            if child.tag in (
                q("autXML"),
                q("infRespTec"),
                q("obsCont"),
                q("xPed"),
                q("nFCI"),
                q("nProt"),
                q("digVal"),
                q("nFat")
            ):
                parent.remove(child)
                if child.tag == q("obsCont"):
                    stats["observacoes"] += 1


# ============================================================
# INSCRIÇÕES FISCAIS E REFERÊNCIAS NF-e
# ============================================================

def _pseudonimizar_inscricoes(root, key: str, cache: dict, stats: dict) -> None:
    for el in root.iter():
        tag = local_name(el.tag)
        if tag not in {"IE", "IEST", "IM"}:
            continue
        original = (el.text or "").strip()
        if not original or original.upper() == "ISENTO":
            continue
        novo = cache.setdefault(
            (tag, original),
            fake_numeric(key, f"{tag}:DW", original, len(original))
        )
        el.text = novo
        stats["inscricoes"] += 1


def _pseudonimizar_chave_referencia(chave_original: str, key: str, cache: dict) -> str | None:
    chave = (chave_original or "").strip().upper()
    if not re.fullmatch(r"[A-Z0-9]{44}", chave):
        return None
    cnpj_original = chave[6:20]
    novo_cnpj = cache.setdefault(("CNPJ", cnpj_original), fake_cnpj(key, cnpj_original))
    # Usa exatamente a mesma regra aplicada quando a própria NF-e é
    # processada, preservando a integridade referencial no DW.
    original_nnf = chave[25:34]
    novo_nnf = fake_numeric(
        key,
        "nNF",
        f"{chave}|{original_nnf}",
        9
    )
    novo_cnf = fake_numeric(
        key,
        "cNF",
        chave,
        8
    )
    corpo = (
        chave[:6]
        + novo_cnpj
        + chave[20:25]
        + novo_nnf
        + chave[34:35]
        + novo_cnf
    )
    return corpo + str(_dv_chave_nfe(corpo))


def _pseudonimizar_referencias_nfe(root, key: str, cache: dict, stats: dict) -> None:
    """
    Trata chaves de acesso que referenciam OUTROS documentos (ex.: nota de
    devolução apontando para a nota de origem). O chNFe do PRÓPRIO
    documento (ide/dentro de protNFe) é tratado separadamente em
    pseudonimizar_xml, reaproveitando a mesma nova chave já calculada -
    por isso "chNFe" não entra nesta lista.
    """
    tags = {"refNFe", "refNFeSig", "chNFeRef"}
    for el in root.iter():
        if local_name(el.tag) not in tags or not (el.text or "").strip():
            continue
        nova = _pseudonimizar_chave_referencia(el.text, key, cache)
        if nova:
            el.text = nova
            stats["referencias"] += 1


# ============================================================
# PROCESSAMENTO DO XML
# ============================================================

def pseudonimizar_xml(
    caminho_entrada: str,
    caminho_saida: str,
    key: str
) -> dict:

    tree = ET.parse(
        caminho_entrada
    )

    root = tree.getroot()

    # IMPORTANTE:
    # cache precisa existir antes de ser usado.
    cache = {}

    # Mapeia chave_original -> nova_chave para este documento, garantindo
    # que toda ocorrência da MESMA chave (ex.: infNFe/@Id e o chNFe
    # dentro de protNFe) fique sincronizada com o mesmo valor.
    chaves_mapeadas = {}

    stats = {
        "CNPJ": 0,
        "CPF": 0,
        "nomes": 0,
        "xFant": 0,
        "inscricoes": 0,
        "endereco": 0,
        "texto_livre": 0,
        "contato": 0,
        "observacoes": 0,
        "referencias": 0,
        "produtos": 0,
        "NCM": 0,
        "codigos_barras": 0,
    }

    # ========================================================
    # 1. EMITENTE / DESTINATÁRIO / TRANSPORTADOR
    # ========================================================

    for infNFe in root.findall(
        f".//{q('infNFe')}"
    ):

        _pseudonimizar_pessoa(
            infNFe.find(q("emit")),
            key,
            cache,
            stats
        )

        _pseudonimizar_pessoa(
            infNFe.find(q("dest")),
            key,
            cache,
            stats
        )

        transp = infNFe.find(
            q("transp")
        )

        if transp is not None:

            transporta = transp.find(
                q("transporta")
            )

            if transporta is not None:

                _pseudonimizar_pessoa(
                    transporta,
                    key,
                    cache,
                    stats
                )

                xender = transporta.find(
                    q("xEnder")
                )

                if (
                    xender is not None
                    and (xender.text or "").strip()
                ):

                    xender.text = (
                        "DADO_SUPRIMIDO"
                    )

                    stats["endereco"] += 1


        # ====================================================
        # 3. RECUPERA A CHAVE ORIGINAL
        # ====================================================

        id_attr = infNFe.get(
            "Id",
            ""
        )

        match = re.search(
            r"([A-Z0-9]{44})",
            id_attr
        )

        chave_original = (
            match.group(1)
            if match
            else None
        )

        # ====================================================
        # 4. RECUPERA NOVO CNPJ DO EMITENTE
        # ====================================================

        emit = infNFe.find(
            q("emit")
        )

        cnpj_emit = ""

        if emit is not None:

            cnpj_el = emit.find(
                q("CNPJ")
            )

            if (
                cnpj_el is not None
                and (cnpj_el.text or "").strip()
            ):

                cnpj_emit = (
                    cnpj_el.text.strip()
                )

        # ====================================================
        # 5. IDENTIFICADORES DO DOCUMENTO
        # ====================================================

        novo_nnf = None

        nnf_el = infNFe.find(
            f"./{q('ide')}/{q('nNF')}"
        )

        if (
            nnf_el is not None
            and (nnf_el.text or "").strip()
        ):
            original_nnf = nnf_el.text.strip().zfill(9)[-9:]
            referencia = f"{chave_original or ''}|{original_nnf}"

            novo_nnf = fake_numeric(
                key,
                "nNF",
                referencia,
                9
            )

            nnf_el.text = novo_nnf



        # ====================================================
        # 6. NOVA CHAVE DE ACESSO
        # ====================================================

        if (
            chave_original
            and cnpj_emit
        ):

            nova_chave = (
                recalcula_chave_acesso(
                    chave_original,
                    cnpj_emit,
                    key,
                    novo_nnf=novo_nnf
                )
            )

            if nova_chave:

                chaves_mapeadas[chave_original.strip().upper()] = nova_chave

                # ------------------------------------------
                # infNFe/@Id
                # ------------------------------------------

                infNFe.set(
                    "Id",
                    "NFe" + nova_chave
                )

                ide = infNFe.find(
                    q("ide")
                )

                if ide is not None:

                    # --------------------------------------
                    # cNF
                    # --------------------------------------

                    cnf_el = ide.find(
                        q("cNF")
                    )

                    if cnf_el is not None:

                        cnf_el.text = (
                            nova_chave[35:43]
                        )

                    # --------------------------------------
                    # cDV
                    # --------------------------------------

                    cdv_el = ide.find(
                        q("cDV")
                    )

                    if cdv_el is not None:

                        cdv_el.text = (
                            nova_chave[-1]
                        )

    # ------------------------------------------------------
    # Sincroniza qualquer chNFe que se refira ao PRÓPRIO
    # documento (ex.: protNFe/infProt/chNFe) com a mesma nova
    # chave já calculada acima - evita vazar nNF/cNF originais.
    # ------------------------------------------------------

    for chnfe_el in root.findall(f".//{q('chNFe')}"):
        if not (chnfe_el.text or "").strip():
            continue
        original_limpo = re.sub(r"[^A-Za-z0-9]", "", chnfe_el.text).upper()
        if original_limpo in chaves_mapeadas:
            chnfe_el.text = chaves_mapeadas[original_limpo]


    # ========================================================
    # 7. SANITIZA TEXTOS E IDENTIFICADORES
    # ========================================================

    _remover_nos_sem_utilidade_analitica(
        root,
        stats
    )

    _pseudonimizar_inscricoes(root, key, cache, stats)
    _pseudonimizar_referencias_nfe(root, key, cache, stats)
    _pseudonimizar_produtos(root, key, cache, stats)

    _sanitizar_textos(
        root,
        stats
    )

    # ========================================================
    # 8. REMOVE ASSINATURA DIGITAL
    # ========================================================

    for parent in root.iter():

        for child in list(parent):

            if (
                child.tag
                == f"{{{DSIG_NS}}}Signature"
            ):

                parent.remove(
                    child
                )

    # ========================================================
    # 9. REMOVE DIGEST DA ASSINATURA ORIGINAL
    # ========================================================

    for digval in root.findall(
        f".//{q('digVal')}"
    ):

        if digval.text:

            digval.text = (
                "[SUPRIMIDO]"
            )

    # ========================================================
    # 10. VALIDA CPF/CNPJ GERADOS
    # ========================================================

    for el in root.iter():

        tag = local_name(
            el.tag
        )

        if (
            tag == "CNPJ"
            and el.text
        ):

            if not validar_cnpj(
                el.text
            ):

                raise ValueError(
                    "CNPJ sintético inválido "
                    f"em {caminho_entrada}"
                )

        if (
            tag == "CPF"
            and el.text
        ):

            if not validar_cpf(
                el.text
            ):

                raise ValueError(
                    "CPF sintético inválido "
                    f"em {caminho_entrada}"
                )

    # ========================================================
    # 11. VALIDAÇÃO FINAL
    # ========================================================

    _validar_resultado_nfe(root, caminho_entrada)

    # ========================================================
    # 12. ESCREVE ARQUIVO
    # ========================================================

    os.makedirs(
        os.path.dirname(
            caminho_saida
        ) or ".",
        exist_ok=True
    )

    tree.write(
        caminho_saida,
        encoding="utf-8",
        xml_declaration=True
    )

    return {
        "status": "ok",
        "arquivo": os.path.basename(
            caminho_entrada
        ),
        "stats": stats
    }


# ============================================================
# VALIDAÇÃO FINAL DA NF-e PSEUDONIMIZADA
# ============================================================

def _validar_resultado_nfe(root, caminho_entrada: str) -> None:
    chaves_documento = set()

    for infNFe in root.findall(f".//{q('infNFe')}"):
        id_attr = infNFe.get("Id", "")
        if not re.fullmatch(r"NFe[A-Z0-9]{44}", id_attr):
            raise ValueError(f"infNFe/@Id inválido após pseudonimização: {caminho_entrada}")

        chave = id_attr[3:]
        chaves_documento.add(chave)

        if _dv_chave_nfe(chave[:43]) != int(chave[43]):
            raise ValueError(f"DV da chave de acesso inválido após pseudonimização: {caminho_entrada}")

        ide = infNFe.find(q("ide"))
        if ide is not None:
            cnf = ide.find(q("cNF"))
            if cnf is not None and (cnf.text or "") != chave[35:43]:
                raise ValueError(f"cNF incompatível com a chave de acesso: {caminho_entrada}")
            cdv = ide.find(q("cDV"))
            if cdv is not None and (cdv.text or "") != chave[43]:
                raise ValueError(f"cDV incompatível com a chave de acesso: {caminho_entrada}")

    # Se houver protocolo de autorização, seu chNFe deve corresponder
    # exatamente a uma das chaves pseudonimizadas dos infNFe presentes.
    for chnfe_el in root.findall(f".//{q('protNFe')}/{q('infProt')}/{q('chNFe')}"):
        chnfe = re.sub(r"[^A-Za-z0-9]", "", (chnfe_el.text or "")).upper()
        if chnfe and chnfe not in chaves_documento:
            raise ValueError(
                f"chNFe do protocolo incompatível com infNFe/@Id: {caminho_entrada}"
            )


# ============================================================
# WORKER
# ============================================================

def processar_arquivo_worker(
    entrada: str,
    saida: str,
    key: str
) -> dict:

    try:

        return pseudonimizar_xml(
            entrada,
            saida,
            key
        )

    except Exception as exc:

        return {
            "status": "erro",
            "arquivo": os.path.basename(
                entrada
            ),
            "erro": str(exc)
        }


# ============================================================
# MAIN
# ============================================================

def main() -> None:

    parser = argparse.ArgumentParser(
        description=(
            "Pseudonimizador de XML NF-e "
            "para proteção de dados e preparação analítica (DW)."
        )
    )

    parser.add_argument(
        "-i",
        "--input",
        required=True,
        help=(
            "Pasta contendo os XMLs originais."
        )
    )

    parser.add_argument(
        "-o",
        "--output",
        required=True,
        help=(
            "Pasta de destino dos XMLs protegidos."
        )
    )

    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=min(
            4,
            mp.cpu_count()
        ),
        help=(
            "Quantidade de processos paralelos. "
            "Padrão: até 4."
        )
    )

    args = parser.parse_args()

    input_dir = Path(
        args.input
    )

    output_dir = Path(
        args.output
    )

    # ========================================================
    # VALIDAÇÕES
    # ========================================================

    if not input_dir.is_dir():

        logger.error(
            "Pasta de entrada não encontrada: %s",
            input_dir
        )

        sys.exit(1)

    if args.workers < 1:

        logger.error(
            "--workers deve ser >= 1."
        )

        sys.exit(1)

    # ========================================================
    # LOCALIZA XMLs
    # ========================================================

    arquivos = [
        entry
        for entry in input_dir.iterdir()
        if (
            entry.is_file()
            and entry.suffix.lower()
            == ".xml"
        )
    ]

    if not arquivos:

        logger.warning(
            "Nenhum arquivo XML encontrado."
        )

        return

    # ========================================================
    # CHAVE SECRETA
    # ========================================================

    chave_secreta = getpass(
        "Digite a chave secreta "
        "(não será exibida na tela): "
    ).strip()

    if not chave_secreta:

        logger.error(
            "A chave secreta não pode estar vazia."
        )

        sys.exit(1)

    output_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    if input_dir.resolve() == output_dir.resolve():
        logger.error(
            "A pasta de saída deve ser diferente da pasta de entrada."
        )
        sys.exit(1)

    # ========================================================
    # PROCESSAMENTO
    # ========================================================

    ok = 0
    falhas = 0

    quantidade_workers = min(
        args.workers,
        len(arquivos)
    )

    logger.info(
        "Processando %d XML(s) com %d processo(s)...",
        len(arquivos),
        quantidade_workers
    )

    with ProcessPoolExecutor(
        max_workers=quantidade_workers
    ) as executor:

        futures = {
            executor.submit(
                processar_arquivo_worker,
                str(entrada),
                str(
                    output_dir
                    / entrada.name
                ),
                chave_secreta
            ): entrada.name
            for entrada in arquivos
        }

        for future in as_completed(
            futures
        ):

            nome = futures[
                future
            ]

            try:

                resultado = (
                    future.result()
                )

            except Exception as exc:

                falhas += 1

                logger.error(
                    "[ERRO] %s: %s",
                    nome,
                    exc
                )

                continue

            if (
                resultado["status"]
                == "ok"
            ):

                ok += 1

                logger.info(
                    "[OK] %s",
                    nome
                )

            else:

                falhas += 1

                logger.error(
                    "[ERRO] %s: %s",
                    nome,
                    resultado["erro"]
                )

    # ========================================================
    # FINAL
    # ========================================================

    logger.info(
        "Concluído: %d XML(s) processado(s) | "
        "%d falha(s).",
        ok,
        falhas
    )

    logger.info(
        "A chave secreta não foi gravada "
        "em arquivo ou log."
    )


if __name__ == "__main__":

    mp.freeze_support()

    main()