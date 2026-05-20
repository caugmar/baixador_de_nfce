import os
import time
import tempfile
import requests
import certifi_icpbr
from lxml import etree
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
)
from cryptography.hazmat.primitives.serialization.pkcs12 import (
    load_key_and_certificates,
)


def _extrair_pems_do_pfx(pfx_path, senha):
    with open(pfx_path, "rb") as f:
        pfx_data = f.read()
    senha_bytes = senha.encode() if isinstance(senha, str) else senha
    chave_privada, certificado, _ = load_key_and_certificates(pfx_data, senha_bytes)
    cert_pem = certificado.public_bytes(Encoding.PEM)
    key_pem = chave_privada.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    )
    fd_cert, path_cert = tempfile.mkstemp(suffix=".pem", prefix="nfe_cert_")
    fd_key, path_key = tempfile.mkstemp(suffix=".pem", prefix="nfe_key_")
    try:
        os.write(fd_cert, cert_pem)
        os.write(fd_key, key_pem)
    finally:
        os.close(fd_cert)
        os.close(fd_key)
    return path_cert, path_key


def listar_chaves_sae_sp(
    data_inicio, data_fim, certificado_path, senha, homologacao=False
):
    if homologacao:
        url_wsdl = (
            "https://homologacao.nfce.fazenda.sp.gov.br/ws/NFCeListagemChaves.asmx"
        )
    else:
        url_wsdl = "https://nfce.fazenda.sp.gov.br/ws/NFCeListagemChaves.asmx"

    action_soap = (
        "http://www.portalfiscal.inf.br/nfe/wsdl/NFCeListagemChaves/nfceListagemChaves"
    )
    xml_soap = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
        ' xmlns:xsd="http://www.w3.org/2001/XMLSchema"'
        ' xmlns:soap="http://www.w3.org/2003/05/soap-envelope">'
        "<soap:Body>"
        '<nfeDadosMsg xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/NFCeListagemChaves">'
        '<nfceListagemChaves xmlns="http://www.portalfiscal.inf.br/nfe" versao="1.00">'
        f"<tpAmb>{'2' if homologacao else '1'}</tpAmb>"
        f"<dataHoraInicial>{data_inicio}T00:00</dataHoraInicial>"
        f"<dataHoraFinal>{data_fim}T23:59</dataHoraFinal>"
        "</nfceListagemChaves>"
        "</nfeDadosMsg>"
        "</soap:Body>"
        "</soap:Envelope>"
    )
    headers = {
        "Content-Type": f'application/soap+xml; charset=utf-8; action="{action_soap}"',
    }

    path_cert = path_key = None
    try:
        path_cert, path_key = _extrair_pems_do_pfx(certificado_path, senha)
        session = requests.Session()
        resposta = session.post(
            url_wsdl,
            data=xml_soap.encode("utf-8"),
            headers=headers,
            cert=(path_cert, path_key),
            verify=certifi_icpbr.where(),
        )
        if resposta.status_code == 200:
            return _parse_listagem(resposta.content, homologacao)
        else:
            print(f"Erro HTTP {resposta.status_code}: {resposta.text}")
            return []
    except Exception as e:
        print(f"Falha de comunicação (ListagemChaves): {e}")
        return []
    finally:
        for p in (path_cert, path_key):
            if p and os.path.exists(p):
                os.remove(p)


def _parse_listagem(xml_conteudo, homologacao):
    """Extrai lista de chaves da resposta. Se cStat=101 (lista incompleta),
    retorna as chaves disponíveis e avisa — o chamador deve subdividir o período."""
    ns = {"ns": "http://www.portalfiscal.inf.br/nfe"}
    root = etree.fromstring(xml_conteudo)
    chaves = root.xpath("//ns:chNFCe/text()", namespaces=ns)
    cStat = (root.xpath("//ns:cStat/text()", namespaces=ns) or ["?"])[0]
    xMotivo = (root.xpath("//ns:xMotivo/text()", namespaces=ns) or [""])[0]

    if cStat == "101":
        dh_ult = (root.xpath("//ns:dhEmisUltNfce/text()", namespaces=ns) or ["?"])[0]
        print(
            f"Aviso: lista incompleta (máx. 2000 chaves atingido). "
            f"Última emissão retornada: {dh_ult}. Subdivida o período."
        )
    elif cStat not in ("100", "107"):
        print(f"Retorno SEFAZ [{cStat}]: {xMotivo}")

    return chaves


def baixar_xmls_sae_sp(
    chaves,
    certificado_path,
    senha,
    homologacao=False,
    diretorio="notas",
    intervalo_segundos=2,
):
    """Baixa o XML de cada NFC-e da lista de chaves e salva em `diretorio/`.

    Args:
        chaves:              lista de chaves de 44 dígitos
        certificado_path:    caminho do .pfx
        senha:               senha do certificado
        homologacao:         True = ambiente de homologação
        diretorio:           pasta de destino (criada se não existir)
        intervalo_segundos:  pausa entre requisições para respeitar o rate limit

    Returns:
        dict com {"ok": [...], "erro": [...]} listando chaves processadas
    """
    if homologacao:
        url_wsdl = "https://homologacao.nfce.fazenda.sp.gov.br/ws/NFCeDownloadXML.asmx"
    else:
        url_wsdl = "https://nfce.fazenda.sp.gov.br/ws/NFCeDownloadXML.asmx"

    action_soap = (
        "http://www.portalfiscal.inf.br/nfe/wsdl/NFCeDownloadXML/nfceDownloadXML"
    )
    headers = {
        "Content-Type": f'application/soap+xml; charset=utf-8; action="{action_soap}"',
    }
    ns = {
        "soap": "http://www.w3.org/2003/05/soap-envelope",
        "ns": "http://www.portalfiscal.inf.br/nfe",
    }

    os.makedirs(diretorio, exist_ok=True)

    resultado = {"ok": [], "erro": []}
    path_cert = path_key = None

    try:
        path_cert, path_key = _extrair_pems_do_pfx(certificado_path, senha)
        session = requests.Session()
        total = len(chaves)

        for i, chave in enumerate(chaves, 1):
            destino = os.path.join(diretorio, f"{chave}.xml")

            # Pula se já foi baixado anteriormente
            if os.path.exists(destino):
                print(f"[{i}/{total}] {chave} — já existe, pulando.")
                resultado["ok"].append(chave)
                continue

            xml_soap = (
                '<?xml version="1.0" encoding="utf-8"?>'
                '<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
                ' xmlns:xsd="http://www.w3.org/2001/XMLSchema"'
                ' xmlns:soap="http://www.w3.org/2003/05/soap-envelope">'
                "<soap:Body>"
                '<nfeDadosMsg xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/NFCeDownloadXML">'
                '<nfceDownloadXML xmlns="http://www.portalfiscal.inf.br/nfe" versao="1.00">'
                f"<tpAmb>{'2' if homologacao else '1'}</tpAmb>"
                f"<chNFCe>{chave}</chNFCe>"
                "</nfceDownloadXML>"
                "</nfeDadosMsg>"
                "</soap:Body>"
                "</soap:Envelope>"
            )

            try:
                resposta = session.post(
                    url_wsdl,
                    data=xml_soap.encode("utf-8"),
                    headers=headers,
                    cert=(path_cert, path_key),
                    verify=certifi_icpbr.where(),
                )

                if resposta.status_code != 200:
                    print(f"[{i}/{total}] {chave} — HTTP {resposta.status_code}")
                    resultado["erro"].append(chave)
                    continue

                root = etree.fromstring(resposta.content)
                cStat = (root.xpath("//ns:cStat/text()", namespaces=ns) or ["?"])[0]
                xMotivo = (root.xpath("//ns:xMotivo/text()", namespaces=ns) or [""])[0]

                if cStat != "200":
                    print(f"[{i}/{total}] {chave} — [{cStat}] {xMotivo}")
                    resultado["erro"].append(chave)
                    continue

                # Extrai o elemento <NFe> e serializa como XML completo
                nfe_els = root.xpath("//ns:NFe", namespaces=ns)
                if not nfe_els:
                    print(f"[{i}/{total}] {chave} — cStat 200 mas <NFe> não encontrado")
                    resultado["erro"].append(chave)
                    continue

                xml_nfe = etree.tostring(
                    nfe_els[0],
                    xml_declaration=True,
                    encoding="utf-8",
                    pretty_print=True,
                )
                with open(destino, "wb") as f:
                    f.write(xml_nfe)

                print(f"[{i}/{total}] {chave} — salvo em {destino}")
                resultado["ok"].append(chave)

            except Exception as e:
                print(f"[{i}/{total}] {chave} — exceção: {e}")
                resultado["erro"].append(chave)

            # Respeita o rate limit da SEFAZ entre requisições
            if i < total:
                time.sleep(intervalo_segundos)

    finally:
        for p in (path_cert, path_key):
            if p and os.path.exists(p):
                os.remove(p)

    print(
        f"\nConcluído: {len(resultado['ok'])} baixados, "
        f"{len(resultado['erro'])} com erro."
    )
    return resultado


# --- Exemplo de uso ---
if __name__ == "__main__":
    CERTIFICADO = "cert.pfx"
    SENHA_CERT = "1234"
    DATA_DE = "2026-04-01"
    DATA_ATE = "2026-04-03"

    print("Listando chaves...")
    chaves = listar_chaves_sae_sp(
        data_inicio=DATA_DE,
        data_fim=DATA_ATE,
        certificado_path=CERTIFICADO,
        senha=SENHA_CERT,
        homologacao=False,
    )
    print(f"{len(chaves)} chaves encontradas.\n")

    if chaves:
        print("Baixando XMLs...")
        baixar_xmls_sae_sp(
            chaves=chaves,
            certificado_path=CERTIFICADO,
            senha=SENHA_CERT,
            homologacao=False,
        )
