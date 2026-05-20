import os
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
    cnpj, data_inicio, data_fim, certificado_path, senha, homologacao=False
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

    # SOAP 1.2: namespace correto e Content-Type application/soap+xml

    # XML compacto — sem espaços nem quebras entre tags
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

        ##### DEBUG #####

        wsdl_resp = session.get(
            url_wsdl + "?WSDL",
            cert=(path_cert, path_key),
            verify=certifi_icpbr.where(),
        )
        print(wsdl_resp.text[:3000])  # ver o WSDL cru
        wsdl_root = etree.fromstring(wsdl_resp.content)
        for el in wsdl_root.iter():
            action = el.get(
                "{http://schemas.xmlsoap.org/wsdl/soap12/}operation"
            ) or el.get("soapAction")
            if action:
                print("soapAction encontrada:", action)
            if "operation" in el.tag.lower():
                print("operation:", el.get("name"))

        ##### DEBUG #####

        resposta = session.post(
            url_wsdl,
            data=xml_soap.encode("utf-8"),
            headers=headers,
            cert=(path_cert, path_key),
            verify=certifi_icpbr.where(),
        )

        if resposta.status_code == 200:
            print("RESPOSTA RAW:", resposta.text)  # DEBUG
            return traduzir_resposta_sae(resposta.content)
        else:
            print(f"Erro na requisição WebService: Status {resposta.status_code}")
            print(resposta.text)
            return []

    except Exception as e:
        print(f"Falha de comunicação com o SAE NFC-e SP: {e}")
        return []

    finally:
        for p in (path_cert, path_key):
            if p and os.path.exists(p):
                os.remove(p)


def traduzir_resposta_sae(xml_conteudo):
    chaves = []
    try:
        root = etree.fromstring(xml_conteudo)
        namespaces = {
            "soap": "http://www.w3.org/2003/05/soap-envelope",
            "wsdl_ns": "http://www.portalfiscal.inf.br/nfe/wsdl/NFCeListagemChaves",
            "ns": "http://www.portalfiscal.inf.br/nfe",
        }

        # Chaves ficam dentro de retNfceListagemChaves
        chaves.extend(root.xpath("//ns:chNFCe/text()", namespaces=namespaces))

        xMotivo = root.xpath("//ns:xMotivo/text()", namespaces=namespaces)
        cStat = root.xpath("//ns:cStat/text()", namespaces=namespaces)
        if cStat:
            print(f"cStat: {cStat[0]}")
        if xMotivo:
            print(f"Retorno da SEFAZ: {xMotivo[0]}")

    except Exception as e:
        print(f"Erro ao processar o XML de resposta: {e}")

    return chaves


if __name__ == "__main__":
    CNPJ_CONTRIBUINTE = "09347349000179"
    CERTIFICADO = "cert.pfx"
    SENHA_CERT = "1234"
    DATA_DE = "2026-04-01"
    DATA_ATE = "2026-04-03"

    print("Consultando chaves de NFC-e no SAE-SP...")
    lista_chaves = listar_chaves_sae_sp(
        cnpj=CNPJ_CONTRIBUINTE,
        data_inicio=DATA_DE,
        data_fim=DATA_ATE,
        certificado_path=CERTIFICADO,
        senha=SENHA_CERT,
        homologacao=False,
    )

    print(
        f"\nBusca finalizada. Foram encontradas {len(lista_chaves)} chaves de acesso."
    )
    for c in lista_chaves:
        print(f"Chave NFC-e: {c}")
