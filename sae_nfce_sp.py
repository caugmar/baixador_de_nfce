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
    """Extrai cert.pem e key.pem de um .pfx para arquivos temporários.
    Retorna os caminhos; o chamador é responsável por apagá-los."""
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
    """Lista todas as chaves NFC-e no período, paginando automaticamente
    quando cStat=101 (lista incompleta, máx. 2000 chaves por chamada).

    Args:
        data_inicio:      data inicial no formato YYYY-MM-DD
        data_fim:         data final no formato YYYY-MM-DD
        certificado_path: caminho do arquivo .pfx
        senha:            senha do certificado
        homologacao:      True = ambiente de homologação

    Returns:
        lista de chaves de acesso (44 dígitos), sem duplicatas
    """
    if homologacao:
        url_wsdl = (
            "https://homologacao.nfce.fazenda.sp.gov.br/ws/NFCeListagemChaves.asmx"
        )
    else:
        url_wsdl = "https://nfce.fazenda.sp.gov.br/ws/NFCeListagemChaves.asmx"

    action_soap = (
        "http://www.portalfiscal.inf.br/nfe/wsdl/NFCeListagemChaves/nfceListagemChaves"
    )
    headers = {
        "Content-Type": f'application/soap+xml; charset=utf-8; action="{action_soap}"',
    }
    ns = {"ns": "http://www.portalfiscal.inf.br/nfe"}

    todas_chaves = []
    dh_ini = f"{data_inicio}T00:00"
    dh_fim = f"{data_fim}T23:59"
    pagina = 1
    dh_ult_anterior = None

    path_cert = path_key = None
    try:
        path_cert, path_key = _extrair_pems_do_pfx(certificado_path, senha)
        session = requests.Session()

        while True:
            print(f"  Página {pagina}: {dh_ini} → {dh_fim}")

            xml_soap = (
                '<?xml version="1.0" encoding="utf-8"?>'
                '<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
                ' xmlns:xsd="http://www.w3.org/2001/XMLSchema"'
                ' xmlns:soap="http://www.w3.org/2003/05/soap-envelope">'
                "<soap:Body>"
                '<nfeDadosMsg xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/NFCeListagemChaves">'
                '<nfceListagemChaves xmlns="http://www.portalfiscal.inf.br/nfe" versao="1.00">'
                f"<tpAmb>{'2' if homologacao else '1'}</tpAmb>"
                f"<dataHoraInicial>{dh_ini}</dataHoraInicial>"
                f"<dataHoraFinal>{dh_fim}</dataHoraFinal>"
                "</nfceListagemChaves>"
                "</nfeDadosMsg>"
                "</soap:Body>"
                "</soap:Envelope>"
            )

            resposta = session.post(
                url_wsdl,
                data=xml_soap.encode("utf-8"),
                headers=headers,
                cert=(path_cert, path_key),
                verify=certifi_icpbr.where(),
            )

            if resposta.status_code != 200:
                print(f"  Erro HTTP {resposta.status_code}: {resposta.text}")
                break

            root = etree.fromstring(resposta.content)
            cStat = (root.xpath("//ns:cStat/text()", namespaces=ns) or ["?"])[0]
            xMotivo = (root.xpath("//ns:xMotivo/text()", namespaces=ns) or [""])[0]
            chaves = root.xpath("//ns:chNFCe/text()", namespaces=ns)
            dh_ult = (root.xpath("//ns:dhEmisUltNfce/text()", namespaces=ns) or [None])[
                0
            ]

            todas_chaves.extend(chaves)
            print(
                f"  cStat {cStat}: {xMotivo} "
                f"(+{len(chaves)} chaves, total {len(todas_chaves)})"
            )

            if cStat == "101":
                # Lista incompleta — avança cursor para a próxima página
                if not dh_ult:
                    print(
                        "  Aviso: cStat=101 sem dhEmisUltNfce. Interrompendo paginação."
                    )
                    break
                if dh_ult == dh_ult_anterior:
                    print(
                        "  Aviso: dhEmisUltNfce repetido. Interrompendo para evitar loop."
                    )
                    break
                # dhEmisUltNfce vem como YYYY-MM-DDTHH:MM:SS — trunca para HH:MM
                dh_ini = dh_ult[:16]
                dh_ult_anterior = dh_ult
                pagina += 1

            elif cStat in ("100", "107"):
                # 100 = sucesso completo; 107 = sucesso sem registros
                break

            else:
                print(f"  Retorno inesperado [{cStat}]: {xMotivo}")
                break

    except Exception as e:
        print(f"Falha de comunicação (ListagemChaves): {e}")

    finally:
        for p in (path_cert, path_key):
            if p and os.path.exists(p):
                os.remove(p)

    # Remove duplicatas que surgem na fronteira entre páginas, preservando ordem
    return list(dict.fromkeys(todas_chaves))


def baixar_xmls_sae_sp(
    chaves,
    certificado_path,
    senha,
    homologacao=False,
    diretorio="notas",
    intervalo_segundos=1,
):
    """Baixa o XML de cada NFC-e da lista de chaves e salva em `diretorio/`.

    Args:
        chaves:              lista de chaves de 44 dígitos
        certificado_path:    caminho do arquivo .pfx
        senha:               senha do certificado
        homologacao:         True = ambiente de homologação
        diretorio:           pasta de destino (criada automaticamente se não existir)
        intervalo_segundos:  pausa entre requisições para respeitar o rate limit da SEFAZ

    Returns:
        dict {"ok": [chaves baixadas], "erro": [chaves com falha]}
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
    total = len(chaves)
    path_cert = path_key = None

    try:
        path_cert, path_key = _extrair_pems_do_pfx(certificado_path, senha)
        session = requests.Session()

        for i, chave in enumerate(chaves, 1):
            destino = os.path.join(diretorio, f"{chave}.xml")

            # Pula arquivos já baixados (permite retomar downloads interrompidos)
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
    DATA_DE = "2026-04-04"
    DATA_ATE = "2026-04-15"

    print("Listando chaves NFC-e no SAE-SP...")
    chaves = listar_chaves_sae_sp(
        data_inicio=DATA_DE,
        data_fim=DATA_ATE,
        certificado_path=CERTIFICADO,
        senha=SENHA_CERT,
        homologacao=False,
    )
    print(f"\n{len(chaves)} chaves encontradas.\n")

    if chaves:
        print("Baixando XMLs...")
        baixar_xmls_sae_sp(
            chaves=chaves,
            certificado_path=CERTIFICADO,
            senha=SENHA_CERT,
            homologacao=False,
        )
