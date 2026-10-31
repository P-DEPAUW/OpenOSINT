"""Regression and privacy checks for optional external OSINT integrations."""
import asyncio
import json
from unittest.mock import Mock

import pytest

from openosint.tools import extra_sources as ex


def test_domain_validation_rejects_bad_inputs():
    for domain in ('https://example.com', '-oA/tmp/evil', 'localhost', '192.168.1.1', 'x.local', '', 'foo..com'):
        with pytest.raises(ValueError):
            ex._domain(domain)
    assert ex._domain('EXAMPLE.COM.') == 'example.com'


def test_image_requires_public_https():
    for url in ('http://example.com/a.png', 'https://127.0.0.1/a.png', 'https://localhost/a.png', 'https://user:pass@example.com/a.png', 'file:///tmp/a.png', 'https://example.com'):
        with pytest.raises(ValueError):
            ex._image_url(url)
    assert ex._image_url('https://example.com/public.jpg') == 'https://example.com/public.jpg'


def test_certificates_filters_domains_and_dedupes(monkeypatch):
    def fake(url, **kwargs):
        assert url == "https://api.certspotter.com/v1/issuances"
        assert kwargs["params"]["domain"] == "example.com"
        return [{"dns_names": ["WWW.example.com", "*.test.example.com"]},
                {"dns_names": ["example.com", "evil.com", "www.example.com"]}], None
    monkeypatch.setattr(ex, "_json_get", fake)
    result = json.loads(asyncio.run(ex.run_certificates_osint("example.com")))
    assert result["hosts"] == ["example.com", "test.example.com", "www.example.com"]
    assert "SSLMate" in result["source"]


def test_certificates_fallback_on_provider_error(monkeypatch):
    urls = []
    def fake(url, **kwargs):
        urls.append(url)
        if url.endswith("/issuances"):
            return None, "HTTP 429"
        return [{"name_value": "www.example.com"}], None
    monkeypatch.setattr(ex, "_json_get", fake)
    result = json.loads(asyncio.run(ex.run_certificates_osint("example.com")))
    assert result["hosts"] == ["www.example.com"]
    assert urls == ["https://api.certspotter.com/v1/issuances", "https://crt.sh/"]


def test_archive_fallback_when_cdx_unavailable(monkeypatch):
    def fake(url, **kwargs):
        if "cdx" in url:
            return None, "ReadTimeout"
        return {"archived_snapshots": {"closest": {"available": True, "timestamp": "20200101",
               "url": "http://web.archive.org/web/20200101/https://example.com/"}}}, None
    monkeypatch.setattr(ex, "_json_get", fake)
    res = json.loads(asyncio.run(ex.run_archive_osint("example.com")))
    assert "nearest" in res["source"]
    assert res["captures"][0]["archive_url"].startswith("https://web.archive.org/")


def test_archive_limits_and_filters_other_domains(monkeypatch):
    data=[['urlkey','timestamp','original','statuscode'],['x','20200101','https://www.example.com/hello','200'], ['x','20200202','https://evil.net/','200']]
    monkeypatch.setattr(ex, '_json_get', lambda *a, **k: (data,None))
    result=json.loads(asyncio.run(ex.run_archive_osint('example.com')))
    assert len(result['captures']) == 1
    assert result['captures'][0]['timestamp'] == '20200101'


def test_archive_provider_error_no_crash(monkeypatch):
    monkeypatch.setattr(ex,'_json_get',lambda *a,**k:(None,'Provider HTTP 503'))
    assert '503' in asyncio.run(ex.run_archive_osint('example.com'))


def test_lens_requires_key_and_never_calls_provider(monkeypatch):
    monkeypatch.delenv('SERPAPI_API_KEY', raising=False)
    monkeypatch.setattr(ex, '_json_get', lambda *a, **k: pytest.fail('No key; request must not happen'))
    assert 'not run' in asyncio.run(ex.run_lens_osint('https://example.com/photo.png'))


def test_lens_key_private_and_results_bounded(monkeypatch):
    monkeypatch.setenv('SERPAPI_API_KEY','SECRET_THAT_MUST_NOT_LEAK')
    def fake(url, **kw):
        assert url == 'https://serpapi.com/search.json'
        assert kw['params']['api_key'] == 'SECRET_THAT_MUST_NOT_LEAK'
        assert kw['params']['url'] == 'https://example.com/image.png'
        return {'visual_matches':[{'title':'example','link':'https://example.org','private_internal':'NO'}]},None
    monkeypatch.setattr(ex,'_json_get',fake)
    result=asyncio.run(ex.run_lens_osint('https://example.com/image.png'))
    assert 'SECRET_THAT_MUST_NOT_LEAK' not in result
    assert 'private_internal' not in result
    assert json.loads(result)['matches'][0]['title'] == 'example'


def test_lens_error_omits_secret(monkeypatch):
    monkeypatch.setenv('SERPAPI_API_KEY','SECRET_KEY')
    monkeypatch.setattr(ex,'_json_get', lambda *a,**k:(None,'Provider request failed (ConnectionError); no results verified.'))
    text=asyncio.run(ex.run_lens_osint('https://example.com/a.png'))
    assert 'SECRET_KEY' not in text and 'no results verified' in text


def test_nmap_disabled_by_default(monkeypatch):
    monkeypatch.delenv('OPENOSINT_ALLOW_ACTIVE',raising=False)
    monkeypatch.setattr(ex.subprocess,'run',lambda *a,**k: pytest.fail('No active scan'))
    assert 'disabled' in asyncio.run(ex.run_nmap_osint('example.com'))


def test_nmap_argv_no_shell_and_bounded(monkeypatch):
    monkeypatch.setenv('OPENOSINT_ALLOW_ACTIVE','1')
    monkeypatch.setattr(ex.shutil,'which',lambda x:'/usr/local/bin/nmap')
    captured=[]
    def run(args,**kwargs):
        captured.extend(args)
        assert kwargs['timeout'] <= 30 and kwargs['check'] is False
        return Mock(returncode=0,stdout='80/tcp open http',stderr='')
    monkeypatch.setattr(ex.subprocess,'run',run)
    result=asyncio.run(ex.run_nmap_osint('example.com'))
    assert captured[-1] == 'example.com'
    assert '--' in captured
    assert '-p' in captured and '22,80,443,445,8080' in captured
    assert '80/tcp open' in result


def test_nmap_rejects_injection(monkeypatch):
    monkeypatch.setenv('OPENOSINT_ALLOW_ACTIVE','1')
    for value in ['--script=all', 'example.com;rm -rf /', 'bad host']:
        with pytest.raises(ValueError):
            asyncio.run(ex.run_nmap_osint(value))


def test_mcp_tools_are_registered_and_policy_applies(monkeypatch):
    import openosint.mcp_server as m
    monkeypatch.delenv('OPENOSINT_ALLOW_ACTIVE',raising=False)
    names={x.name for x in asyncio.run(m.list_tools())}
    assert {'search_certificates','search_archive'} <= names
    assert 'scan_host_ports' not in names and 'search_lens' not in names
    monkeypatch.setenv('OPENOSINT_ALLOW_ACTIVE','1')
    active_names={x.name for x in asyncio.run(m.list_tools())}
    assert {'scan_host_ports','search_lens'} <= active_names


def test_mcp_call_blocks_active_without_provider(monkeypatch):
    import openosint.mcp_server as m
    monkeypatch.delenv('OPENOSINT_ALLOW_ACTIVE',raising=False)
    result=asyncio.run(m.call_tool('search_lens',{'image_url':'https://example.com/image.png'}))
    assert result.isError is True


def test_mcp_call_passive_execution(monkeypatch):
    import openosint.mcp_server as m
    monkeypatch.delenv('OPENOSINT_ALLOW_ACTIVE',raising=False)
    monkeypatch.setattr(m,'run_certificates_osint',lambda domain: asyncio.sleep(0,result=f'CERT_OK:{domain}'))
    result=asyncio.run(m.call_tool('search_certificates',{'domain':'example.com'}))
    assert result.isError is False and 'CERT_OK:example.com' in result.content[0].text


def test_greynoise_public_ip_validation(monkeypatch):
    for value in ('192.168.68.99', 'localhost', '127.0.0.1', '::1'):
        with pytest.raises(ValueError):
            asyncio.run(ex.run_greynoise_osint(value))


def test_greynoise_result(monkeypatch):
    monkeypatch.delenv('GREYNOISE_API_KEY', raising=False)
    def mock_get(url, **kwargs):
        assert url.endswith('/1.1.1.1')
        assert kwargs['headers'] == {}
        return {'noise': False, 'riot': True, 'classification': 'benign', 'internal_field': 'unreported'}, None
    monkeypatch.setattr(ex, '_json_get', mock_get)
    result=json.loads(asyncio.run(ex.run_greynoise_osint('1.1.1.1')))
    assert result['riot'] is True and 'internal_field' not in result


def test_local_file_metadata(monkeypatch, tmp_path):
    sample=tmp_path/'image.png'
    sample.write_bytes(b'hello')
    monkeypatch.setattr(ex.shutil,'which',lambda _: '/opt/homebrew/bin/exiftool')
    def fake_run(argv, **kwargs):
        assert argv[-1] == str(sample)
        assert '-j' in argv
        return Mock(returncode=0, stdout='[{"FileType":"PNG","ImageWidth":1}]', stderr='')
    monkeypatch.setattr(ex.subprocess,'run',fake_run)
    result=json.loads(asyncio.run(ex.run_metadata_osint(str(sample))))
    assert result['tags']['FileType']=='PNG'


def test_local_file_metadata_rejects_other_paths(tmp_path):
    item = tmp_path / 'script.sh'
    item.write_text('dummy')
    with pytest.raises(ValueError):
        asyncio.run(ex.run_metadata_osint(str(item)))
