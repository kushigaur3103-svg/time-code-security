"""
Master Security Rules & Signatures Bank for TimeCodeSecurity (TCS).
Consolidated Registry:
- Full Gitleaks Ruleset (120+ Cloud, AI, VCS, Finance, & SaaS Signatures)
- Gitleaks Official Allowlists & Stopwords (False-Positive Suppression)
- PyCQA Bandit & CodeQL Enterprise Sinks (39 AST Injection Sinks)
"""

# =====================================================================
# 1. BANDIT & CODEQL ENTERPRISE CODE SINKS (AST Engine)
# =====================================================================
ENTERPRISE_SINKS_BANK = {
    # CWE-502: Insecure Deserialization & Socket Injection
    "pickle.loads": {"cwe": "CWE-502", "severity": "CRITICAL"},
    "pickle.load": {"cwe": "CWE-502", "severity": "CRITICAL"},
    "_pickle.loads": {"cwe": "CWE-502", "severity": "CRITICAL"},
    "_pickle.load": {"cwe": "CWE-502", "severity": "CRITICAL"},
    "yaml.load": {"cwe": "CWE-502", "severity": "CRITICAL"},
    "yaml.unsafe_load": {"cwe": "CWE-502", "severity": "CRITICAL"},
    "shelve.open": {"cwe": "CWE-502", "severity": "HIGH"},
    "marshal.loads": {"cwe": "CWE-502", "severity": "CRITICAL"},
    "torch.load": {"cwe": "CWE-502", "severity": "CRITICAL"},
    "logging.config.listen": {"cwe": "CWE-502", "severity": "CRITICAL"},

    # CWE-22: Path Traversal & Archive Slip
    "shutil.rmtree": {"cwe": "CWE-22", "severity": "HIGH"},
    "zipfile.ZipFile.extractall": {"cwe": "CWE-22", "severity": "CRITICAL", "type": "receiver"},
    "tarfile.TarFile.extractall": {"cwe": "CWE-22", "severity": "CRITICAL", "type": "receiver"},
    "tarfile.extractall": {"cwe": "CWE-22", "severity": "CRITICAL"},

    # CWE-79: Sanitization Bypass / XSS
    "markupsafe.Markup": {"cwe": "CWE-79", "severity": "HIGH"},
    "django.utils.safestring.mark_safe": {"cwe": "CWE-79", "severity": "HIGH"},

    # CWE-295: Broken TLS / Insecure Transport & Host Key Verification
    "paramiko.client.AutoAddPolicy": {"cwe": "CWE-295", "severity": "HIGH"},
    "paramiko.AutoAddPolicy": {"cwe": "CWE-295", "severity": "HIGH"},
    "ssl._create_unverified_context": {"cwe": "CWE-295", "severity": "HIGH"},
    "urllib3.disable_warnings": {"cwe": "CWE-295", "severity": "MEDIUM"},

    # CWE-918: Server-Side Request Forgery (SSRF)
    "urllib.request.urlopen": {"cwe": "CWE-918", "severity": "HIGH"},
    "requests.get": {"cwe": "CWE-918", "severity": "HIGH"},
    "requests.post": {"cwe": "CWE-918", "severity": "HIGH"},
    "requests.put": {"cwe": "CWE-918", "severity": "HIGH"},
    "httpx.get": {"cwe": "CWE-918", "severity": "HIGH"},
    "httpx.post": {"cwe": "CWE-918", "severity": "HIGH"},
    "aiohttp.ClientSession.get": {"cwe": "CWE-918", "severity": "HIGH"},
    "aiohttp.ClientSession.post": {"cwe": "CWE-918", "severity": "HIGH"},

    # CWE-611: XML External Entity (XXE)
    "xml.etree.ElementTree.fromstring": {"cwe": "CWE-611", "severity": "HIGH"},
    "xml.dom.minidom.parseString": {"cwe": "CWE-611", "severity": "HIGH"},
    "xml.dom.minidom.parse": {"cwe": "CWE-611", "severity": "HIGH"},
    "lxml.etree.fromstring": {"cwe": "CWE-611", "severity": "HIGH"},
    "lxml.etree.parse": {"cwe": "CWE-611", "severity": "HIGH"},

    # CWE-601: Open Redirect
    "flask.redirect": {"cwe": "CWE-601", "severity": "MEDIUM"},
    "django.shortcuts.redirect": {"cwe": "CWE-601", "severity": "MEDIUM"},

    # CWE-1333 / CWE-400: Regex Injection / ReDoS / Resource Exhaustion
    "re.compile": {"cwe": "CWE-1333", "severity": "MEDIUM"},
    "regex.compile": {"cwe": "CWE-1333", "severity": "MEDIUM"},
    "re.search": {"cwe": "CWE-400", "severity": "MEDIUM"},
    "re.match": {"cwe": "CWE-400", "severity": "MEDIUM"},

    # CWE-327 / CWE-328: Broken Crypto & Hashing
    "hashlib.md5": {"cwe": "CWE-327", "severity": "MEDIUM"},
    "hashlib.sha1": {"cwe": "CWE-327", "severity": "MEDIUM"},
    "Crypto.Cipher.DES.new": {"cwe": "CWE-327", "severity": "HIGH"},
    "Crypto.Cipher.DES": {"cwe": "CWE-327", "severity": "HIGH"},
    "DES.new": {"cwe": "CWE-327", "severity": "HIGH"},

    # CWE-338: Insecure Randomness for Security Contexts
    "random.random": {"cwe": "CWE-338", "severity": "MEDIUM"},
    "random.randint": {"cwe": "CWE-338", "severity": "MEDIUM"},
    "random.choice": {"cwe": "CWE-338", "severity": "MEDIUM"},
    "random.randrange": {"cwe": "CWE-338", "severity": "MEDIUM"},
    "random.sample": {"cwe": "CWE-338", "severity": "MEDIUM"},

    # CWE-1336: SSTI (Server-Side Template Injection)
    "jinja2.Template": {"cwe": "CWE-1336", "severity": "HIGH"},
    "mako.template.Template": {"cwe": "CWE-1336", "severity": "HIGH"},
}

# =====================================================================
# 2. FULL GITLEAKS OFFICIAL SIGNATURES (120+ SECRETS)
# =====================================================================
GITLEAKS_SECRETS_BANK = {
    # 1Password & Authress
    "1password-secret-key": r"\bA3-[A-Z0-9]{6}-(?:(?:[A-Z0-9]{11})|(?:[A-Z0-9]{6}-[A-Z0-9]{5}))-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b",
    "1password-service-account-token": r"ops_eyJ[a-zA-Z0-9+/]{250,}={0,3}",
    "authress-service-client-access-key": r"\b((?:sc|ext|scauth|authress)_(?i)[a-z0-9]{5,30}\.[a-z0-9]{4,6}\.(?-i:acc)[_-][a-z0-9-]{10,32}\.[a-z0-9+/_=-]{30,120})",

    # AI Platforms
    "adafruit-api-key": r"(?i)[\w.-]{0,50}?(?:adafruit)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9_-]{32})",
    "anthropic-admin-api-key": r"\b(sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA)\b",
    "anthropic-api-key": r"\b(sk-ant-api03-[a-zA-Z0-9_\-]{93}AA)\b",
    "cohere-api-token": r"[\w.-]{0,50}?(?i:[\w.-]{0,50}?(?:cohere|CO_API_KEY)(?:[ \t\w.-]{0,20})[\s'\"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-zA-Z0-9]{40})",
    "huggingface-access-token": r"\b(hf_(?i:[a-z]{34}))\b",
    "huggingface-organization-api-token": r"\b(api_org_(?i:[a-z]{34}))\b",
    "openai-api-key": r"\b(sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})\b|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})",
    "perplexity-api-key": r"\b(pplx-[a-zA-Z0-9]{48})\b",
    "privateai-api-token": r"[\w.-]{0,50}?(?i:[\w.-]{0,50}?(?:private[_-]?ai)(?:[ \t\w.-]{0,20})[\s'\"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9]{32})",

    # Adobe, Age & Airtable
    "adobe-client-id": r"(?i)[\w.-]{0,50}?(?:adobe)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-f0-9]{32})",
    "adobe-client-secret": r"\b(p8e-(?i)[a-z0-9]{32})",
    "age-secret-key": r"AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}",
    "airtable-api-key": r"(?i)[\w.-]{0,50}?(?:airtable)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9]{17})",
    "airtable-personnal-access-token": r"\b(pat[[:alnum:]]{14}\.[a-f0-9]{64})\b",
    "algolia-api-key": r"(?i)[\w.-]{0,50}?(?:algolia)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9]{32})",

    # Cloud Giants: Alibaba, AWS, Azure, GCP
    "alibaba-access-key-id": r"\b(LTAI(?i)[a-z0-9]{20})\b",
    "alibaba-secret-key": r"(?i)[\w.-]{0,50}?(?:alibaba)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9]{30})",
    "aws-access-token": r"\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b",
    "aws-amazon-bedrock-api-key-long-lived": r"\b(ABSK[A-Za-z0-9+/]{109,269}={0,2})\b",
    "aws-amazon-bedrock-api-key-short-lived": r"bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t",
    "azure-ad-client-secret": r"(?:^|[\\'\x60\s>=:(,)])([a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34})(?:$|[\\'\x60\s<),])",
    "gcp-api-key": r"\b(AIza[\w-]{35})\b",

    # Artifactory, Asana, Atlassian, Beamer
    "artifactory-api-key": r"\bAKCp[A-Za-z0-9]{69}\b",
    "artifactory-reference-token": r"\bcmVmd[A-Za-z0-9]{59}\b",
    "asana-client-id": r"(?i)[\w.-]{0,50}?(?:asana)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([0-9]{16})",
    "asana-client-secret": r"(?i)[\w.-]{0,50}?(?:asana)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9]{32})",
    "atlassian-api-token": r"(?i)[\w.-]{0,50}?(?:(?-i:ATLASSIAN|[Aa]tlassian)|(?-i:CONFLUENCE|[Cc]onfluence)|(?-i:JIRA|[Jj]ira))(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9]{20}[a-f0-9]{4})|\b(ATATT3[A-Za-z0-9_\-=]{186})",
    "beamer-api-token": r"(?i)[\w.-]{0,50}?(?:beamer)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}(b_[a-z0-9=_\-]{44})",

    # Bitbucket, Bittrex, Cisco, Clickhouse, Clojars
    "bitbucket-client-id": r"(?i)[\w.-]{0,50}?(?:bitbucket)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9]{32})",
    "bitbucket-client-secret": r"(?i)[\w.-]{0,50}?(?:bitbucket)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9=_\-]{64})",
    "bittrex-access-key": r"(?i)[\w.-]{0,50}?(?:bittrex)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9]{32})",
    "bittrex-secret-key": r"(?i)[\w.-]{0,50}?(?:bittrex)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9]{32})",
    "cisco-meraki-api-key": r"[\w.-]{0,50}?(?i:[\w.-]{0,50}?(?:(?-i:[Mm]eraki|MERAKI))(?:[ \t\w.-]{0,20})[\s'\"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([0-9a-f]{40})",
    "clickhouse-cloud-api-secret-key": r"\b(4b1d[A-Za-z0-9]{38})\b",
    "clojars-api-token": r"(?i)CLOJARS_[a-z0-9]{60}",

    # Cloudflare, Codecov, Coinbase, Confluent, Contentful, cURL
    "cloudflare-api-key": r"(?i)[\w.-]{0,50}?(?:cloudflare)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9_-]{40})",
    "cloudflare-global-api-key": r"(?i)[\w.-]{0,50}?(?:cloudflare)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-f0-9]{37})",
    "cloudflare-origin-ca-key": r"\b(v1\.0-[a-f0-9]{24}-[a-f0-9]{146})\b",
    "codecov-access-token": r"(?i)[\w.-]{0,50}?(?:codecov)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9]{32})",
    "coinbase-access-token": r"(?i)[\w.-]{0,50}?(?:coinbase)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9_-]{64})",
    "confluent-access-token": r"(?i)[\w.-]{0,50}?(?:confluent)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9]{16})",
    "confluent-secret-key": r"(?i)[\w.-]{0,50}?(?:confluent)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9]{64})",
    "contentful-delivery-api-token": r"(?i)[\w.-]{0,50}?(?:contentful)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9=_\-]{43})",
    "curl-auth-header": r"\bcurl\b(?:.*?|.*?(?:[\r\n]{1,2}.*?){1,5})[ \t\n\r](?:-H|--header)(?:=|[ \t]{0,5})(?:\"(?i)(?:Authorization:[ \t]{0,5}(?:Basic[ \t]([a-z0-9+/]{8,}={0,3})|(?:Bearer|(?:Api-)?Token)[ \t]([\w=~@.+/-]{8,})|([\w=~@.+/-]{8,}))|(?:(?:X-(?:[a-z]+-)?)?(?:Api-?)?(?:Key|Token)):[ \t]{0,5}([\w=~@.+/-]{8,}))\"|'(?i)(?:Authorization:[ \t]{0,5}(?:Basic[ \t]([a-z0-9+/]{8,}={0,3})|(?:Bearer|(?:Api-)?Token)[ \t]([\w=~@.+/-]{8,})|([\w=~@.+/-]{8,}))|(?:(?:X-(?:[a-z]+-)?)?(?:Api-?)?(?:Key|Token)):[ \t]{0,5}([\w=~@.+/-]{8,}))')",
    "curl-auth-user": r"\bcurl\b(?:.*|.*(?:[\r\n]{1,2}.*){1,5})[ \t\n\r](?:-u|--user)(?:=|[ \t]{0,5})(\"(:[^\"]{3,}|[^:\"]{3,}:|[^:\"]{3,}:[^\"]{3,})\"|'([^:']{3,}:[^']{3,})'|((?:\"[^\"]{3,}\"|'[^']{3,}'|[\w$@.-]+):(?:\"[^\"]{3,}\"|'[^']{3,}'|[\w${}@.-]+)))",

    # Databricks, Datadog, Defined Networking, DigitalOcean, Discord, Doppler, DroneCI
    "databricks-api-token": r"\b(dapi[a-f0-9]{32}(?:-\d)?)\b",
    "datadog-access-token": r"(?i)[\w.-]{0,50}?(?:datadog)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9]{40})",
    "defined-networking-api-token": r"(?i)[\w.-]{0,50}?(?:dnkey)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}(dnkey-[a-z0-9=_\-]{26}-[a-z0-9=_\-]{52})",
    "digitalocean-access-token": r"\b(doo_v1_[a-f0-9]{64})\b",
    "digitalocean-pat": r"\b(dop_v1_[a-f0-9]{64})\b",
    "digitalocean-refresh-token": r"(?i)\b(dor_v1_[a-f0-9]{64})\b",
    "discord-api-token": r"(?i)[\w.-]{0,50}?(?:discord)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-f0-9]{64})",
    "discord-client-id": r"(?i)[\w.-]{0,50}?(?:discord)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([0-9]{18})",
    "discord-client-secret": r"(?i)[\w.-]{0,50}?(?:discord)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9=_\-]{32})",
    "doppler-api-token": r"dp\.pt\.(?i)[a-z0-9]{43}",
    "droneci-access-token": r"(?i)[\w.-]{0,50}?(?:droneci)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9]{32})",

    # Dropbox, Duffel, Dynatrace, EasyPost, Etsy, Facebook, Fastly, Finicity, Finnhub, Flickr
    "dropbox-api-token": r"(?i)[\w.-]{0,50}?(?:dropbox)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9]{15})",
    "dropbox-long-lived-api-token": r"(?i)[\w.-]{0,50}?(?:dropbox)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9]{11}(AAAAAAAAAA)[a-z0-9\-_=]{43})",
    "dropbox-short-lived-api-token": r"(?i)[\w.-]{0,50}?(?:dropbox)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}(sl\.[a-z0-9\-=_]{135})",
    "duffel-api-token": r"duffel_(?:test|live)_(?i)[a-z0-9_\-=]{43}",
    "dynatrace-api-token": r"dt0c01\.(?i)[a-z0-9]{24}\.[a-z0-9]{64}",
    "easypost-api-token": r"\bEZAK(?i)[a-z0-9]{54}\b",
    "easypost-test-api-token": r"\bEZTK(?i)[a-z0-9]{54}\b",
    "etsy-access-token": r"(?i)[\w.-]{0,50}?(?:(?-i:ETSY|[Ee]tsy))(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9]{24})",
    "facebook-access-token": r"(?i)\b(\d{15,16}(\||%)[0-9a-z\-_]{27,40})",
    "facebook-page-access-token": r"\b(EAA[MC](?i)[a-z0-9]{100,})",
    "facebook-secret": r"(?i)[\w.-]{0,50}?(?:facebook)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-f0-9]{32})",
    "fastly-api-token": r"(?i)[\w.-]{0,50}?(?:fastly)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9=_\-]{32})",
    "finicity-api-token": r"(?i)[\w.-]{0,50}?(?:finicity)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-f0-9]{32})",
    "finicity-client-secret": r"(?i)[\w.-]{0,50}?(?:finicity)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9]{20})",
    "finnhub-access-token": r"(?i)[\w.-]{0,50}?(?:finnhub)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9]{20})",
    "flickr-access-token": r"(?i)[\w.-]{0,50}?(?:flickr)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9]{32})",

    # Flutterwave, Fly.io, Frame.io, Freemius, Freshbooks
    "flutterwave-encryption-key": r"FLWSECK_TEST-(?i)[a-h0-9]{12}",
    "flutterwave-public-key": r"FLWPUBK_TEST-(?i)[a-h0-9]{32}-X",
    "flutterwave-secret-key": r"FLWSECK_TEST-(?i)[a-h0-9]{32}-X",
    "flyio-access-token": r"\b((?:fo1_[\w-]{43}|fm1[ar]_[a-zA-Z0-9+\/]{100,}={0,3}|fm2_[a-zA-Z0-9+\/]{100,}={0,3}))",
    "frameio-api-token": r"fio-u-(?i)[a-z0-9\-_=]{64}",
    "freemius-secret-key": r"(?i)[\"']secret_key[\"']\s*=>\s*[\"'](sk_[\S]{29})[\"']",
    "freshbooks-access-token": r"(?i)[\w.-]{0,50}?(?:freshbooks)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9]{64})",

    # GitHub (5 Rules)
    "github-app-token": r"(?:ghu|ghs)_[0-9a-zA-Z]{36}",
    "github-fine-grained-pat": r"github_pat_\w{82}",
    "github-oauth": r"gho_[0-9a-zA-Z]{36}",
    "github-pat": r"ghp_[0-9a-zA-Z]{36}",
    "github-refresh-token": r"ghr_[0-9a-zA-Z]{36}",

    # GitLab (15 Rules)
    "gitlab-cicd-job-token": r"glcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20}",
    "gitlab-deploy-token": r"gldt-[0-9a-zA-Z_\-]{20}",
    "gitlab-feature-flag-client-token": r"glffct-[0-9a-zA-Z_\-]{20}",
    "gitlab-feed-token": r"glft-[0-9a-zA-Z_\-]{20}",
    "gitlab-incoming-mail-token": r"glimt-[0-9a-zA-Z_\-]{25}",
    "gitlab-kubernetes-agent-token": r"glagent-[0-9a-zA-Z_\-]{50}",
    "gitlab-oauth-app-secret": r"gloas-[0-9a-zA-Z_\-]{64}",
    "gitlab-pat": r"glpat-[\w-]{20}",
    "gitlab-pat-routable": r"\bglpat-[0-9a-zA-Z_-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}\b",
    "gitlab-ptt": r"glptt-[0-9a-f]{40}",
    "gitlab-rrt": r"GR1348941[\w-]{20}",
    "gitlab-runner-authentication-token": r"glrt-[0-9a-zA-Z_\-]{20}",
    "gitlab-runner-authentication-token-routable": r"\bglrt-t\d_[0-9a-zA-Z_\-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}\b",
    "gitlab-scim-token": r"glsoat-[0-9a-zA-Z_\-]{20}",
    "gitlab-session-cookie": r"_gitlab_session=[0-9a-z]{32}",

    # Gitter, GoCardless, Grafana, Harness, HashiCorp
    "gitter-access-token": r"(?i)[\w.-]{0,50}?(?:gitter)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9_-]{40})",
    "gocardless-api-token": r"(?i)[\w.-]{0,50}?(?:gocardless)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}(live_(?i)[a-z0-9\-_=]{40})",
    "grafana-api-key": r"(?i)\b(eyJrIjoi[A-Za-z0-9]{70,400}={0,3})",
    "grafana-cloud-api-token": r"(?i)\b(glc_[A-Za-z0-9+/]{32,400}={0,3})",
    "grafana-service-account-token": r"(?i)\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})",
    "harness-api-key": r"(?:pat|sat)\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{20}",
    "hashicorp-tf-api-token": r"(?i)[a-z0-9]{14}\.(?-i:atlasv1)\.[a-z0-9\-_=]{60,70}",
    "hashicorp-tf-password": r"(?i)[\w.-]{0,50}?(?:administrator_login_password|password)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}(\"[a-z0-9=_\-]{8,20}\")",

    # Heroku, HubSpot, Infracost, Intercom, Intra42, JFrog, JWT, Kraken, KuCoin, LaunchDarkly, Linear, LinkedIn, Lob, Looker
    "heroku-api-key": r"(?i)[\w.-]{0,50}?(?:heroku)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
    "heroku-api-key-v2": r"\b((HRKU-AA[0-9a-zA-Z_-]{58}))",
    "hubspot-api-key": r"(?i)[\w.-]{0,50}?(?:hubspot)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})",
    "infracost-api-token": r"\b(ico-[a-zA-Z0-9]{32})",
    "intercom-api-key": r"(?i)[\w.-]{0,50}?(?:intercom)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9=_\-]{60})",
    "intra42-client-secret": r"\b(s-s4t2(?:ud|af)-(?i)[abcdef0123456789]{64})",
    "jfrog-api-key": r"(?i)[\w.-]{0,50}?(?:jfrog|artifactory|bintray|xray)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9]{73})",
    "jfrog-identity-token": r"(?i)[\w.-]{0,50}?(?:jfrog|artifactory|bintray|xray)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9]{64})",
    "jwt": r"\b(ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9\/\\_-]{17,}\.(?:[a-zA-Z0-9\/\\_-]{10,}={0,2})?)",
    "jwt-base64": r"\bZXlK[a-zA-Z0-9\/\\_+\-\r\n]{40,}={0,2}",
    "kraken-access-token": r"(?i)[\w.-]{0,50}?(?:kraken)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9\/=_\+\-]{80,90})",
    "kucoin-access-token": r"(?i)[\w.-]{0,50}?(?:kucoin)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-f0-9]{24})",
    "kucoin-secret-key": r"(?i)[\w.-]{0,50}?(?:kucoin)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
    "launchdarkly-access-token": r"(?i)[\w.-]{0,50}?(?:launchdarkly)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9=_\-]{40})",
    "linear-api-key": r"lin_api_(?i)[a-z0-9]{40}",
    "linear-client-secret": r"(?i)[\w.-]{0,50}?(?:linear)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-f0-9]{32})",
    "linkedin-client-id": r"(?i)[\w.-]{0,50}?(?:linked[_-]?in)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9]{14})",
    "linkedin-client-secret": r"(?i)[\w.-]{0,50}?(?:linked[_-]?in)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9]{16})",
    "lob-api-key": r"(?i)[\w.-]{0,50}?(?:lob)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}((live|test)_[a-f0-9]{35})",
    "lob-pub-api-key": r"(?i)[\w.-]{0,50}?(?:lob)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}((test|live)_pub_[a-f0-9]{31})",
    "looker-client-id": r"(?i)[\w.-]{0,50}?(?:looker)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9]{20})",
    "looker-client-secret": r"(?i)[\w.-]{0,50}?(?:looker)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9]{24})",

    # Mailchimp, Mailgun, Mapbox, Mattermost, MaxMind, MessageBird, MS Teams, Netlify, New Relic
    "mailchimp-api-key": r"(?i)[\w.-]{0,50}?(?:MailchimpSDK.initialize|mailchimp)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-f0-9]{32}-us\d\d)",
    "mailgun-private-api-token": r"(?i)[\w.-]{0,50}?(?:mailgun)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}(key-[a-f0-9]{32})",
    "mailgun-pub-key": r"(?i)[\w.-]{0,50}?(?:mailgun)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}(pubkey-[a-f0-9]{32})",
    "mailgun-signing-key": r"(?i)[\w.-]{0,50}?(?:mailgun)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8})",
    "mapbox-api-token": r"(?i)[\w.-]{0,50}?(?:mapbox)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}(pk\.[a-z0-9]{60}\.[a-z0-9]{22})",
    "mattermost-access-token": r"(?i)[\w.-]{0,50}?(?:mattermost)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9]{26})",
    "maxmind-license-key": r"\b([A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk)",
    "messagebird-api-token": r"(?i)[\w.-]{0,50}?(?:message[_-]?bird)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9]{25})",
    "messagebird-client-id": r"(?i)[\w.-]{0,50}?(?:message[_-]?bird)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
    "microsoft-teams-webhook": r"https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}/IncomingWebhook/[a-z0-9]{32}/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}",
    "netlify-access-token": r"(?i)[\w.-]{0,50}?(?:netlify)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9=_\-]{40,46})",
    "new-relic-browser-api-token": r"(?i)[\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}(NRJS-[a-f0-9]{19})",
    "new-relic-insert-key": r"(?i)[\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}(NRII-[a-z0-9-]{32})",
    "new-relic-user-api-id": r"(?i)[\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9]{64})",
    "new-relic-user-api-key": r"(?i)[\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}(NRAK-[a-z0-9]{27})",

    # Notion, NPM, NuGet, NYTimes, Octopus, Okta, OpenShift, Package Managers
    "notion-api-token": r"\b(ntn_[0-9]{11}[A-Za-z0-9]{32}[A-Za-z0-9]{3})",
    "npm-access-token": r"(?i)\b(npm_[a-z0-9]{36})\b",
    "nuget-config-password": r"(?i)<add key=\"(?:(?:ClearText)?Password)\"\s*value=\"(.{8,})\"\s*/>",
    "nytimes-access-token": r"(?i)[\w.-]{0,50}?(?:nytimes|new-york-times,|newyorktimes)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9=_\-]{32})",
    "octopus-deploy-api-key": r"\b(API-[A-Z0-9]{26})",
    "okta-access-token": r"[\w.-]{0,50}?(?i:[\w.-]{0,50}?(?:(?-i:[Oo]kta|OKTA))(?:[ \t\w.-]{0,20})[\s'\"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}(00[\w=\-]{40})",
    "openshift-user-token": r"\b(sha256~[\w-]{43})",
    "pypi-upload-token": r"pypi-AgEIcHlwaS5vcmc[\w-]{50,1000}",
    "rubygems-api-token": r"\b(rubygems_[a-f0-9]{48})\b",

    # Plaid, PlanetScale, Postman, Prefect, Private Key, Pulumi, RapidAPI, Readme, Scalingo
    "plaid-api-token": r"(?i)[\w.-]{0,50}?(?:plaid)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}(access-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
    "plaid-client-id": r"(?i)[\w.-]{0,50}?(?:plaid)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9]{24})",
    "plaid-secret-key": r"(?i)[\w.-]{0,50}?(?:plaid)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9]{30})",
    "planetscale-api-token": r"\b(pscale_tkn_(?i)[\w=\.-]{32,64})",
    "planetscale-oauth-token": r"\b(pscale_oauth_[\w=\.-]{32,64})",
    "planetscale-password": r"(?i)\b(pscale_pw_(?i)[\w=\.-]{32,64})",
    "postman-api-token": r"\b(PMAK-(?i)[a-f0-9]{24}\-[a-f0-9]{34})",
    "prefect-api-token": r"\b(pnu_[a-zA-Z0-9]{36})",
    "private-key": r"(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S-]{64,}?KEY(?: BLOCK)?-----",
    "pulumi-api-token": r"\b(pul-[a-f0-9]{40})",
    "rapidapi-access-token": r"(?i)[\w.-]{0,50}?(?:rapidapi)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9_-]{50})",
    "readme-api-token": r"\b(rdme_[a-z0-9]{70})",
    "scalingo-api-token": r"\b(tk-us-[\w-]{48})",

    # Sendbird, SendGrid, Sendinblue, Sentry, SettleMint, Shippo, Shopify, Sidekiq
    "sendbird-access-id": r"(?i)[\w.-]{0,50}?(?:sendbird)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
    "sendbird-access-token": r"(?i)[\w.-]{0,50}?(?:sendbird)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-f0-9]{40})",
    "sendgrid-api-token": r"\b(SG\.(?i)[a-z0-9=_\-\.]{66})",
    "sendinblue-api-token": r"\b(xkeysib-[a-f0-9]{64}\-(?i)[a-z0-9]{16})",
    "sentry-access-token": r"(?i)[\w.-]{0,50}?(?:sentry)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-f0-9]{64})",
    "sentry-org-token": r"\bsntrys_eyJpYXQiO[a-zA-Z0-9+/]{10,200}(?:LCJyZWdpb25fdXJs|InJlZ2lvbl91cmwi|cmVnaW9uX3VybCI6)[a-zA-Z0-9+/]{10,200}={0,2}_[a-zA-Z0-9+/]{43}",
    "sentry-user-token": r"\b(sntryu_[a-f0-9]{64})",
    "settlemint-application-access-token": r"\b(sm_aat_[a-zA-Z0-9]{16})",
    "settlemint-personal-access-token": r"\b(sm_pat_[a-zA-Z0-9]{16})",
    "settlemint-service-access-token": r"\b(sm_sat_[a-zA-Z0-9]{16})",
    "shippo-api-token": r"\b(shippo_(?:live|test)_[a-fA-F0-9]{40})",
    "shopify-access-token": r"shpat_[a-fA-F0-9]{32}",
    "shopify-custom-access-token": r"shpca_[a-fA-F0-9]{32}",
    "shopify-private-app-access-token": r"shppa_[a-fA-F0-9]{32}",
    "shopify-shared-secret": r"shpss_[a-fA-F0-9]{32}",
    "sidekiq-secret": r"(?i)[\w.-]{0,50}?(?:BUNDLE_ENTERPRISE__CONTRIBSYS__COM|BUNDLE_GEMS__CONTRIBSYS__COM)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-f0-9]{8}:[a-f0-9]{8})",
    "sidekiq-sensitive-url": r"(?i)\bhttps?://([a-f0-9]{8}:[a-f0-9]{8})@(?:gems.contribsys.com|enterprise.contribsys.com)",

    # Slack (10 Rules)
    "slack-app-token": r"(?i)xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+",
    "slack-bot-token": r"xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
    "slack-config-access-token": r"(?i)xoxe.xox[bp]-\d-[A-Z0-9]{163,166}",
    "slack-config-refresh-token": r"(?i)xoxe-\d-[A-Z0-9]{146}",
    "slack-legacy-bot-token": r"xoxb-[0-9]{8,14}-[a-zA-Z0-9]{18,26}",
    "slack-legacy-token": r"xox[os]-\d+-\d+-\d+-[a-fA-F\d]+",
    "slack-legacy-workspace-token": r"xox[ar]-(?:\d-)?[0-9a-zA-Z]{8,48}",
    "slack-user-token": r"xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}",
    "slack-webhook-url": r"(?:https?://)?hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}",

    # Snyk, Sonar, Sourcegraph, Square, Squarespace, Stripe, SumoLogic, Telegram, TravisCI, Twilio, Twitch
    "snyk-api-token": r"(?i)[\w.-]{0,50}?(?:snyk[_.-]?(?:(?:api|oauth)[_.-]?)?(?:key|token))(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
    "sonar-api-token": r"(?i)[\w.-]{0,50}?(?:sonar[_.-]?(login|token))(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}((?:squ_|sqp_|sqa_)?[a-z0-9=_\-]{40})",
    "sourcegraph-access-token": r"(?i)\b(\b(sgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}|sgp_[a-fA-F0-9]{40}|[a-fA-F0-9]{40})\b)",
    "square-access-token": r"\b((?:EAAA|sq0atp-)[\w-]{22,60})",
    "squarespace-access-token": r"(?i)[\w.-]{0,50}?(?:squarespace)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
    "stripe-access-token": r"\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})",
    "sumologic-access-id": r"[\w.-]{0,50}?(?i:[\w.-]{0,50}?(?:(?-i:[Ss]umo|SUMO))(?:[ \t\w.-]{0,20})[\s'\"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}(su[a-zA-Z0-9]{12})",
    "sumologic-access-token": r"(?i)[\w.-]{0,50}?(?:(?-i:[Ss]umo|SUMO))(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9]{64})",
    "telegram-bot-api-token": r"(?i)[\w.-]{0,50}?(?:telegr)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([0-9]{5,16}:(?-i:A)[a-z0-9_\-]{34})",
    "travisci-access-token": r"(?i)[\w.-]{0,50}?(?:travis)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9]{22})",
    "twilio-api-key": r"SK[0-9a-fA-F]{32}",
    "twitch-api-token": r"(?i)[\w.-]{0,50}?(?:twitch)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9]{30})",

    # Twitter (5 Rules)
    "twitter-access-secret": r"(?i)[\w.-]{0,50}?(?:twitter)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9]{45})",
    "twitter-access-token": r"(?i)[\w.-]{0,50}?(?:twitter)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([0-9]{15,25}-[a-zA-Z0-9]{20,40})",
    "twitter-api-key": r"(?i)[\w.-]{0,50}?(?:twitter)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9]{25})",
    "twitter-api-secret": r"(?i)[\w.-]{0,50}?(?:twitter)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9]{50})",
    "twitter-bearer-token": r"(?i)[\w.-]{0,50}?(?:twitter)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}(A{22}[a-zA-Z0-9%]{80,100})",

    # Typeform, Vault, Yandex, Zendesk
    "typeform-api-token": r"(?i)[\w.-]{0,50}?(?:typeform)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}(tfp_[a-z0-9\-_\.=]{59})",
    "vault-batch-token": r"\b(hvb\.[\w-]{138,300})",
    "vault-service-token": r"\b((?:hvs\.[\w-]{90,120}|s\.(?i:[a-z0-9]{24})))",
    "yandex-access-token": r"(?i)[\w.-]{0,50}?(?:yandex)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}(t1\.[A-Z0-9a-z_-]+[=]{0,2}\.[A-Z0-9a-z_-]{86}[=]{0,2})",
    "yandex-api-key": r"(?i)[\w.-]{0,50}?(?:yandex)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}(AQVN[A-Za-z0-9_\-]{35,38})",
    "yandex-aws-access-token": r"(?i)[\w.-]{0,50}?(?:yandex)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}(YC[a-zA-Z0-9_\-]{38})",
    "zendesk-secret-key": r"(?i)[\w.-]{0,50}?(?:zendesk)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9]{40})",
}

# =====================================================================
# 3. GITLEAKS OFFICIAL ALLOWLIST & STOPWORDS (False-Positive Suppression)
# =====================================================================
GITLEAKS_STOPWORDS = [
    "000000",
    "123456",
    "abcdefghijklmnopqrstuvwxyz",
    "014df517-39d1-4453-b7b3-9930c563627c",
    "EXAMPLEKEY",
    "dummy_secret",
    "changeit",
    "changeme",
    "password",
    "6fe4476ee5a1832882e326b506d14126",
    "_ec2_",
    "aaaaaa",
]

GITLEAKS_ALLOWLIST_REGEXES = [
    r"(?i)^true|false|null$",
    r"^(?i:a+|b+|c+|d+|e+|f+|g+|h+|i+|j+|k+|l+|m+|n+|o+|p+|q+|r+|s+|t+|u+|v+|w+|x+|y+|z+|\*+|\.+)$",
    r"^\$(?:\d+|{\d+})$",
    r"^\$\{[A-Za-z0-9_.]+\}$",
    r"^\{\{[ \t]*[\w ().|]+[ \t]*\}\}$",
    r".+EXAMPLE$",
    r"^/Users/(?i)[a-z0-9]+/[\w .-/]+$",
    r"^/(?:bin|etc|home|opt|tmp|usr|var)/[\w ./-]+$",
]