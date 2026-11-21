//! Signed JWT validation for OIDC ID tokens and API bearer tokens (RFC 7515, 7517, 7519) on top of
//! `ring`. Only asymmetric algorithms are accepted: RS256, PS256, ES256 and EdDSA (Ed25519).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{self, RsaPublicKeyComponents, UnparsedPublicKey};
use serde_json::{Map, Value};
use subtle::ConstantTimeEq;

/// Longest token accepted, in bytes: ID tokens of users with many groups exceed 16 KiB.
pub const MAX_TOKEN_BYTES: usize = 64 * 1024;
/// Allowed clock difference for `exp`, `nbf` and `iat`, in seconds.
pub const SKEW_SECS: i64 = 60;
const MAX_KEYS: usize = 64;
const MAX_KEY_TRIES: usize = 8;

/// A signature algorithm this module verifies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Alg {
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    Rs256,
    /// RSASSA-PSS with SHA-256.
    Ps256,
    /// ECDSA P-256 with SHA-256.
    Es256,
    /// Ed25519.
    EdDsa,
}

/// Every algorithm this module verifies.
pub const ALL_ALGS: [Alg; 4] = [Alg::Rs256, Alg::Ps256, Alg::Es256, Alg::EdDsa];

impl Alg {
    /// The JOSE name (`RS256`, `PS256`, `ES256`, `EdDSA`).
    pub fn as_str(self) -> &'static str {
        match self {
            Alg::Rs256 => "RS256",
            Alg::Ps256 => "PS256",
            Alg::Es256 => "ES256",
            Alg::EdDsa => "EdDSA",
        }
    }

    /// The algorithm of a JOSE name; HMAC, `none` and others are `None`.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "RS256" => Some(Alg::Rs256),
            "PS256" => Some(Alg::Ps256),
            "ES256" => Some(Alg::Es256),
            "EdDSA" => Some(Alg::EdDsa),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum KeyMaterial {
    Rsa { n: Vec<u8>, e: Vec<u8> },
    P256(Vec<u8>),
    Ed25519(Vec<u8>),
}

/// A public signing key from a JWKS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Jwk {
    kid: Option<String>,
    alg: Option<Alg>,
    key: KeyMaterial,
}

impl Jwk {
    fn fits(&self, alg: Alg) -> bool {
        if self.alg.is_some_and(|a| a != alg) {
            return false;
        }
        matches!(
            (&self.key, alg),
            (KeyMaterial::Rsa { .. }, Alg::Rs256 | Alg::Ps256)
                | (KeyMaterial::P256(_), Alg::Es256)
                | (KeyMaterial::Ed25519(_), Alg::EdDsa)
        )
    }

    fn verify(&self, alg: Alg, msg: &[u8], sig: &[u8]) -> bool {
        match (&self.key, alg) {
            (KeyMaterial::Rsa { n, e }, Alg::Rs256) => RsaPublicKeyComponents { n, e }
                .verify(&signature::RSA_PKCS1_2048_8192_SHA256, msg, sig)
                .is_ok(),
            (KeyMaterial::Rsa { n, e }, Alg::Ps256) => RsaPublicKeyComponents { n, e }
                .verify(&signature::RSA_PSS_2048_8192_SHA256, msg, sig)
                .is_ok(),
            (KeyMaterial::P256(p), Alg::Es256) => {
                UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, p)
                    .verify(msg, sig)
                    .is_ok()
            }
            (KeyMaterial::Ed25519(p), Alg::EdDsa) => UnparsedPublicKey::new(&signature::ED25519, p)
                .verify(msg, sig)
                .is_ok(),
            _ => false,
        }
    }
}

/// The signing keys of a JWKS document that this module can use; others are skipped.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct JwkSet {
    keys: Vec<Jwk>,
}

fn b64(v: &Value, field: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(v.get(field)?.as_str()?).ok()
}

fn strip_zeros(mut b: Vec<u8>) -> Vec<u8> {
    let n = b.iter().take_while(|x| **x == 0).count();
    b.drain(..n);
    b
}

fn parse_jwk(v: &Value) -> Option<Jwk> {
    if v.get("use").is_some_and(|u| u != "sig") {
        return None;
    }
    if let Some(ops) = v.get("key_ops").and_then(Value::as_array)
        && !ops.iter().any(|o| o == "verify")
    {
        return None;
    }
    let alg = match v.get("alg") {
        None => None,
        Some(a) => Some(Alg::parse(a.as_str()?)?),
    };
    let key = match (
        v.get("kty")?.as_str()?,
        v.get("crv").and_then(Value::as_str),
    ) {
        ("RSA", _) => {
            let n = strip_zeros(b64(v, "n")?);
            let e = strip_zeros(b64(v, "e")?);
            if n.len() < 256 || n.len() > 1024 || e.is_empty() || e.len() > 8 {
                return None;
            }
            KeyMaterial::Rsa { n, e }
        }
        ("EC", Some("P-256")) => {
            let x = b64(v, "x")?;
            let y = b64(v, "y")?;
            if x.len() != 32 || y.len() != 32 {
                return None;
            }
            let mut p = Vec::with_capacity(65);
            p.push(4);
            p.extend_from_slice(&x);
            p.extend_from_slice(&y);
            KeyMaterial::P256(p)
        }
        ("OKP", Some("Ed25519")) => {
            let x = b64(v, "x")?;
            if x.len() != 32 {
                return None;
            }
            KeyMaterial::Ed25519(x)
        }
        _ => return None,
    };
    Some(Jwk {
        kid: v.get("kid").and_then(Value::as_str).map(String::from),
        alg,
        key,
    })
}

impl JwkSet {
    /// Parses a JWKS document, keeping at most 64 usable signing keys; fails when none is usable.
    pub fn parse(body: &[u8]) -> anyhow::Result<Self> {
        let v: Value = serde_json::from_slice(body)
            .map_err(|e| anyhow::anyhow!("the JWKS is not JSON: {e}"))?;
        let list = v
            .get("keys")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow::anyhow!("the JWKS has no keys array"))?;
        let keys: Vec<Jwk> = list.iter().filter_map(parse_jwk).take(MAX_KEYS).collect();
        if keys.is_empty() {
            anyhow::bail!("the JWKS has no RS256, PS256, ES256 or Ed25519 signing key");
        }
        Ok(Self { keys })
    }

    /// Number of usable keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// No usable key.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Whether a key has this `kid`.
    pub fn knows(&self, kid: &str) -> bool {
        self.keys.iter().any(|k| k.kid.as_deref() == Some(kid))
    }
}

/// Why a JWT was rejected. The text never contains token or claim values.
#[derive(Debug, PartialEq, Eq)]
pub enum JwtError {
    /// Not a compact JWS or not valid JSON inside.
    Malformed,
    /// `none`, HMAC or another algorithm outside the allow-list, or `crit` header parameters.
    Algorithm,
    /// No key in the JWKS has the token's `kid` (or fits its algorithm).
    UnknownKey,
    /// The signature does not verify.
    Signature,
    /// A claim check failed; the text names the claim, never its value.
    Claims(&'static str),
}

impl std::error::Error for JwtError {}

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwtError::Malformed => f.write_str("malformed token"),
            JwtError::Algorithm => f.write_str("algorithm not allowed"),
            JwtError::UnknownKey => f.write_str("unknown signing key"),
            JwtError::Signature => f.write_str("invalid signature"),
            JwtError::Claims(c) => write!(f, "claim check failed: {c}"),
        }
    }
}

/// Expected values of the registered claims.
pub struct Expect<'a> {
    /// Expected `iss`, compared byte for byte.
    pub issuer: &'a str,
    /// Expected `aud` (one of the values when it is an array).
    pub audience: &'a str,
    /// ID tokens: the nonce of the pending login. `None` (API tokens): a token carrying a nonce is an
    /// ID token and is refused.
    pub nonce: Option<&'a str>,
    /// ID tokens: `azp`, when present, must be the audience (the client id).
    pub check_azp: bool,
    /// ID tokens: `iat` is mandatory.
    pub require_iat: bool,
    /// Unix time in seconds.
    pub now: i64,
    /// Accepted algorithms; others are [`JwtError::Algorithm`].
    pub algs: &'a [Alg],
}

/// Three dot-separated parts of any content and length: a bearer value meant as a JWT, valid or
/// not (`alg: none` tokens have an empty signature part).
pub fn jwt_shaped(value: &str) -> bool {
    value.bytes().filter(|b| *b == b'.').count() == 2
}

/// A compact JWS: three base64url parts separated by dots.
pub fn looks_like_jwt(value: &str) -> bool {
    value.len() <= MAX_TOKEN_BYTES
        && value.split('.').count() == 3
        && value.split('.').all(|p| {
            !p.is_empty()
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

struct Parsed<'a> {
    alg: Alg,
    kid: Option<String>,
    signing_input: &'a str,
    signature: Vec<u8>,
    claims: Map<String, Value>,
}

fn parse<'t>(token: &'t str, algs: &[Alg]) -> Result<Parsed<'t>, JwtError> {
    if !looks_like_jwt(token) {
        return Err(JwtError::Malformed);
    }
    let (signing_input, sig) = token.rsplit_once('.').ok_or(JwtError::Malformed)?;
    let (h, p) = signing_input.split_once('.').ok_or(JwtError::Malformed)?;
    let header: Map<String, Value> = URL_SAFE_NO_PAD
        .decode(h)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or(JwtError::Malformed)?;
    if header.contains_key("crit") {
        return Err(JwtError::Algorithm);
    }
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .and_then(Alg::parse)
        .filter(|a| algs.contains(a))
        .ok_or(JwtError::Algorithm)?;
    let kid = match header.get("kid") {
        None => None,
        Some(Value::String(k)) => Some(k.clone()),
        Some(_) => return Err(JwtError::Malformed),
    };
    let signature = URL_SAFE_NO_PAD
        .decode(sig)
        .map_err(|_| JwtError::Malformed)?;
    let claims: Map<String, Value> = URL_SAFE_NO_PAD
        .decode(p)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or(JwtError::Malformed)?;
    Ok(Parsed {
        alg,
        kid,
        signing_input,
        signature,
        claims,
    })
}

/// The `kid` of a token header, for deciding whether a JWKS refresh can help.
pub fn kid_of(token: &str) -> Option<String> {
    parse(token, &ALL_ALGS).ok().and_then(|p| p.kid)
}

fn time(claims: &Map<String, Value>, name: &'static str) -> Result<Option<i64>, JwtError> {
    match claims.get(name) {
        None => Ok(None),
        Some(v) => v
            .as_i64()
            .or_else(|| v.as_f64().filter(|f| f.is_finite()).map(|f| f as i64))
            .map(Some)
            .ok_or(JwtError::Claims(name)),
    }
}

fn check_claims(c: &Map<String, Value>, e: &Expect<'_>) -> Result<(), JwtError> {
    if c.get("iss").and_then(Value::as_str) != Some(e.issuer) {
        return Err(JwtError::Claims("iss"));
    }
    let aud_ok = match c.get("aud") {
        Some(Value::String(a)) => a == e.audience,
        Some(Value::Array(list)) => list.iter().any(|a| a == e.audience),
        _ => false,
    };
    if !aud_ok {
        return Err(JwtError::Claims("aud"));
    }
    if e.check_azp
        && let Some(azp) = c.get("azp")
        && azp.as_str() != Some(e.audience)
    {
        return Err(JwtError::Claims("azp"));
    }
    let exp = time(c, "exp")?.ok_or(JwtError::Claims("exp"))?;
    if e.now >= exp.saturating_add(SKEW_SECS) {
        return Err(JwtError::Claims("exp"));
    }
    if let Some(nbf) = time(c, "nbf")?
        && e.now.saturating_add(SKEW_SECS) < nbf
    {
        return Err(JwtError::Claims("nbf"));
    }
    match time(c, "iat")? {
        Some(iat) if e.now.saturating_add(SKEW_SECS) < iat => return Err(JwtError::Claims("iat")),
        None if e.require_iat => return Err(JwtError::Claims("iat")),
        _ => {}
    }
    match e.nonce {
        Some(want) => {
            let got = c.get("nonce").and_then(Value::as_str).unwrap_or_default();
            if !bool::from(got.as_bytes().ct_eq(want.as_bytes())) {
                return Err(JwtError::Claims("nonce"));
            }
        }
        None if c.contains_key("nonce") => return Err(JwtError::Claims("nonce")),
        None => {}
    }
    if c.get("sub")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(JwtError::Claims("sub"));
    }
    Ok(())
}

/// Verifies the signature with a key of `keys` and checks the claims; returns the claims.
pub fn verify(
    token: &str,
    keys: &JwkSet,
    expect: &Expect<'_>,
) -> Result<Map<String, Value>, JwtError> {
    let p = parse(token, expect.algs)?;
    let candidates: Vec<&Jwk> = keys
        .keys
        .iter()
        .filter(|k| k.fits(p.alg))
        .filter(|k| p.kid.is_none() || k.kid == p.kid)
        .take(MAX_KEY_TRIES)
        .collect();
    if candidates.is_empty() {
        return Err(JwtError::UnknownKey);
    }
    if !candidates
        .iter()
        .any(|k| k.verify(p.alg, p.signing_input.as_bytes(), &p.signature))
    {
        return Err(JwtError::Signature);
    }
    check_claims(&p.claims, expect)?;
    Ok(p.claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, Ed25519KeyPair, KeyPair};
    use serde_json::json;

    const NOW: i64 = 1_800_000_000;
    const ISS: &str = "https://idp.example.com/realms/test";
    const AUD: &str = "fastmock";

    fn enc(v: &Value) -> String {
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap())
    }

    fn claims() -> Value {
        json!({"iss": ISS, "aud": AUD, "sub": "u1", "exp": NOW + 300, "iat": NOW - 10, "nonce": "n-1", "azp": AUD})
    }

    fn expect() -> Expect<'static> {
        Expect {
            issuer: ISS,
            audience: AUD,
            nonce: Some("n-1"),
            check_azp: true,
            require_iat: true,
            now: NOW,
            algs: &ALL_ALGS,
        }
    }

    struct Ec {
        kp: EcdsaKeyPair,
        kid: String,
    }

    impl Ec {
        fn new(kid: &str) -> Self {
            let rng = SystemRandom::new();
            let alg = &signature::ECDSA_P256_SHA256_FIXED_SIGNING;
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(alg, &rng).unwrap();
            Ec {
                kp: EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref(), &rng).unwrap(),
                kid: kid.into(),
            }
        }

        fn jwk(&self) -> Value {
            let p = self.kp.public_key().as_ref();
            json!({"kty": "EC", "crv": "P-256", "kid": self.kid, "use": "sig", "alg": "ES256",
                "x": URL_SAFE_NO_PAD.encode(&p[1..33]), "y": URL_SAFE_NO_PAD.encode(&p[33..65])})
        }

        fn sign_with_header(&self, header: &Value, claims: &Value) -> String {
            let input = format!("{}.{}", enc(header), enc(claims));
            let sig = self
                .kp
                .sign(&SystemRandom::new(), input.as_bytes())
                .unwrap();
            format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()))
        }

        fn sign(&self, claims: &Value) -> String {
            self.sign_with_header(
                &json!({"alg": "ES256", "kid": self.kid, "typ": "JWT"}),
                claims,
            )
        }
    }

    fn set(keys: &[Value]) -> JwkSet {
        JwkSet::parse(&serde_json::to_vec(&json!({ "keys": keys })).unwrap()).unwrap()
    }

    #[test]
    fn tokens_up_to_64_kib_are_accepted() {
        let k = Ec::new("k1");
        let keys = set(&[k.jwk()]);
        let sized = |bytes: usize| {
            let mut n = bytes / 60;
            loop {
                let mut c = claims();
                let groups: Vec<String> = (0..n)
                    .map(|i| format!("group-with-a-long-name-{i:010}"))
                    .collect();
                c["groups"] = json!(groups);
                let t = k.sign(&c);
                if t.len() >= bytes {
                    return t;
                }
                n += 8;
            }
        };
        let t17 = sized(17 * 1000);
        assert!(t17.len() < 17 * 1000 + 500, "{}", t17.len());
        assert!(t17.len() > 16 * 1024, "{}", t17.len());
        assert!(verify(&t17, &keys, &expect()).is_ok());
        let t70 = sized(70 * 1000);
        assert!(t70.len() > MAX_TOKEN_BYTES, "{}", t70.len());
        assert_eq!(verify(&t70, &keys, &expect()), Err(JwtError::Malformed));
    }

    #[test]
    fn valid_es256() {
        let k = Ec::new("k1");
        let keys = set(&[k.jwk()]);
        let c = verify(&k.sign(&claims()), &keys, &expect()).unwrap();
        assert_eq!(c["sub"], "u1");
        let mut no_kid = k.sign_with_header(&json!({"alg": "ES256"}), &claims());
        assert!(verify(&no_kid, &keys, &expect()).is_ok());
        no_kid.push('A');
        assert_eq!(verify(&no_kid, &keys, &expect()), Err(JwtError::Signature));
    }

    #[test]
    fn valid_eddsa() {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let jwk = json!({"kty": "OKP", "crv": "Ed25519", "kid": "ed",
            "x": URL_SAFE_NO_PAD.encode(kp.public_key().as_ref())});
        let input = format!(
            "{}.{}",
            enc(&json!({"alg": "EdDSA", "kid": "ed"})),
            enc(&claims())
        );
        let t = format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(kp.sign(input.as_bytes()).as_ref())
        );
        assert!(verify(&t, &set(&[jwk]), &expect()).is_ok());
    }

    /// RS256 and PS256 tokens signed once with a throw-away 2048-bit key whose private part was
    /// discarded; validated at the fixed time `NOW`.
    const RSA_JWK: &str = include_str!("../tests/data/jwt-rsa-public.json");
    const RS256_TOKEN: &str = include_str!("../tests/data/jwt-rs256.txt");
    const PS256_TOKEN: &str = include_str!("../tests/data/jwt-ps256.txt");
    const RSA_PUBLIC_PEM: &str = include_str!("../tests/data/jwt-rsa-public.pem");

    #[test]
    fn valid_rs256_and_ps256() {
        let keys = JwkSet::parse(RSA_JWK.as_bytes()).unwrap();
        for t in [RS256_TOKEN, PS256_TOKEN] {
            let c = verify(t.trim(), &keys, &expect()).unwrap();
            assert_eq!(c["iss"], ISS);
        }
        let mut late = expect();
        late.now = NOW + 3600;
        assert_eq!(
            verify(RS256_TOKEN.trim(), &keys, &late),
            Err(JwtError::Claims("exp"))
        );
    }

    fn hmac_token(alg: &str, secret: &[u8], claims: &Value) -> String {
        let input = format!(
            "{}.{}",
            enc(&json!({"alg": alg, "kid": "rsa-1"})),
            enc(claims)
        );
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret);
        let tag = ring::hmac::sign(&key, input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(tag.as_ref()))
    }

    #[test]
    fn rejects_hmac_signed_with_the_public_key() {
        let keys = JwkSet::parse(RSA_JWK.as_bytes()).unwrap();
        for secret in [RSA_PUBLIC_PEM.as_bytes(), RSA_JWK.as_bytes()] {
            for alg in ["HS256", "HS384", "HS512"] {
                let t = hmac_token(alg, secret, &claims());
                assert_eq!(verify(&t, &keys, &expect()), Err(JwtError::Algorithm));
            }
        }
    }

    #[test]
    fn rejects_alg_none_and_others() {
        let k = Ec::new("k1");
        let keys = set(&[k.jwk()]);
        let body = enc(&claims());
        for alg in ["none", "None", "NONE", "RS384", "ES384", "ES512", ""] {
            let h = enc(&json!({"alg": alg, "kid": "k1"}));
            for sig in ["", "AAAA"] {
                let t = format!("{h}.{body}.{sig}");
                assert!(
                    matches!(
                        verify(&t, &keys, &expect()),
                        Err(JwtError::Algorithm | JwtError::Malformed)
                    ),
                    "{alg}"
                );
            }
        }
        let t = format!("{}.{body}.", enc(&json!({"alg": "none"})));
        assert!(verify(&t, &keys, &expect()).is_err());
        let crit = k.sign_with_header(
            &json!({"alg": "ES256", "kid": "k1", "crit": ["exp"]}),
            &claims(),
        );
        assert_eq!(verify(&crit, &keys, &expect()), Err(JwtError::Algorithm));
        let es_as_rs = k.sign_with_header(&json!({"alg": "RS256", "kid": "k1"}), &claims());
        assert_eq!(
            verify(&es_as_rs, &keys, &expect()),
            Err(JwtError::UnknownKey)
        );
    }

    #[test]
    fn allowed_algorithms_are_enforced() {
        let k = Ec::new("k1");
        let keys = set(&[k.jwk()]);
        let only_rsa = [Alg::Rs256];
        let mut e = expect();
        e.algs = &only_rsa;
        assert_eq!(
            verify(&k.sign(&claims()), &keys, &e),
            Err(JwtError::Algorithm)
        );
        let rsa = JwkSet::parse(RSA_JWK.as_bytes()).unwrap();
        assert!(verify(RS256_TOKEN.trim(), &rsa, &e).is_ok());
        assert_eq!(
            verify(PS256_TOKEN.trim(), &rsa, &e),
            Err(JwtError::Algorithm)
        );
        for a in ALL_ALGS {
            assert_eq!(Alg::parse(a.as_str()), Some(a));
        }
    }

    #[test]
    fn rejects_unknown_kid() {
        let k = Ec::new("k1");
        let other = Ec::new("k2");
        let keys = set(&[k.jwk()]);
        assert_eq!(
            verify(&other.sign(&claims()), &keys, &expect()),
            Err(JwtError::UnknownKey)
        );
        let forged = Ec::new("k1");
        assert_eq!(
            verify(&forged.sign(&claims()), &keys, &expect()),
            Err(JwtError::Signature)
        );
        assert!(keys.knows("k1"));
        assert!(!keys.knows("k2"));
        assert_eq!(kid_of(&other.sign(&claims())).as_deref(), Some("k2"));
    }

    #[test]
    fn claim_checks() {
        let k = Ec::new("k1");
        let keys = set(&[k.jwk()]);
        let with = |f: &dyn Fn(&mut Value)| {
            let mut c = claims();
            f(&mut c);
            verify(&k.sign(&c), &keys, &expect())
        };
        assert_eq!(
            with(&|c| c["iss"] = json!("https://evil.example.com")),
            Err(JwtError::Claims("iss"))
        );
        assert_eq!(
            with(&|c| c["iss"] = json!(format!("{ISS}/"))),
            Err(JwtError::Claims("iss"))
        );
        assert_eq!(
            with(&|c| c["aud"] = json!("other")),
            Err(JwtError::Claims("aud"))
        );
        assert!(with(&|c| c["aud"] = json!(["other", AUD])).is_ok());
        assert_eq!(
            with(&|c| c["azp"] = json!("other")),
            Err(JwtError::Claims("azp"))
        );
        assert!(
            with(&|c| {
                c.as_object_mut().unwrap().remove("azp");
            })
            .is_ok()
        );
        assert_eq!(
            with(&|c| c["exp"] = json!(NOW - SKEW_SECS - 1)),
            Err(JwtError::Claims("exp"))
        );
        assert!(with(&|c| c["exp"] = json!(NOW - SKEW_SECS + 1)).is_ok());
        assert_eq!(
            with(&|c| c["exp"] = json!(NOW - SKEW_SECS)),
            Err(JwtError::Claims("exp")),
            "a token is invalid from exp on (RFC 7519 4.1.4)"
        );
        assert_eq!(
            with(&|c| {
                c.as_object_mut().unwrap().remove("exp");
            }),
            Err(JwtError::Claims("exp"))
        );
        assert_eq!(
            with(&|c| c["exp"] = json!("tomorrow")),
            Err(JwtError::Claims("exp"))
        );
        assert_eq!(
            with(&|c| c["nbf"] = json!(NOW + SKEW_SECS + 5)),
            Err(JwtError::Claims("nbf"))
        );
        assert!(with(&|c| c["nbf"] = json!(NOW + 30)).is_ok());
        assert_eq!(
            with(&|c| c["iat"] = json!(NOW + SKEW_SECS + 5)),
            Err(JwtError::Claims("iat"))
        );
        assert_eq!(
            with(&|c| {
                c.as_object_mut().unwrap().remove("iat");
            }),
            Err(JwtError::Claims("iat"))
        );
        assert_eq!(
            with(&|c| c["nonce"] = json!("n-2")),
            Err(JwtError::Claims("nonce"))
        );
        assert_eq!(
            with(&|c| {
                c.as_object_mut().unwrap().remove("nonce");
            }),
            Err(JwtError::Claims("nonce"))
        );
        assert_eq!(
            with(&|c| c["sub"] = json!("")),
            Err(JwtError::Claims("sub"))
        );
        let api = Expect {
            issuer: ISS,
            audience: "fastmock-api",
            nonce: None,
            check_azp: false,
            require_iat: false,
            now: NOW,
            algs: &ALL_ALGS,
        };
        let mut c = claims();
        c["aud"] = json!("fastmock-api");
        c["azp"] = json!("some-cli");
        c.as_object_mut().unwrap().remove("nonce");
        c.as_object_mut().unwrap().remove("iat");
        assert!(verify(&k.sign(&c), &keys, &api).is_ok());
        assert_eq!(
            verify(&k.sign(&claims()), &keys, &api),
            Err(JwtError::Claims("aud"))
        );
        c["nonce"] = json!("n-1");
        assert_eq!(
            verify(&k.sign(&c), &keys, &api),
            Err(JwtError::Claims("nonce")),
            "an ID token is not an API token"
        );
    }

    #[test]
    fn malformed_and_jwks_parsing() {
        let keys = set(&[Ec::new("k").jwk()]);
        for t in [
            "",
            "a.b",
            "a.b.c.d",
            "a..c",
            "a.b.c=",
            "eyJ.eyJ.sig",
            "a+b.c.d",
        ] {
            assert!(verify(t, &keys, &expect()).is_err(), "{t}");
        }
        assert!(!looks_like_jwt(&"a".repeat(MAX_TOKEN_BYTES + 1)));
        assert!(jwt_shaped("eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0."));
        assert!(jwt_shaped(&format!("a.{}.c", "b".repeat(MAX_TOKEN_BYTES))));
        assert!(!jwt_shaped("fm_0123"));
        assert!(!jwt_shaped("a.b"));
        assert!(!looks_like_jwt("fm_0123"));
        assert!(JwkSet::parse(b"{}").is_err());
        assert!(JwkSet::parse(b"{\"keys\": [{\"kty\": \"oct\", \"k\": \"c2VjcmV0\"}]}").is_err());
        let enc_only = json!({"keys": [{"kty": "EC", "crv": "P-256", "use": "enc", "x": URL_SAFE_NO_PAD.encode([1u8; 32]), "y": URL_SAFE_NO_PAD.encode([1u8; 32])}]});
        assert!(JwkSet::parse(&serde_json::to_vec(&enc_only).unwrap()).is_err());
        let short_rsa =
            json!({"keys": [{"kty": "RSA", "n": URL_SAFE_NO_PAD.encode([7u8; 128]), "e": "AQAB"}]});
        assert!(JwkSet::parse(&serde_json::to_vec(&short_rsa).unwrap()).is_err());
        let mixed = json!({"keys": [{"kty": "oct", "k": "c2VjcmV0"}, Ec::new("x").jwk()]});
        assert_eq!(
            JwkSet::parse(&serde_json::to_vec(&mixed).unwrap())
                .unwrap()
                .len(),
            1
        );
    }
}
