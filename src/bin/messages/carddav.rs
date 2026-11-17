use std::{collections::BTreeSet, fmt::Write as _, time::Duration};

use anyhow::{Context, Result, ensure};
use reqwest::{Client, Method, StatusCode, Url, header};
use roxmltree::{Document, Node};
use serde::{Deserialize, Serialize};

const HOST: &str = "contacts.icloud.com";
const DAV: &str = "DAV:";
const CARDDAV: &str = "urn:ietf:params:xml:ns:carddav";
const MAX_RESPONSE: usize = 16 * 1024 * 1024;
const MAX_CARDS: usize = 10_000;
const BATCH: usize = 64;

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Recipient {
    pub name: String,
    pub address: String,
}

struct CardDav<'a> {
    client: Client,
    origin: Url,
    account: &'a str,
    password: &'a str,
    headers: header::HeaderMap,
}

pub(super) async fn fetch(account: &str, password: &str) -> Result<Vec<Recipient>> {
    CardDav::new(account, password)?.fetch(None).await
}

pub(super) async fn fetch_with_apple_grant(
    grant: &linux_imessage::apple::IcloudContactsGrant,
) -> Result<Vec<Recipient>> {
    ensure!(
        !grant.dsid.is_empty() && grant.dsid.bytes().all(|byte| byte.is_ascii_digit()),
        "Invalid saved iCloud account identifier"
    );
    let mut dav = CardDav::new(&grant.dsid, &grant.token)?;
    let principal = if let Some(url) = &grant.url {
        let url = Url::parse(url)?;
        dav.validate_url(&url)?;
        dav.origin = url;
        None
    } else {
        Some(dav.origin.join(&format!("{}/principal/", grant.dsid))?)
    };
    dav.headers = grant.carddav_headers().await?;
    dav.fetch(principal).await
}

impl<'a> CardDav<'a> {
    fn new(account: &'a str, password: &'a str) -> Result<Self> {
        let client = Client::builder()
            .no_proxy()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(8))
            .timeout(Duration::from_secs(25))
            .build()?;
        Ok(Self {
            client,
            origin: Url::parse("https://contacts.icloud.com/")?,
            account,
            password,
            headers: header::HeaderMap::new(),
        })
    }

    async fn fetch(&self, principal: Option<Url>) -> Result<Vec<Recipient>> {
        tokio::time::timeout(
            Duration::from_secs(100),
            self.contacts(default_region(), principal),
        )
        .await
        .context("iCloud Contacts sync timed out")?
    }
    async fn contacts(
        &self,
        region: Option<phonenumber::country::Id>,
        principal: Option<Url>,
    ) -> Result<Vec<Recipient>> {
        let principal = match principal {
            Some(principal) => principal,
            None => {
                self.discovery(
                    &self.origin,
                    DAV,
                    "current-user-principal",
                    "<d:current-user-principal/>",
                )
                .await?
            }
        };
        let home = self
            .discovery(
                &principal,
                CARDDAV,
                "addressbook-home-set",
                "<c:addressbook-home-set/>",
            )
            .await?;
        let (base, xml) = self.propfind(&home, "1", "<d:resourcetype/>").await?;
        let document = multistatus(&xml)?;
        let books = responses(&document)
            .filter(|response| {
                property(*response, DAV, "resourcetype")
                    .and_then(|kind| child(kind, CARDDAV, "addressbook"))
                    .is_some()
            })
            .map(|response| self.href(&base, href(response)?))
            .collect::<Result<BTreeSet<_>>>()?;
        ensure!(!books.is_empty(), "iCloud returned no address books");
        ensure!(books.len() <= 64, "iCloud returned too many address books");

        let mut recipients = BTreeSet::new();
        let mut card_count = 0;
        for mut book in books {
            if !book.path().ends_with('/') {
                book.path_segments_mut()
                    .map_err(|_| anyhow::anyhow!("Invalid iCloud address book"))?
                    .push("");
            }
            let (base, xml) = self
                .propfind(&book, "1", "<d:resourcetype/><d:getetag/>")
                .await?;
            let document = multistatus(&xml)?;
            let cards = responses(&document)
                .filter(|response| property(*response, DAV, "getetag").is_some())
                .filter(|response| {
                    property(*response, DAV, "resourcetype")
                        .and_then(|kind| child(kind, DAV, "collection"))
                        .is_none()
                })
                .map(|response| self.card_path(&base, href(response)?))
                .collect::<Result<BTreeSet<_>>>()?
                .into_iter()
                .collect::<Vec<_>>();
            card_count += cards.len();
            ensure!(card_count <= MAX_CARDS, "Too many iCloud contacts to sync");

            for batch in cards.chunks(BATCH) {
                self.fetch_cards(&base, batch, region, &mut recipients)
                    .await?;
                ensure!(
                    recipients.len() <= 40_000,
                    "Too many iCloud contact addresses to sync"
                );
            }
        }
        Ok(recipients.into_iter().collect())
    }

    async fn fetch_cards(
        &self,
        book: &Url,
        batch: &[String],
        region: Option<phonenumber::country::Id>,
        recipients: &mut BTreeSet<Recipient>,
    ) -> Result<()> {
        let mut request = format!(
            r#"<c:addressbook-multiget xmlns:d="{DAV}" xmlns:c="{CARDDAV}"><d:prop><c:address-data><c:prop name="FN"/><c:prop name="N"/><c:prop name="EMAIL"/><c:prop name="TEL"/></c:address-data></d:prop>"#
        );
        for path in batch {
            write!(
                request,
                "<d:href>{}</d:href>",
                quick_xml::escape::escape(path)
            )?;
        }
        request.push_str("</c:addressbook-multiget>");
        let (base, xml) = self.request(book, "REPORT", "0", request).await?;
        let document = multistatus(&xml)?;
        let mut remaining = batch.iter().map(String::as_str).collect::<BTreeSet<_>>();
        for response in responses(&document) {
            let path = self.card_path(&base, href(response)?)?;
            ensure!(
                remaining.remove(path.as_str()),
                "iCloud returned an unexpected contact"
            );
            if status(response) == Some(404) {
                continue;
            }
            let card = property(response, CARDDAV, "address-data")
                .context("iCloud omitted contact data")?;
            let text = card
                .children()
                .filter_map(|node| node.text())
                .collect::<String>();
            recipients.extend(parse_card(&text, region)?);
        }
        ensure!(
            remaining.is_empty(),
            "iCloud returned an incomplete contacts response"
        );
        Ok(())
    }

    async fn discovery(&self, url: &Url, ns: &str, name: &str, xml: &str) -> Result<Url> {
        let (base, xml) = self.propfind(url, "0", xml).await?;
        let document = multistatus(&xml)?;
        let value = responses(&document)
            .find_map(|response| {
                property(response, ns, name)
                    .and_then(|prop| child(prop, DAV, "href"))
                    .and_then(|node| node.text())
            })
            .context("Could not discover the iCloud Contacts account")?;
        self.href(&base, value)
    }

    async fn propfind(&self, url: &Url, depth: &str, props: &str) -> Result<(Url, String)> {
        let body = format!(
            r#"<d:propfind xmlns:d="{DAV}" xmlns:c="{CARDDAV}"><d:prop>{props}</d:prop></d:propfind>"#
        );
        self.request(url, "PROPFIND", depth, body).await
    }

    async fn request(
        &self,
        base: &Url,
        method: &str,
        depth: &str,
        body: String,
    ) -> Result<(Url, String)> {
        let mut url = base.clone();
        let method = Method::from_bytes(method.as_bytes())?;
        for _ in 0..5 {
            self.validate_url(&url)?;
            let mut response = self
                .client
                .request(method.clone(), url.clone())
                .headers(self.headers.clone())
                .basic_auth(self.account, Some(self.password))
                .header("depth", depth)
                .header(header::USER_AGENT, "iMessage for Linux")
                .header(header::ACCEPT, "application/xml, text/xml")
                .header(header::CONTENT_TYPE, "application/xml; charset=utf-8")
                .body(body.clone())
                .send()
                .await
                .map_err(reqwest::Error::without_url)
                .context("Could not reach iCloud Contacts")?;
            match response.status() {
                StatusCode::MOVED_PERMANENTLY
                | StatusCode::FOUND
                | StatusCode::TEMPORARY_REDIRECT
                | StatusCode::PERMANENT_REDIRECT => {
                    let location = response
                        .headers()
                        .get(header::LOCATION)
                        .and_then(|value| value.to_str().ok())
                        .context("iCloud Contacts returned a redirect without a destination")?;
                    url = self.href(&url, location)?;
                }
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => anyhow::bail!(
                    "iCloud denied access to Contacts (HTTP {})",
                    response.status().as_u16()
                ),
                StatusCode::MULTI_STATUS => {
                    let mut bytes = Vec::new();
                    while let Some(chunk) = response
                        .chunk()
                        .await
                        .map_err(reqwest::Error::without_url)?
                    {
                        ensure!(
                            bytes.len() + chunk.len() <= MAX_RESPONSE,
                            "The iCloud Contacts response is too large"
                        );
                        bytes.extend_from_slice(&chunk);
                    }
                    return Ok((
                        url,
                        String::from_utf8(bytes)
                            .context("iCloud returned invalid Contacts text")?,
                    ));
                }
                status => anyhow::bail!("iCloud Contacts returned HTTP {}", status.as_u16()),
            }
        }
        anyhow::bail!("Too many iCloud Contacts redirects")
    }

    fn href(&self, base: &Url, value: &str) -> Result<Url> {
        let url = base
            .join(value.trim())
            .context("Invalid iCloud Contacts address")?;
        self.validate_url(&url)?;
        Ok(url)
    }

    fn card_path(&self, book: &Url, value: &str) -> Result<String> {
        let resource = self.href(book, value)?;
        let collection = format!("{}/", book.path().trim_end_matches('/'));
        ensure!(
            resource.origin() == book.origin()
                && resource
                    .path()
                    .strip_prefix(&collection)
                    .is_some_and(|path| !path.is_empty() && !path.contains('/')),
            "iCloud returned a contact outside the address book"
        );
        Ok(resource.path().to_owned())
    }

    fn validate_url(&self, url: &Url) -> Result<()> {
        #[cfg(test)]
        if self.origin.host_str() == Some("127.0.0.1") && url.origin() == self.origin.origin() {
            return Ok(());
        }
        let approved = url.domain().is_some_and(|host| {
            host == HOST
                || host
                    .strip_prefix('p')
                    .and_then(|host| host.strip_suffix("-contacts.icloud.com"))
                    .is_some_and(|partition| {
                        !partition.is_empty()
                            && partition.bytes().all(|digit| digit.is_ascii_digit())
                    })
        });
        ensure!(
            approved
                && url.scheme() == "https"
                && url.port_or_known_default() == Some(443)
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none(),
            "iCloud Contacts returned an untrusted destination"
        );
        Ok(())
    }
}

fn multistatus(xml: &str) -> Result<Document<'_>> {
    let document = Document::parse_with_options(
        xml,
        roxmltree::ParsingOptions {
            nodes_limit: 350_000,
            ..Default::default()
        },
    )
    .map_err(|_| anyhow::anyhow!("iCloud returned unreadable Contacts XML"))?;
    ensure!(
        document.root_element().has_tag_name((DAV, "multistatus")),
        "iCloud omitted the Contacts results"
    );
    ensure!(
        responses(&document)
            .all(|response| status(response).is_none_or(|status| matches!(status, 200 | 404))),
        "iCloud returned incomplete Contacts results"
    );
    Ok(document)
}

fn responses<'a, 'xml>(doc: &'a Document<'xml>) -> impl Iterator<Item = Node<'a, 'xml>> {
    doc.root_element()
        .children()
        .filter(|node| node.has_tag_name((DAV, "response")))
}

fn child<'a, 'xml>(node: Node<'a, 'xml>, ns: &str, name: &str) -> Option<Node<'a, 'xml>> {
    node.children().find(|child| child.has_tag_name((ns, name)))
}

fn status(node: Node<'_, '_>) -> Option<u16> {
    child(node, DAV, "status")?
        .text()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

fn property<'a, 'xml>(response: Node<'a, 'xml>, ns: &str, name: &str) -> Option<Node<'a, 'xml>> {
    response
        .children()
        .filter(|node| node.has_tag_name((DAV, "propstat")) && status(*node) == Some(200))
        .find_map(|node| child(node, DAV, "prop").and_then(|prop| child(prop, ns, name)))
}

fn href<'a>(node: Node<'a, '_>) -> Result<&'a str> {
    child(node, DAV, "href")
        .and_then(|href| href.text())
        .context("iCloud omitted a Contacts address")
}

fn default_region() -> Option<phonenumber::country::Id> {
    ["LC_ALL", "LC_TELEPHONE", "LANG"]
        .into_iter()
        .filter_map(|key| std::env::var(key).ok())
        .find_map(|locale| {
            let (_, region) = locale.split_once('_')?;
            region.split(['.', '@']).next()?.parse().ok()
        })
}

fn parse_card(card: &str, region: Option<phonenumber::country::Id>) -> Result<Vec<Recipient>> {
    let mut lines: Vec<String> = Vec::new();
    for line in card.trim_matches(['\r', '\n']).lines() {
        if let Some(continuation) = line.strip_prefix([' ', '\t'])
            && let Some(previous) = lines.last_mut()
        {
            previous.push_str(continuation);
        } else {
            lines.push(line.to_owned());
        }
    }
    ensure!(
        lines.first().is_some_and(|line| line
            .trim_start_matches('\u{feff}')
            .eq_ignore_ascii_case("BEGIN:VCARD"))
            && lines
                .iter()
                .rfind(|line| !line.is_empty())
                .is_some_and(|line| line.eq_ignore_ascii_case("END:VCARD")),
        "iCloud returned an incomplete contact card"
    );
    let mut display_name = String::new();
    let mut structured_name = String::new();
    let mut addresses = BTreeSet::new();
    for line in &lines {
        let mut quoted = false;
        let delimiter = line.char_indices().find_map(|(index, ch)| {
            if ch == '"' {
                quoted = !quoted;
            }
            (ch == ':' && !quoted).then_some(index)
        });
        let Some(delimiter) = delimiter else { continue };
        let field = line[..delimiter]
            .split(';')
            .next()
            .unwrap_or_default()
            .rsplit('.')
            .next()
            .unwrap_or_default();
        let raw = &line[delimiter + 1..];
        let value = unescape(raw);
        match field.to_ascii_uppercase().as_str() {
            "FN" if display_name.is_empty() => display_name = clean_name(&value),
            "N" if structured_name.is_empty() => {
                let mut parts = raw.split(';');
                let family = unescape(parts.next().unwrap_or_default());
                let given = unescape(parts.next().unwrap_or_default());
                structured_name = clean_name(&format!("{given} {family}"));
            }
            "EMAIL" => {
                if let Ok(address) = linux_imessage::address(value.trim())
                    && address.starts_with("mailto:")
                {
                    addresses.insert(address);
                }
            }
            "TEL" => {
                let value = value.trim().strip_prefix("tel:").unwrap_or(value.trim());
                let value = value
                    .strip_prefix("00")
                    .map(|digits| format!("+{digits}"))
                    .unwrap_or_else(|| value.to_owned());
                if let Ok(number) = phonenumber::parse(region, &value)
                    && number.is_valid()
                {
                    addresses.insert(format!(
                        "tel:{}",
                        number.format().mode(phonenumber::Mode::E164)
                    ));
                }
            }
            _ => (),
        }
    }
    let name = if display_name.is_empty() {
        structured_name
    } else {
        display_name
    };
    Ok(addresses
        .into_iter()
        .map(|address| Recipient {
            name: if name.is_empty() {
                linux_imessage::display_address(&address).to_owned()
            } else {
                name.clone()
            },
            address,
        })
        .collect())
}

fn clean_name(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .filter(|ch| !ch.is_control())
        .take(128)
        .collect()
}

fn unescape(value: &str) -> String {
    let mut chars = value.chars();
    let mut text = String::new();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            text.push(match chars.next() {
                Some('n' | 'N') => '\n',
                Some(next) => next,
                None => '\\',
            });
        } else {
            text.push(ch);
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, http::Uri, response::IntoResponse};
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    #[tokio::test]
    async fn discovers_icloud_address_books_and_fetches_only_contact_fields() -> Result<()> {
        linux_imessage::install_tls_provider();
        const ACCOUNT: &str = "person@example.invalid";
        const PASSWORD: &str = "fixture-app-password";
        let app = Router::new().fallback(|method: Method, uri: Uri, headers: header::HeaderMap, body: String| async move {
            assert_eq!(headers[header::AUTHORIZATION], format!("Basic {}", STANDARD.encode(format!("{ACCOUNT}:{PASSWORD}"))));
            let good = |href, prop| format!("<d:response><d:href>{href}</d:href><d:propstat><d:prop>{prop}</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>");
            let depth = headers["depth"].to_str().unwrap();
            let response = match (method.as_str(), uri.path(), depth) {
                ("PROPFIND", "/", "0") => return (StatusCode::TEMPORARY_REDIRECT, [(header::LOCATION, "/discovery")]).into_response(),
                ("PROPFIND", "/discovery", "0") => {
                    assert!(body.contains("current-user-principal"));
                    good("/discovery", "<d:current-user-principal><d:href>/principal/</d:href></d:current-user-principal>")
                }
                ("PROPFIND", "/principal/", "0") => {
                    assert!(body.contains("addressbook-home-set"));
                    good("/principal/", "<c:addressbook-home-set><d:href>/contacts/</d:href></c:addressbook-home-set>")
                }
                ("PROPFIND", "/contacts/", "1") => good("/contacts/card", "<d:resourcetype><d:collection/><c:addressbook/></d:resourcetype>"),
                ("PROPFIND", "/contacts/card/", "1") => good("/contacts/card/", "<d:resourcetype><d:collection/></d:resourcetype><d:getetag>book</d:getetag>")
                    + &good("/contacts/card/person.vcf", "<d:resourcetype/><d:getetag>1</d:getetag>"),
                ("REPORT", "/contacts/card/", "0") => {
                    assert!(body.contains("addressbook-multiget") && body.contains("/contacts/card/person.vcf") && body.contains("name=\"TEL\"") && !body.contains("PHOTO"));
                    good("/contacts/card/person.vcf", "<c:address-data><![CDATA[BEGIN:VCARD\nFN:Zoë\n  Hart\nitem1.EMAIL;TYPE=HOME:Zoe@Example.Invalid\nitem2.TEL;TYPE=CELL:07911 123456\nEND:VCARD]]></c:address-data>")
                }
                unexpected => panic!("Unexpected Contacts request {unexpected:?}"),
            };
            (StatusCode::MULTI_STATUS, format!(r#"<d:multistatus xmlns:d="{DAV}" xmlns:c="{CARDDAV}">{response}</d:multistatus>"#)).into_response()
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let origin = Url::parse(&format!("http://{}/", listener.local_addr()?))?;
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let dav = CardDav {
            client: Client::builder().no_proxy().build()?,
            origin,
            account: ACCOUNT,
            password: PASSWORD,
            headers: header::HeaderMap::new(),
        };
        let recipients = dav
            .contacts(Some(phonenumber::country::Id::GB), None)
            .await?;
        server.abort();
        assert_eq!(
            recipients
                .iter()
                .map(|entry| (entry.name.as_str(), entry.address.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("Zoë Hart", "mailto:zoe@example.invalid"),
                ("Zoë Hart", "tel:+447911123456"),
            ]
        );
        assert!(
            dav.href(
                &dav.origin,
                "https://p123-contacts.icloud.com:443/account/card/"
            )
            .is_ok()
        );
        for destination in [
            "https://contacts.icloud.com.example.invalid/",
            "http://contacts.icloud.com/",
            "https://user@contacts.icloud.com/",
            "https://contacts.icloud.com:8443/",
        ] {
            assert!(dav.href(&dav.origin, destination).is_err());
        }
        Ok(())
    }
}
