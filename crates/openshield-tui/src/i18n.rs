use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use thiserror::Error;

const MAX_LOCALE_INPUT_BYTES: usize = 64;
const MAX_RESOURCE_BYTES: usize = 128 * 1024;
const MAX_MESSAGES: usize = 256;
const MAX_MESSAGE_CHARS: usize = 8_192;

const EN: &str = include_str!("../locales/en.json");
const RU: &str = include_str!("../locales/ru.json");
const ZH: &str = include_str!("../locales/zh.json");
const ES: &str = include_str!("../locales/es.json");
const HI: &str = include_str!("../locales/hi.json");
const AR: &str = include_str!("../locales/ar.json");
const PT: &str = include_str!("../locales/pt.json");
const FR: &str = include_str!("../locales/fr.json");
const DE: &str = include_str!("../locales/de.json");
const JA: &str = include_str!("../locales/ja.json");
const KO: &str = include_str!("../locales/ko.json");
const ID: &str = include_str!("../locales/id.json");
const TR: &str = include_str!("../locales/tr.json");
const IT: &str = include_str!("../locales/it.json");
const PL: &str = include_str!("../locales/pl.json");
const UK: &str = include_str!("../locales/uk.json");
const NL: &str = include_str!("../locales/nl.json");
const VI: &str = include_str!("../locales/vi.json");
const TH: &str = include_str!("../locales/th.json");
const FA: &str = include_str!("../locales/fa.json");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Locale {
    En,
    Ru,
    Zh,
    Es,
    Hi,
    Ar,
    Pt,
    Fr,
    De,
    Ja,
    Ko,
    Id,
    Tr,
    It,
    Pl,
    Uk,
    Nl,
    Vi,
    Th,
    Fa,
}

impl Locale {
    #[cfg(test)]
    pub const SUPPORTED: [Self; 20] = [
        Self::En,
        Self::Ru,
        Self::Zh,
        Self::Es,
        Self::Hi,
        Self::Ar,
        Self::Pt,
        Self::Fr,
        Self::De,
        Self::Ja,
        Self::Ko,
        Self::Id,
        Self::Tr,
        Self::It,
        Self::Pl,
        Self::Uk,
        Self::Nl,
        Self::Vi,
        Self::Th,
        Self::Fa,
    ];

    pub const fn code(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::Ru => "ru",
            Self::Zh => "zh",
            Self::Es => "es",
            Self::Hi => "hi",
            Self::Ar => "ar",
            Self::Pt => "pt",
            Self::Fr => "fr",
            Self::De => "de",
            Self::Ja => "ja",
            Self::Ko => "ko",
            Self::Id => "id",
            Self::Tr => "tr",
            Self::It => "it",
            Self::Pl => "pl",
            Self::Uk => "uk",
            Self::Nl => "nl",
            Self::Vi => "vi",
            Self::Th => "th",
            Self::Fa => "fa",
        }
    }

    const fn resource(self) -> &'static str {
        match self {
            Self::En => EN,
            Self::Ru => RU,
            Self::Zh => ZH,
            Self::Es => ES,
            Self::Hi => HI,
            Self::Ar => AR,
            Self::Pt => PT,
            Self::Fr => FR,
            Self::De => DE,
            Self::Ja => JA,
            Self::Ko => KO,
            Self::Id => ID,
            Self::Tr => TR,
            Self::It => IT,
            Self::Pl => PL,
            Self::Uk => UK,
            Self::Nl => NL,
            Self::Vi => VI,
            Self::Th => TH,
            Self::Fa => FA,
        }
    }
}

impl fmt::Display for Locale {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl FromStr for Locale {
    type Err = LocaleError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        parse_locale(value)
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum LocaleError {
    #[error("invalid locale identifier")]
    Invalid,
    #[error("unsupported locale: {0}")]
    Unsupported(String),
    #[error("invalid embedded {locale} translation resource: {reason}")]
    InvalidResource {
        locale: &'static str,
        reason: String,
    },
}

#[derive(Clone, Debug)]
pub struct I18n {
    messages: Arc<BTreeMap<String, String>>,
}

impl I18n {
    pub fn load(locale: Locale) -> Result<Self, LocaleError> {
        let english = parse_resource(Locale::En)?;
        let messages = if locale == Locale::En {
            english
        } else {
            let translated = parse_resource(locale)?;
            validate_overrides(locale, &english, &translated)?;
            let mut merged = english.clone();
            merged.extend(translated);
            validate_parity(locale, &english, &merged)?;
            merged
        };
        Ok(Self {
            messages: Arc::new(messages),
        })
    }

    pub fn detect() -> Result<Self, LocaleError> {
        Self::load(detect_locale_from(|name| env::var(name).ok()))
    }

    pub fn tr<'a>(&'a self, key: &'a str) -> &'a str {
        self.messages.get(key).map_or(key, String::as_str)
    }

    pub fn format(&self, key: &str, arguments: &[(&str, &str)]) -> String {
        interpolate(self.tr(key), arguments)
    }

    #[cfg(test)]
    pub fn test_english() -> Self {
        Self::load(Locale::En).unwrap_or_else(|_| Self {
            messages: Arc::new(BTreeMap::new()),
        })
    }
}

pub fn detect_locale_from(mut get: impl FnMut(&str) -> Option<String>) -> Locale {
    for variable in ["LC_ALL", "LC_MESSAGES", "LANGUAGE", "LANG"] {
        let Some(value) = get(variable) else {
            continue;
        };
        for candidate in value.split(':') {
            match parse_locale(candidate) {
                Ok(locale) => return locale,
                Err(
                    LocaleError::Invalid
                    | LocaleError::Unsupported(_)
                    | LocaleError::InvalidResource { .. },
                ) => {}
            }
        }
    }
    Locale::En
}

fn parse_locale(value: &str) -> Result<Locale, LocaleError> {
    if value.is_empty()
        || value.len() > MAX_LOCALE_INPUT_BYTES
        || !value.is_ascii()
        || value.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'@'))
        })
    {
        return Err(LocaleError::Invalid);
    }

    let (without_modifier, modifier) = value
        .split_once('@')
        .map_or((value, None), |(base, suffix)| (base, Some(suffix)));
    if modifier.is_some_and(|suffix| {
        suffix.is_empty()
            || !suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    }) || without_modifier.contains('@')
    {
        return Err(LocaleError::Invalid);
    }
    let (without_encoding, encoding) = without_modifier
        .split_once('.')
        .map_or((without_modifier, None), |(base, suffix)| {
            (base, Some(suffix))
        });
    if encoding.is_some_and(|suffix| {
        suffix.is_empty()
            || !suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) || without_encoding.contains('.')
        || without_encoding.is_empty()
    {
        return Err(LocaleError::Invalid);
    }
    if without_encoding.eq_ignore_ascii_case("c") || without_encoding.eq_ignore_ascii_case("posix")
    {
        return Ok(Locale::En);
    }
    let mut components = without_encoding.split(['_', '-']);
    let language_component = components.next().ok_or(LocaleError::Invalid)?;
    if !(2..=3).contains(&language_component.len())
        || !language_component
            .bytes()
            .all(|byte| byte.is_ascii_alphabetic())
        || components.any(|component| {
            component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
    {
        return Err(LocaleError::Invalid);
    }
    let language = language_component.to_ascii_lowercase();
    let locale = match language.as_str() {
        "en" => Locale::En,
        "ru" => Locale::Ru,
        "zh" => Locale::Zh,
        "es" => Locale::Es,
        "hi" => Locale::Hi,
        "ar" => Locale::Ar,
        "pt" => Locale::Pt,
        "fr" => Locale::Fr,
        "de" => Locale::De,
        "ja" => Locale::Ja,
        "ko" => Locale::Ko,
        "id" => Locale::Id,
        "tr" => Locale::Tr,
        "it" => Locale::It,
        "pl" => Locale::Pl,
        "uk" => Locale::Uk,
        "nl" => Locale::Nl,
        "vi" => Locale::Vi,
        "th" => Locale::Th,
        "fa" => Locale::Fa,
        _ => return Err(LocaleError::Unsupported(language)),
    };
    Ok(locale)
}

fn parse_resource(locale: Locale) -> Result<BTreeMap<String, String>, LocaleError> {
    let resource = locale.resource();
    if resource.len() > MAX_RESOURCE_BYTES {
        return Err(resource_error(locale, "resource is too large"));
    }
    let messages = serde_json::from_str::<BTreeMap<String, String>>(resource)
        .map_err(|error| resource_error(locale, &error.to_string()))?;
    if messages.is_empty() || messages.len() > MAX_MESSAGES {
        return Err(resource_error(locale, "invalid message count"));
    }
    for (key, value) in &messages {
        if key.is_empty()
            || !key.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_')
            })
        {
            return Err(resource_error(locale, "invalid message key"));
        }
        if value.is_empty() || value.chars().count() > MAX_MESSAGE_CHARS {
            return Err(resource_error(locale, "invalid message length"));
        }
        if value
            .chars()
            .any(|character| character.is_control() && character != '\n')
        {
            return Err(resource_error(locale, "control character in message"));
        }
        placeholders(value).map_err(|reason| resource_error(locale, reason))?;
    }
    Ok(messages)
}

fn validate_parity(
    locale: Locale,
    english: &BTreeMap<String, String>,
    translated: &BTreeMap<String, String>,
) -> Result<(), LocaleError> {
    if english.keys().ne(translated.keys()) {
        return Err(resource_error(locale, "message keys differ from English"));
    }
    for (key, english_value) in english {
        let Some(translated_value) = translated.get(key) else {
            return Err(resource_error(locale, "message missing"));
        };
        let english_placeholders =
            placeholders(english_value).map_err(|reason| resource_error(Locale::En, reason))?;
        let translated_placeholders =
            placeholders(translated_value).map_err(|reason| resource_error(locale, reason))?;
        if english_placeholders != translated_placeholders {
            return Err(resource_error(
                locale,
                "message placeholders differ from English",
            ));
        }
    }
    Ok(())
}

fn validate_overrides(
    locale: Locale,
    english: &BTreeMap<String, String>,
    translated: &BTreeMap<String, String>,
) -> Result<(), LocaleError> {
    for (key, translated_value) in translated {
        let Some(english_value) = english.get(key) else {
            return Err(resource_error(
                locale,
                "translation contains an unknown key",
            ));
        };
        let english_placeholders =
            placeholders(english_value).map_err(|reason| resource_error(Locale::En, reason))?;
        let translated_placeholders =
            placeholders(translated_value).map_err(|reason| resource_error(locale, reason))?;
        if english_placeholders != translated_placeholders {
            return Err(resource_error(
                locale,
                "message placeholders differ from English",
            ));
        }
    }
    Ok(())
}

fn placeholders(value: &str) -> Result<BTreeSet<&str>, &'static str> {
    let mut result = BTreeSet::new();
    let mut remainder = value;
    while let Some(start) = remainder.find('{') {
        let after_start = &remainder[start + 1..];
        let Some(end) = after_start.find('}') else {
            return Err("unclosed placeholder");
        };
        let name = &after_start[..end];
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        {
            return Err("invalid placeholder");
        }
        result.insert(name);
        remainder = &after_start[end + 1..];
    }
    if remainder.contains('}') {
        return Err("unmatched closing brace");
    }
    Ok(result)
}

fn interpolate(template: &str, arguments: &[(&str, &str)]) -> String {
    let mut output = String::with_capacity(template.len());
    let mut remainder = template;
    while let Some(start) = remainder.find('{') {
        output.push_str(&remainder[..start]);
        let after_start = &remainder[start + 1..];
        let Some(end) = after_start.find('}') else {
            output.push_str(&remainder[start..]);
            return output;
        };
        let name = &after_start[..end];
        if let Some((_, value)) = arguments.iter().find(|(candidate, _)| *candidate == name) {
            output.push_str(value);
        } else {
            output.push('{');
            output.push_str(name);
            output.push('}');
        }
        remainder = &after_start[end + 1..];
    }
    output.push_str(remainder);
    output
}

fn resource_error(locale: Locale, reason: &str) -> LocaleError {
    LocaleError::InvalidResource {
        locale: locale.code(),
        reason: reason.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_twenty_resources_are_complete_and_have_placeholder_parity() {
        assert_eq!(Locale::SUPPORTED.len(), 20);
        for locale in Locale::SUPPORTED {
            let loaded = I18n::load(locale);
            assert!(loaded.is_ok(), "{locale}: {loaded:?}");
            if locale != Locale::En {
                let overrides = parse_resource(locale);
                assert!(
                    overrides.is_ok_and(|messages| {
                        parse_resource(Locale::En)
                            .is_ok_and(|english| messages.keys().eq(english.keys()))
                    }),
                    "{locale}: translation resource does not have exact key parity"
                );
            }
        }
    }

    #[test]
    fn locale_normalization_accepts_common_posix_forms() {
        assert_eq!(parse_locale("ru_RU.UTF-8"), Ok(Locale::Ru));
        assert_eq!(parse_locale("pt-BR"), Ok(Locale::Pt));
        assert_eq!(parse_locale("C.UTF-8"), Ok(Locale::En));
    }

    #[test]
    fn unknown_auto_detected_locale_falls_back_to_english() {
        let locale = detect_locale_from(|name| (name == "LANG").then(|| "xx_XX.UTF-8".to_owned()));
        assert_eq!(locale, Locale::En);
    }

    #[test]
    fn language_priority_list_uses_first_supported_locale() {
        let locale =
            detect_locale_from(|name| (name == "LANGUAGE").then(|| "xx:uk_UA:en".to_owned()));
        assert_eq!(locale, Locale::Uk);
    }

    #[test]
    fn locale_environment_precedence_is_deterministic() {
        let locale = detect_locale_from(|name| match name {
            "LC_ALL" => Some("de_DE.UTF-8".to_owned()),
            "LC_MESSAGES" => Some("fr_FR.UTF-8".to_owned()),
            "LANGUAGE" => Some("es".to_owned()),
            "LANG" => Some("ru_RU.UTF-8".to_owned()),
            _ => None,
        });
        assert_eq!(locale, Locale::De);
    }

    #[test]
    fn malicious_locale_inputs_are_rejected_without_filesystem_access() {
        for value in [
            "../../etc/passwd",
            "..\\..\\windows",
            "/tmp/ru",
            "ru\0en",
            "ru;sh",
            "ru en",
            "..",
            ".UTF-8",
            "en..UTF-8",
            "en@",
            "русский",
        ] {
            assert_eq!(parse_locale(value), Err(LocaleError::Invalid), "{value:?}");
        }
    }

    #[test]
    fn explicit_unknown_locale_is_reported() {
        assert_eq!(
            parse_locale("zz-ZZ"),
            Err(LocaleError::Unsupported("zz".to_owned()))
        );
    }

    #[test]
    fn interpolation_does_not_reinterpret_untrusted_argument_braces() {
        let translated = interpolate("before {value} after", &[("value", "{other}\u{1b}[31m")]);
        assert_eq!(translated, "before {other}\u{1b}[31m after");
    }
}
