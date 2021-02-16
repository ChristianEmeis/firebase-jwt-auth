// See https://firebase.google.com/docs/auth/admin/verify-id-tokens

use chrono::Utc;
use jsonwebtoken::errors::Error as JwtError;
use jsonwebtoken::{decode, DecodingKey, Validation};
use jsonwebtoken::{decode_header, TokenData};
use lazy_static::*;
use regex::Regex;
use reqwest;
use serde::{Deserialize, Serialize};
use std::{
    convert::TryInto,
    sync::{Arc, Mutex},
    time::Duration,
    time::SystemTime,
    time::UNIX_EPOCH,
};

const GOOGLE_JWK_URL: &'static str =
    "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";

lazy_static! {
    static ref GOOGLE_PUBLC_KEYS_CACHE: Arc<Mutex<Option<GoogleAuthKeys>>> =
        Arc::new(Mutex::new(None));
}

#[derive(Deserialize, Debug)]
struct JsonWebKey {
    e: String,
    n: String,
    kid: String,
}

#[derive(Deserialize, Debug)]
struct JsonWebKeys {
    keys: Vec<JsonWebKey>,
}

#[derive(Debug)]
struct GoogleAuthKeys {
    expires: Duration,
    keys: JsonWebKeys,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FirebaseClaims {
    exp: usize,
    iat: usize,
    aud: String,
    iss: String,
    sub: String,
    auth_time: usize,
    user_id: String,
    email: Option<String>,
    email_verified: Option<bool>,
    firebase: Option<serde_json::Value>
}

#[derive(Debug, thiserror::Error)]
pub enum FirebaseAuthenticationError {
    #[error("Failed to accquire lock on Google keys cache mutex")]
    KeyCacheMutexLockFailed,

    #[error("Google auth keys were null when they should not have been")]
    MissingKeys,

    #[error("Failed to validate JWT")]
    JwtValidationFailed {
        detail: Option<String>,

        #[source]
        source: Option<JwtError>,
    },

    #[error("Failed to fetch Google auth keys. Details: {}", detail)]
    FetchKeysFailed {
        detail: String,

        #[source]
        source: Option<Box<dyn std::error::Error>>,
    },

    #[error("No matching Google key for JWT kid")]
    NoMatchingKey,

    #[error("Failed to parse Google keys from {}", GOOGLE_JWK_URL)]
    GoogleKeysParsingFailed {
        #[source]
        source: Box<reqwest::Error>,
    },
}

pub async fn extract_firebase_token_claims(
    token: &str,
    firebase_id: &str,
) -> Result<FirebaseClaims, FirebaseAuthenticationError> {
    update_google_keys_cache_if_required().await?;

    if let Some(ref cached_keys) = *(GOOGLE_PUBLC_KEYS_CACHE
        .lock()
        .map_err(|_| FirebaseAuthenticationError::KeyCacheMutexLockFailed)?)
    {
        let token_header =
            decode_header(token).map_err(|err| FirebaseAuthenticationError::JwtValidationFailed {
                detail: Some(String::from("Failed to decode JWT header")),
                source: Some(err),
            })?;

        let key_id =
            token_header
                .kid
                .ok_or_else(|| FirebaseAuthenticationError::JwtValidationFailed {
                    detail: Some(String::from(
                        "kid is not present or couldn't be extrated from JWT",
                    )),
                    source: None,
                })?;
        let key = cached_keys
            .keys
            .keys
            .iter()
            .find(|x| x.kid == key_id)
            .ok_or_else(|| FirebaseAuthenticationError::NoMatchingKey)?;

        let decoding_key = DecodingKey::from_rsa_components(&key.n, &key.e);

        // Validation requirements according to Google docs
        // exp,
        //
        // Key         Name                  Description
        //________________________________________________________________________________________________________________________________________________________________________________
        // exp 	     | Expiration time	   | Must be in the future. The time is measured in seconds since the UNIX epoch.
        // iat	     | Issued-at time	   | Must be in the past. The time is measured in seconds since the UNIX epoch.
        // aud	     | Audience	           | Must be your Firebase project ID, the unique identifier for your Firebase project, which can be found in the URL of that project's console.
        // iss	     | Issuer	           | Must be "https://securetoken.google.com/<projectId>", where <projectId> is the same project ID used for aud above.
        // sub	     | Subject	           | Must be a non-empty string and must be the uid of the user or device.
        // auth_time | Authentication time | Must be in the past. The time when the user authenticated.

        let mut validation = Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_audience(&[firebase_id]);
        validation.iss = Some(format!(
            "https://securetoken.google.com/{}",
            firebase_id
        ));

        let token_data: TokenData<FirebaseClaims> = decode(token, &decoding_key, &validation)
            .map_err(|err| FirebaseAuthenticationError::JwtValidationFailed {
                detail: None,
                source: Some(err),
            })?;

        if token_data.claims.sub.is_empty() {
            return Err(FirebaseAuthenticationError::JwtValidationFailed {
                detail: Some(String::from(
                    "sub must be a non-empty string and must be the uid of the user or device",
                )),
                source: None,
            });
        }

        if Utc::now().timestamp()
            < token_data
                .claims
                .auth_time
                .try_into()
                .expect("Failed to convert usize to i64")
        {
            return Err(FirebaseAuthenticationError::JwtValidationFailed {
                detail: Some(String::from("auth_time must be in the past. auth_time is the time when the user was authenticated")),
                source: None,
            });
        }

        Ok(token_data.claims)
    } else {
        return Err(FirebaseAuthenticationError::MissingKeys);
    }
}

async fn update_google_keys_cache_if_required() -> Result<(), FirebaseAuthenticationError> {
    let cached_keys = &mut *GOOGLE_PUBLC_KEYS_CACHE
        .lock()
        .map_err(|_| FirebaseAuthenticationError::KeyCacheMutexLockFailed)?;

    let requires_fetch = match *cached_keys {
        Some(ref keys) => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|err| FirebaseAuthenticationError::FetchKeysFailed {
                    detail: String::from("Failed to get duration since UNIX_EPOCH"),
                    source: Some(Box::new(err)),
                })?;

            // 10 seconds of leeway
            keys.expires.as_secs() - 10 < now.as_secs()
        }
        None => true,
    };

    if requires_fetch {
        let resp = reqwest::get(GOOGLE_JWK_URL).await.map_err(|err| {
            FirebaseAuthenticationError::FetchKeysFailed {
                detail: String::from("Request for Google auth keys failed"),
                source: Some(Box::new(err)),
            }
        })?;

        let max_age: usize = match resp.headers().get("cache-control") {
            Some(value) => {
                let re = Regex::new("max-age=([0-9]*)").unwrap();
                let value_str = value.to_str().map_err(|err| FirebaseAuthenticationError::FetchKeysFailed {
                    detail: String::from("Failed to covert cache-control header value bytes into str"),                  
                    source: Some(Box::new(err))
                })?;
                let captures = re.captures(value_str).ok_or(FirebaseAuthenticationError::FetchKeysFailed {
                    detail: String::from(format!("Failed to extract max-age from cache-control header due to no regex match. cache-control={}", value_str)),
                    source: None,
                })?;

                let max_age_str = captures.get(1).ok_or(FirebaseAuthenticationError::FetchKeysFailed {
                    detail: String::from(format!("Failed to extract max-age from cache-control header due to no regex match. cache-control={}", value_str)),
                    source: None,
                })?.as_str();

                max_age_str.parse::<usize>().map_err(|err| FirebaseAuthenticationError::FetchKeysFailed {
                    detail: String::from("max-age was extracted from the cache-control header but could not be parsed as usize"),
                    source: Some(Box::new(err))
                })?
            },
            None => return Err(FirebaseAuthenticationError::FetchKeysFailed {
                detail: String::from("Failed to extract max-age from cache-control header because the header wasn't present"),
                source: None,
            })
        };

        let now = SystemTime::now();

        let mut expires = now.duration_since(UNIX_EPOCH).map_err(|err| {
            FirebaseAuthenticationError::FetchKeysFailed {
                detail: String::from("Failed to get duration since UNIX_EPOCH"),
                source: Some(Box::new(err)),
            }
        })?;

        expires += Duration::new(max_age as u64, 0);

        let keys: JsonWebKeys = resp.json().await.map_err(|err| {
            FirebaseAuthenticationError::GoogleKeysParsingFailed {
                source: Box::new(err),
            }
        })?;

        let keys = GoogleAuthKeys {
            keys,
            expires,
        };

        *cached_keys = Some(keys);
    }

    Ok(())
}
