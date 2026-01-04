//! Google Cloud Secret Manager integration for retrieving secrets.

use bon::Builder;
use chewie_crypto::secrets::{EncodingError, SecretEncoding, SecretSource};
use google_cloud_secretmanager_v1::client::SecretManagerService;
use snafu::prelude::*;

/// Errors that can occur when using the Google Cloud Secret Manager API.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum SecretSourceError {
    /// Failed to access the secret value data.
    AccessSecret {
        /// The underlying error from the Secret Manager API.
        source: google_cloud_secretmanager_v1::Error,
    },
    /// The secret response did not contain a payload.
    ///
    /// This may happen if the secret is disabled or destroyed.
    MissingPayload,
    /// Failed to decode the secret data.
    Decode {
        /// The encoding error
        source: EncodingError,
    },
}

/// A secret value stored in Google Cloud Secret Manager.
///
/// # Usage
///
/// ```rust
/// # use chewie_crypto::secrets::StringEncoding;
/// # use chewie_crypto_gcp::secretmanager::SecretManagerSource;
/// # use google_cloud_secretmanager_v1::client::SecretManagerService;
///
/// async fn setup(secret_manager: SecretManagerService) {
/// # let secret = SecretManagerSource::builder()
///   .client(secret_manager)
///   .resource_name("projects/boogawooga/secrets/my-private-secret/versions/1")
///   .encoding(StringEncoding)
///   .build();
/// # }
/// ```
#[derive(Debug, Clone, Builder)]
pub struct SecretManagerSource<E: SecretEncoding> {
    /// The Secret Manager client used for operations.
    client: SecretManagerService,
    /// The secret resource name (e.g. "projects/x/secrets/y/versions/z").
    #[builder(into)]
    resource_name: String,
    /// The encoding applied to the secret data.
    encoding: E,
}

impl<E: SecretEncoding> SecretSource for SecretManagerSource<E> {
    type Error = SecretSourceError;
    type Output = E::Output;

    async fn get_secret(&self) -> Result<Self::Output, Self::Error> {
        let response = self
            .client
            .access_secret_version()
            .set_name(&self.resource_name)
            .send()
            .await
            .context(AccessSecretSnafu)?;

        let payload = response.payload.context(MissingPayloadSnafu)?;
        self.encoding.decode(&payload.data).context(DecodeSnafu)
    }
}
