//! Cloud KMS signing with automatic algorithm discovery.

use bytes::Bytes;
use chewie_crypto::signer::Signer;
use google_cloud_kms_v1::{
    client::KeyManagementService, model::crypto_key_version::CryptoKeyVersionAlgorithm,
};
use snafu::prelude::*;

/// Errors that can occur when creating a key.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum SetupError {
    /// Failed to retrieve crypto key details.
    GetCryptoKey {
        /// The underlying error from the KMS API.
        source: google_cloud_kms_v1::Error,
    },
    /// The specified key uses an unsupported algorithm.
    UnsupportedAlgorithm {
        /// The algorithm reported by the KMS API.
        algorithm: CryptoKeyVersionAlgorithm,
    },
}

/// Errors that can occur when using a key.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum SigningError {
    /// Failed to sign data with the key.
    AsymmetricSign {
        /// The underlying error from the KMS API.
        source: google_cloud_kms_v1::Error,
    },
}

/// Information about the algorithm supported by the key.
#[derive(Debug, Clone)]
struct AlgorithmInfo {
    /// A human readable algorithm name.
    algorithm: &'static str,
    #[allow(dead_code)]
    /// The JWS-compatible algorithm name.
    jwt_alg: &'static str,
}

/// An asymmetric key that supports JWS, stored in Google Cloud KMS.
#[derive(Debug, Clone)]
pub struct AsymmetricJwsKey {
    /// The KMS client used for operations.
    client: KeyManagementService,
    /// The full resource name of the key.
    resource_name: String,
    /// Information about the algorithm supported by the key.
    algorithm_info: AlgorithmInfo,
}

impl AsymmetricJwsKey {
    /// Create a new `AsymmetricJwsKey`.
    ///
    /// # Errors
    ///
    /// Returns an error if the key information could not be retrieved,
    /// or the algorithm is not supported.
    pub async fn new(
        kms_client: KeyManagementService,
        resource_name: impl Into<String>,
    ) -> Result<Self, SetupError> {
        let resource_name = resource_name.into();
        let algorithm_info = get_algorithm_info_for_resource(&kms_client, &resource_name).await?;

        Ok(Self {
            client: kms_client,
            resource_name,
            algorithm_info,
        })
    }
}

impl Signer for AsymmetricJwsKey {
    type Error = SigningError;

    fn algorithm(&self) -> &str {
        self.algorithm_info.algorithm
    }

    async fn sign(&self, input: &[u8]) -> Result<Bytes, Self::Error> {
        let result = self
            .client
            .asymmetric_sign()
            .set_name(&self.resource_name)
            .set_data(input.to_vec())
            .send()
            .await
            .context(AsymmetricSignSnafu)?;

        Ok(result.signature)
    }
}

async fn get_algorithm_info_for_resource(
    kms_client: &KeyManagementService,
    resource_name: &str,
) -> Result<AlgorithmInfo, SetupError> {
    let key_version = kms_client
        .get_crypto_key_version()
        .set_name(resource_name)
        .send()
        .await
        .context(GetCryptoKeySnafu)?;

    let algorithm =
        get_algorithm_info(&key_version.algorithm).with_context(|| UnsupportedAlgorithmSnafu {
            algorithm: key_version.algorithm,
        })?;

    Ok(algorithm)
}

fn get_algorithm_info(algorithm: &CryptoKeyVersionAlgorithm) -> Option<AlgorithmInfo> {
    use CryptoKeyVersionAlgorithm::{
        EcSignEd25519, EcSignP256Sha256, EcSignP384Sha384, RsaSignPkcs12048Sha256,
        RsaSignPkcs13072Sha256, RsaSignPkcs14096Sha256, RsaSignPkcs14096Sha512,
        RsaSignPss2048Sha256, RsaSignPss3072Sha256, RsaSignPss4096Sha256, RsaSignPss4096Sha512,
    };

    match algorithm {
        // RSA-PSS SHA-256 variants (2048/3072/4096 bit keys)
        RsaSignPss2048Sha256 | RsaSignPss3072Sha256 | RsaSignPss4096Sha256 => Some(AlgorithmInfo {
            algorithm: "RSA-PSS-SHA256",
            jwt_alg: "PS256",
        }),
        // RSA-PSS SHA-512 variant
        RsaSignPss4096Sha512 => Some(AlgorithmInfo {
            algorithm: "RSA-PSS-SHA512",
            jwt_alg: "PS512",
        }),
        // RSA PKCS#1 v1.5 SHA-256 variants (2048/3072/4096 bit keys)
        RsaSignPkcs12048Sha256 | RsaSignPkcs13072Sha256 | RsaSignPkcs14096Sha256 => {
            Some(AlgorithmInfo {
                algorithm: "RSA-PKCS1-SHA256",
                jwt_alg: "RS256",
            })
        }
        // RSA PKCS#1 v1.5 SHA-512 variant
        RsaSignPkcs14096Sha512 => Some(AlgorithmInfo {
            algorithm: "RSA-PKCS1-SHA512",
            jwt_alg: "RS512",
        }),
        // ECDSA P-256
        EcSignP256Sha256 => Some(AlgorithmInfo {
            algorithm: "ECDSA-P256",
            jwt_alg: "ES256",
        }),
        // ECDSA P-384
        EcSignP384Sha384 => Some(AlgorithmInfo {
            algorithm: "ECDSA-P384",
            jwt_alg: "ES384",
        }),
        // EdDSA (Ed25519)
        EcSignEd25519 => Some(AlgorithmInfo {
            algorithm: "EdDSA-Ed25519",
            jwt_alg: "Ed25519",
        }),
        _ => None,
    }
}
