use bytes::Bytes;
use chewie_crypto::prelude::*;
use chewie_crypto_gcp::kms::{AsymmetricJwsKey, SetupError};
use google_cloud_gax::response::Response;
use google_cloud_kms_v1::{
    client::KeyManagementService,
    model::{
        AsymmetricSignRequest, AsymmetricSignResponse, CryptoKeyVersion,
        GetCryptoKeyVersionRequest, crypto_key_version::CryptoKeyVersionAlgorithm,
    },
};
use mockall::predicate::*;

mockall::mock! {
    #[derive(Debug)]
    KeyManagementService {}

    impl google_cloud_kms_v1::stub::KeyManagementService for KeyManagementService {
        async fn asymmetric_sign(
            &self,
            req: AsymmetricSignRequest,
            options: google_cloud_gax::options::RequestOptions,
        ) -> google_cloud_gax::Result<google_cloud_gax::response::Response<AsymmetricSignResponse>>;

        async fn get_crypto_key_version(
            &self,
            req: GetCryptoKeyVersionRequest,
            options: google_cloud_gax::options::RequestOptions,
        ) -> google_cloud_gax::Result<google_cloud_gax::response::Response<CryptoKeyVersion>>;
    }
}

fn setup_get_crypto_key_expectation(
    mock: &mut MockKeyManagementService,
    resource_name: impl Into<String>,
    algorithm: CryptoKeyVersionAlgorithm,
) {
    let resource_name = resource_name.into();

    mock.expect_get_crypto_key_version()
        .withf(move |req, _| req.name == resource_name)
        .return_once({
            move |req, _| {
                let version_response = CryptoKeyVersion::new()
                    .set_name(req.name)
                    .set_algorithm(algorithm);
                Ok(Response::from(version_response))
            }
        });
}

fn setup_asymmetric_sign_expectation(
    mock: &mut MockKeyManagementService,
    resource_name: impl Into<String>,
    signed_bytes: Bytes,
) {
    let resource_name = resource_name.into();

    mock.expect_asymmetric_sign()
        .withf(move |req, _| req.name == resource_name)
        .return_once({
            move |req, _| {
                let sign_response = AsymmetricSignResponse::new()
                    .set_name(req.name)
                    .set_signature(signed_bytes);
                Ok(Response::from(sign_response))
            }
        });
}

#[tokio::test]
async fn test_asymmetric_sign_success() -> Result<(), Box<dyn std::error::Error>> {
    let resource_name =
        "projects/test/locations/us/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1";
    let expected_signed_bytes = Bytes::from_static(b"signed data");

    let mut mock = MockKeyManagementService::new();
    setup_get_crypto_key_expectation(
        &mut mock,
        resource_name,
        CryptoKeyVersionAlgorithm::RsaSignPkcs12048Sha256,
    );
    setup_asymmetric_sign_expectation(&mut mock, resource_name, expected_signed_bytes.clone());

    let client = KeyManagementService::from_stub(mock);
    let key = AsymmetricJwsKey::new(client, resource_name).await?;
    let signed_bytes = key.sign(b"data").await?;

    assert_eq!(signed_bytes, expected_signed_bytes);
    Ok(())
}

#[tokio::test]
async fn test_asymmetric_unsupported_algorithm_fails() -> Result<(), Box<dyn std::error::Error>> {
    let resource_name =
        "projects/test/locations/us/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1";

    let mut mock = MockKeyManagementService::new();
    setup_get_crypto_key_expectation(
        &mut mock,
        resource_name,
        CryptoKeyVersionAlgorithm::KemXwing,
    );

    let client = KeyManagementService::from_stub(mock);
    let key = AsymmetricJwsKey::new(client, resource_name).await;

    assert!(matches!(
        key,
        Err(SetupError::UnsupportedAlgorithm {
            algorithm: CryptoKeyVersionAlgorithm::KemXwing
        })
    ));

    Ok(())
}
