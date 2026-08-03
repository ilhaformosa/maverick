use std::error::Error as _;
use std::mem::size_of;

use maverick_core::auth_v3::{
    encode_auth_v3_client_control, encode_auth_v3_server_confirmation,
    validate_auth_v3_singleton_bindings, verify_auth_v3_client_control,
    verify_auth_v3_server_confirmation, AuthV3Carrier, AuthV3ClientControlInput,
    AuthV3ClientReceipt, AuthV3Error, AuthV3OwnedProvisioningProfile, AuthV3ProvisioningHandle,
    AuthV3ServerConfirmationInput, AuthV3SingletonBinding, AuthV3TlsVersion,
    AuthV3TrustedConnectionContext,
};
use maverick_core::SecretString;

const SECRET_A: &str = "mv1_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
const SECRET_B: &str = "mv1_AQECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
const CONTROL_PATH_A: &str = "/synthetic-direct-control-a";
const CONTROL_PATH_B: &str = "/synthetic-direct-control-b";
const NOW: u64 = 1_800_000_000;
const NOT_AFTER: u64 = NOW + 172_800;
const EXPORTER: [u8; 32] = [0x60; 32];
const PRINCIPAL_A: [u8; 16] = [0x11; 16];
const DEPLOYMENT_A: [u8; 16] = [0x22; 16];
const NAMESPACE_A: [u8; 16] = [0x33; 16];
const SERVER_A: [u8; 16] = [0x44; 16];
const PRINCIPAL_B: [u8; 16] = [0x51; 16];
const DEPLOYMENT_B: [u8; 16] = [0x52; 16];
const NAMESPACE_B: [u8; 16] = [0x53; 16];
const SERVER_B: [u8; 16] = [0x54; 16];

#[allow(clippy::too_many_arguments)]
fn owned_profile(
    principal_id: [u8; 16],
    deployment_profile_id: [u8; 16],
    credential_namespace_id: [u8; 16],
    expected_server_identity_id: [u8; 16],
    expected_direct_route: bool,
    expected_control_path: &str,
    credential_epoch: u64,
    credential_not_after_unix: u64,
    secret: SecretString,
) -> Result<AuthV3OwnedProvisioningProfile, AuthV3Error> {
    AuthV3OwnedProvisioningProfile::new(
        principal_id,
        deployment_profile_id,
        credential_namespace_id,
        expected_server_identity_id,
        expected_direct_route,
        expected_control_path.to_owned(),
        credential_epoch,
        credential_not_after_unix,
        secret,
    )
}

fn valid_profile_a() -> AuthV3OwnedProvisioningProfile {
    owned_profile(
        PRINCIPAL_A,
        DEPLOYMENT_A,
        NAMESPACE_A,
        SERVER_A,
        true,
        CONTROL_PATH_A,
        7,
        NOT_AFTER,
        SecretString::new(SECRET_A).unwrap(),
    )
    .unwrap()
}

fn valid_profile_b() -> AuthV3OwnedProvisioningProfile {
    owned_profile(
        PRINCIPAL_B,
        DEPLOYMENT_B,
        NAMESPACE_B,
        SERVER_B,
        true,
        CONTROL_PATH_B,
        7,
        NOT_AFTER,
        SecretString::new(SECRET_B).unwrap(),
    )
    .unwrap()
}

fn binding(handle_byte: u8, profile: AuthV3OwnedProvisioningProfile) -> AuthV3SingletonBinding {
    AuthV3SingletonBinding::new(
        AuthV3ProvisioningHandle::new([handle_byte; 16]).unwrap(),
        vec![profile],
    )
    .unwrap()
}

fn connection<'a>(
    deployment_profile_id: &'a [u8; 16],
    server_identity_id: &'a [u8; 16],
    control_path: &'a str,
) -> AuthV3TrustedConnectionContext<'a> {
    AuthV3TrustedConnectionContext::new(
        AuthV3Carrier::H2,
        AuthV3TlsVersion::Tls13,
        true,
        false,
        &EXPORTER,
        true,
        Some(&[]),
        deployment_profile_id,
        server_identity_id,
        control_path,
    )
}

#[test]
fn handle_and_singleton_cardinality_fail_closed() {
    assert_eq!(size_of::<AuthV3ProvisioningHandle>(), 16);
    assert!(matches!(
        AuthV3ProvisioningHandle::new([0; 16]),
        Err(AuthV3Error::ProvisioningHandle)
    ));

    let empty = AuthV3SingletonBinding::new(
        AuthV3ProvisioningHandle::new([0x61; 16]).unwrap(),
        Vec::new(),
    );
    assert!(matches!(empty, Err(AuthV3Error::ProvisioningCardinality)));

    let multiple = AuthV3SingletonBinding::new(
        AuthV3ProvisioningHandle::new([0x62; 16]).unwrap(),
        vec![valid_profile_a(), valid_profile_b()],
    );
    assert!(matches!(
        multiple,
        Err(AuthV3Error::ProvisioningCardinality)
    ));
}

#[test]
fn owned_profile_reuses_existing_trusted_profile_validation() {
    let valid_secret = || SecretString::new(SECRET_A).unwrap();
    let cases = [
        owned_profile(
            [0; 16],
            DEPLOYMENT_A,
            NAMESPACE_A,
            SERVER_A,
            true,
            CONTROL_PATH_A,
            7,
            NOT_AFTER,
            valid_secret(),
        ),
        owned_profile(
            PRINCIPAL_A,
            [0; 16],
            NAMESPACE_A,
            SERVER_A,
            true,
            CONTROL_PATH_A,
            7,
            NOT_AFTER,
            valid_secret(),
        ),
        owned_profile(
            PRINCIPAL_A,
            DEPLOYMENT_A,
            [0; 16],
            SERVER_A,
            true,
            CONTROL_PATH_A,
            7,
            NOT_AFTER,
            valid_secret(),
        ),
        owned_profile(
            PRINCIPAL_A,
            DEPLOYMENT_A,
            NAMESPACE_A,
            [0; 16],
            true,
            CONTROL_PATH_A,
            7,
            NOT_AFTER,
            valid_secret(),
        ),
        owned_profile(
            PRINCIPAL_A,
            DEPLOYMENT_A,
            NAMESPACE_A,
            SERVER_A,
            true,
            CONTROL_PATH_A,
            0,
            NOT_AFTER,
            valid_secret(),
        ),
        owned_profile(
            PRINCIPAL_A,
            DEPLOYMENT_A,
            NAMESPACE_A,
            SERVER_A,
            true,
            CONTROL_PATH_A,
            7,
            0,
            valid_secret(),
        ),
        owned_profile(
            PRINCIPAL_A,
            DEPLOYMENT_A,
            NAMESPACE_A,
            SERVER_A,
            true,
            "",
            7,
            NOT_AFTER,
            valid_secret(),
        ),
    ];
    assert!(cases
        .into_iter()
        .all(|result| matches!(result, Err(AuthV3Error::Credential))));

    assert!(matches!(
        owned_profile(
            PRINCIPAL_A,
            DEPLOYMENT_A,
            NAMESPACE_A,
            SERVER_A,
            false,
            CONTROL_PATH_A,
            7,
            NOT_AFTER,
            valid_secret(),
        ),
        Err(AuthV3Error::Context)
    ));

    let invalid_secret: SecretString =
        serde_json::from_str("\"synthetic-invalid-secret\"").unwrap();
    assert!(matches!(
        owned_profile(
            PRINCIPAL_A,
            DEPLOYMENT_A,
            NAMESPACE_A,
            SERVER_A,
            true,
            CONTROL_PATH_A,
            7,
            NOT_AFTER,
            invalid_secret,
        ),
        Err(AuthV3Error::Credential)
    ));
}

#[test]
fn valid_singleton_preselection_drives_production_encode_and_verify() {
    let binding = binding(0x71, valid_profile_a());
    let preselected = binding.preselected_profile();
    let connection = connection(&DEPLOYMENT_A, &SERVER_A, CONTROL_PATH_A);
    let input = AuthV3ClientControlInput::new(AuthV3Carrier::H2, NOW, [0x41; 32]);
    let profile = preselected.trusted_profile();
    let control = encode_auth_v3_client_control(&profile, &connection, &input).unwrap();
    let verified = verify_auth_v3_client_control(&control, &profile, &connection, NOW).unwrap();

    let confirmation = encode_auth_v3_server_confirmation(
        verified,
        &connection,
        &AuthV3ServerConfirmationInput::new(
            NOW,
            NOW + 1_800,
            NOW + 86_400,
            [0x42; 32],
            [0x43; 16],
            65_536,
            128,
        ),
    )
    .unwrap();
    verify_auth_v3_server_confirmation(
        &confirmation,
        &control,
        &preselected.trusted_profile(),
        &connection,
        &AuthV3ClientReceipt::new(NOW, 131_072, 256),
    )
    .unwrap();
}

#[test]
fn verified_client_control_exposes_exact_credential_expiry_before_confirmation() {
    let expiries = [NOW + 100_000, NOW + 200_000];
    let expiry_markers = expiries.map(|expiry| expiry.to_string());
    let mut confirmations = [None, None];

    for (index, credential_not_after_unix) in expiries.into_iter().enumerate() {
        let profile = owned_profile(
            PRINCIPAL_A,
            DEPLOYMENT_A,
            NAMESPACE_A,
            SERVER_A,
            true,
            CONTROL_PATH_A,
            7,
            credential_not_after_unix,
            SecretString::new(SECRET_A).unwrap(),
        )
        .unwrap();
        let binding = binding(0x74 + index as u8, profile);
        let preselected = binding.preselected_profile();
        let connection = connection(&DEPLOYMENT_A, &SERVER_A, CONTROL_PATH_A);
        let input = AuthV3ClientControlInput::new(AuthV3Carrier::H2, NOW, [0x46; 32]);
        let profile = preselected.trusted_profile();
        let control = encode_auth_v3_client_control(&profile, &connection, &input).unwrap();
        let verified = verify_auth_v3_client_control(&control, &profile, &connection, NOW).unwrap();

        assert_eq!(
            verified.credential_not_after_unix(),
            credential_not_after_unix
        );
        let verified_debug = format!("{verified:?}");
        assert_eq!(verified_debug, "verified auth-v3 client control metadata");
        assert!(expiry_markers
            .iter()
            .all(|marker| !verified_debug.contains(marker)));
        confirmations[index] = Some(
            encode_auth_v3_server_confirmation(
                verified,
                &connection,
                &AuthV3ServerConfirmationInput::new(
                    NOW,
                    NOW + 1_800,
                    NOW + 86_400,
                    [0x47; 32],
                    [0x48; 16],
                    65_536,
                    128,
                ),
            )
            .unwrap(),
        );
    }

    assert_eq!(confirmations[0], confirmations[1]);
}

#[test]
fn preselected_a_rejects_b_and_changed_wire_claims_without_switching() {
    let binding_a = binding(0x72, valid_profile_a());
    let selected_a = binding_a.preselected_profile();
    let connection_a = connection(&DEPLOYMENT_A, &SERVER_A, CONTROL_PATH_A);
    let input = AuthV3ClientControlInput::new(AuthV3Carrier::H2, NOW, [0x45; 32]);

    let binding_b = binding(0x73, valid_profile_b());
    let selected_b = binding_b.preselected_profile();
    let connection_b = connection(&DEPLOYMENT_B, &SERVER_B, CONTROL_PATH_B);
    let signed_by_b =
        encode_auth_v3_client_control(&selected_b.trusted_profile(), &connection_b, &input)
            .unwrap();
    assert_eq!(
        verify_auth_v3_client_control(
            &signed_by_b,
            &selected_a.trusted_profile(),
            &connection_a,
            NOW,
        )
        .unwrap_err(),
        AuthV3Error::Identity
    );

    let encoded_a =
        encode_auth_v3_client_control(&selected_a.trusted_profile(), &connection_a, &input)
            .unwrap();
    let mut changed_commitment = encoded_a;
    changed_commitment[48] ^= 1;
    assert_eq!(
        verify_auth_v3_client_control(
            &changed_commitment,
            &selected_a.trusted_profile(),
            &connection_a,
            NOW,
        )
        .unwrap_err(),
        AuthV3Error::Identity
    );

    let mut changed_epoch = encoded_a;
    changed_epoch[39] = 8;
    assert_eq!(
        verify_auth_v3_client_control(
            &changed_epoch,
            &selected_a.trusted_profile(),
            &connection_a,
            NOW,
        )
        .unwrap_err(),
        AuthV3Error::Epoch
    );
}

#[test]
fn independent_singletons_share_only_a_startup_consistency_gate() {
    let duplicate_handle_a = binding(0x81, valid_profile_a());
    let duplicate_handle_b = binding(0x81, valid_profile_b());
    assert_eq!(
        validate_auth_v3_singleton_bindings(&[duplicate_handle_a, duplicate_handle_b]),
        Err(AuthV3Error::ProvisioningHandle)
    );

    let duplicate_tuple_a = binding(0x82, valid_profile_a());
    let duplicate_tuple_b = binding(
        0x83,
        owned_profile(
            PRINCIPAL_A,
            DEPLOYMENT_A,
            NAMESPACE_A,
            SERVER_A,
            true,
            CONTROL_PATH_A,
            7,
            NOT_AFTER,
            SecretString::new(SECRET_B).unwrap(),
        )
        .unwrap(),
    );
    assert_eq!(
        validate_auth_v3_singleton_bindings(&[duplicate_tuple_a, duplicate_tuple_b]),
        Err(AuthV3Error::Credential)
    );

    let reused_psk_a = binding(0x84, valid_profile_a());
    let reused_psk_b = binding(
        0x85,
        owned_profile(
            PRINCIPAL_B,
            DEPLOYMENT_B,
            NAMESPACE_B,
            SERVER_B,
            true,
            CONTROL_PATH_B,
            7,
            NOT_AFTER,
            SecretString::new(SECRET_A).unwrap(),
        )
        .unwrap(),
    );
    assert_eq!(
        validate_auth_v3_singleton_bindings(&[reused_psk_a, reused_psk_b]),
        Err(AuthV3Error::Credential)
    );

    let mapping_a = binding(0x86, valid_profile_a());
    let mapping_conflict = binding(
        0x87,
        owned_profile(
            PRINCIPAL_B,
            DEPLOYMENT_A,
            NAMESPACE_B,
            SERVER_B,
            true,
            CONTROL_PATH_B,
            8,
            NOT_AFTER,
            SecretString::new(SECRET_B).unwrap(),
        )
        .unwrap(),
    );
    assert_eq!(
        validate_auth_v3_singleton_bindings(&[mapping_a, mapping_conflict]),
        Err(AuthV3Error::Context)
    );
}

#[test]
fn debug_and_errors_are_fixed_bounded_and_value_free() {
    let handle = AuthV3ProvisioningHandle::new([0x7a; 16]).unwrap();
    let profile = owned_profile(
        [0x7b; 16],
        [0x7c; 16],
        [0x7d; 16],
        [0x7e; 16],
        true,
        "/synthetic-sensitive-path-marker",
        9,
        NOT_AFTER,
        SecretString::new(SECRET_A).unwrap(),
    )
    .unwrap();
    let handle_debug = format!("{handle:?}");
    let profile_debug = format!("{profile:?}");
    let binding = AuthV3SingletonBinding::new(handle, vec![profile]).unwrap();
    let binding_debug = format!("{binding:?}");
    let token_debug = format!("{:?}", binding.preselected_profile());
    let error = AuthV3ProvisioningHandle::new([0; 16]).unwrap_err();
    let error_debug = format!("{error:?}");
    let error_display = error.to_string();

    for output in [
        handle_debug,
        profile_debug,
        binding_debug,
        token_debug,
        error_debug,
        error_display,
    ] {
        assert!(output.len() <= 64);
        assert!(!output.contains("synthetic"));
        assert!(!output.contains(SECRET_A));
        assert!(!output.contains("122"));
        assert!(!output.contains("123"));
        assert!(!output.contains("124"));
        assert!(!output.contains("125"));
        assert!(!output.contains("126"));
    }
    assert!(error.source().is_none());
}
