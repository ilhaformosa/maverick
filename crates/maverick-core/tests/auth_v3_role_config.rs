use std::error::Error as _;

use maverick_core::auth_v3::{
    encode_auth_v3_client_control, encode_auth_v3_server_confirmation,
    verify_auth_v3_client_control, verify_auth_v3_server_confirmation, AuthV3Carrier,
    AuthV3ClientControlInput, AuthV3ClientReceipt, AuthV3ServerConfirmationInput, AuthV3TlsVersion,
    AuthV3TrustedConnectionContext,
};
use maverick_core::config::v2::Policy;
use maverick_core::config::{ClientRoleConfig, DirectV3TransportStrategy, ServerRoleConfig};
use maverick_core::{ClientConfig, Error, ServerConfig};

const SECRET: &str = "mv1_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
const HANDLE_TEXT: &str = "EREREREREREREREREREREQ";
const PRINCIPAL_TEXT: &str = "IiIiIiIiIiIiIiIiIiIiIg";
const DEPLOYMENT_TEXT: &str = "MzMzMzMzMzMzMzMzMzMzMw";
const NAMESPACE_TEXT: &str = "RERERERERERERERERERERA";
const SERVER_ID_TEXT: &str = "VVVVVVVVVVVVVVVVVVVVVQ";
const ZERO_ID_TEXT: &str = "AAAAAAAAAAAAAAAAAAAAAA";
const DEPLOYMENT: [u8; 16] = [0x33; 16];
const SERVER_ID: [u8; 16] = [0x55; 16];
const EXPORTER: [u8; 32] = [0x66; 32];
const NOW: u64 = 1_800_000_000;
const NOT_AFTER: u64 = NOW + 172_800;
const CLIENT_ERROR: &str = "configuration error: invalid config v3 client role";
const SERVER_ERROR: &str = "configuration error: invalid config v3 server role";
const CLIENT_AUTHORITY: &str = "client-origin.invalid";
const SERVER_AUTHORITY: &str = "server-origin.invalid";

fn binding_yaml() -> String {
    format!(
        r#"      provisioning_handle: "{HANDLE_TEXT}"
      principal_id: "{PRINCIPAL_TEXT}"
      deployment_profile_id: "{DEPLOYMENT_TEXT}"
      credential_namespace_id: "{NAMESPACE_TEXT}"
      server_identity_id: "{SERVER_ID_TEXT}"
      credential_epoch: 7
      credential_not_after_unix: {NOT_AFTER}
      secret: "{SECRET}"
"#
    )
}

fn client_yaml(strategy: &str) -> String {
    format!(
        r#"version: 3
role: client
security:
  posture: standard
transport:
  strategy: {strategy}
trust:
  route: direct_to_maverick
name_privacy:
  minimum: plain_sni
traffic_shaping:
  policy: disabled
local:
  socks5:
    listen: "127.0.0.1:1080"
server:
  address: "client-origin.invalid:443"
  server_name: "client-origin.invalid"
  tunnel_path: "/synthetic-direct-v3-client"
  ca_cert: null
  cert_pin: null
auth:
  minimum: direct_v3_only
  direct_v3:
    binding:
{}"#,
        binding_yaml()
    )
}

fn server_yaml(strategy: &str) -> String {
    format!(
        r#"version: 3
role: server
security:
  posture: standard
transport:
  strategy: {strategy}
trust:
  route: direct_to_maverick
name_privacy:
  minimum: plain_sni
traffic_shaping:
  policy: disabled
listen: "127.0.0.1:8443"
tls:
  cert_path: "./synthetic-cert.pem"
  key_path: "./synthetic-key.pem"
maverick:
  tunnel_path: "/synthetic-direct-v3-server"
  expected_authority: "{SERVER_AUTHORITY}"
target_open:
  timeout_ms: 10000
  egress:
    allow_loopback: false
    allow_private: false
    allow_link_local: false
    allow_multicast: false
    allow_unspecified: false
auth:
  minimum: direct_v3_only
  direct_v3:
    binding:
{}"#,
        binding_yaml()
    )
}

fn legacy_client_yaml() -> String {
    format!(
        r#"version: 1
mode: auto
local:
  socks5:
    listen: "127.0.0.1:1080"
server:
  address: "legacy-client.invalid:443"
  server_name: "legacy-client.invalid"
  tunnel_path: "/legacy-client"
  credential_id: "legacy-client"
  secret: "{SECRET}"
"#
    )
}

fn legacy_server_yaml() -> String {
    format!(
        r#"version: 1
listen: "127.0.0.1:8443"
tls:
  cert_path: "./legacy-cert.pem"
  key_path: "./legacy-key.pem"
maverick:
  tunnel_path: "/legacy-server"
users:
  - id: "legacy-user"
    secret: "{SECRET}"
fallback:
  type: static
  static_dir: "./public"
"#
    )
}

fn assert_client_rejection(input: &str) {
    let error = ClientRoleConfig::from_yaml_str(input).unwrap_err();
    assert_eq!(error.to_string(), CLIENT_ERROR);
    assert!(error.source().is_none());
}

fn assert_server_rejection(input: &str) {
    let error = ServerRoleConfig::from_yaml_str(input).unwrap_err();
    assert_eq!(error.to_string(), SERVER_ERROR);
    assert!(error.source().is_none());
}

fn assert_valid_yaml_document(input: &str) {
    assert!(
        serde_yaml_ng::from_str::<serde_yaml_ng::Value>(input).is_ok(),
        "test fixture must remain one valid YAML document"
    );
}

fn assert_valid_client_rejection(input: &str) {
    assert_valid_yaml_document(input);
    assert_client_rejection(input);
}

fn assert_valid_server_rejection(input: &str) {
    assert_valid_yaml_document(input);
    assert_server_rejection(input);
}

fn replace_client_authority(input: &str, authority: &str) -> String {
    let authority = serde_yaml_ng::to_string(authority).unwrap();
    input.replace(
        &format!("  server_name: \"{CLIENT_AUTHORITY}\""),
        &format!("  server_name: {}", authority.trim_end()),
    )
}

fn replace_server_authority(input: &str, authority: &str) -> String {
    let authority = serde_yaml_ng::to_string(authority).unwrap();
    input.replace(
        &format!("  expected_authority: \"{SERVER_AUTHORITY}\""),
        &format!("  expected_authority: {}", authority.trim_end()),
    )
}

fn assert_client_fail_closed(input: &str) {
    let error = ClientRoleConfig::from_yaml_str(input).unwrap_err();
    let rendered = error.to_string();
    assert!(
        rendered == CLIENT_ERROR
            || rendered == "configuration error: invalid configuration version metadata",
        "unexpected fixed rejection: {rendered}"
    );
    assert!(error.source().is_none());
}

fn replace_required_line(input: &str, field: &str, replacement: Option<&str>) -> String {
    let prefix = format!("      {field}:");
    let mut output = String::new();
    for line in input.lines() {
        if line.starts_with(&prefix) {
            if let Some(value) = replacement {
                output.push_str(&prefix);
                output.push(' ');
                output.push_str(value);
                output.push('\n');
            }
        } else {
            output.push_str(line);
            output.push('\n');
        }
    }
    output
}

fn replace_yaml_block(
    input: &str,
    start_marker: &str,
    end_marker: Option<&str>,
    replacement: &str,
) -> String {
    let start = input
        .find(start_marker)
        .expect("fixture must contain block start");
    let end = end_marker.map_or(input.len(), |marker| {
        start
            + input[start..]
                .find(marker)
                .expect("fixture must contain block end")
    });
    format!("{}{}{}", &input[..start], replacement, &input[end..])
}

fn connection<'a>(carrier: AuthV3Carrier, path: &'a str) -> AuthV3TrustedConnectionContext<'a> {
    AuthV3TrustedConnectionContext::new(
        carrier,
        AuthV3TlsVersion::Tls13,
        true,
        false,
        &EXPORTER,
        true,
        Some(&[]),
        &DEPLOYMENT,
        &SERVER_ID,
        path,
    )
}

fn exercise_primitives(
    carrier: AuthV3Carrier,
    path: &str,
    preselected: maverick_core::auth_v3::AuthV3PreselectedProfile<'_>,
) {
    let connection = connection(carrier, path);
    let input = AuthV3ClientControlInput::new(carrier, NOW, [0x71; 32]);
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
            [0x72; 32],
            [0x73; 16],
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
        &AuthV3ClientReceipt::new(NOW, 65_536, 128),
    )
    .unwrap();
}

#[test]
fn config_v3_server_requires_trusted_expected_authority() {
    let input = server_yaml("h2").replace(
        &format!("  expected_authority: \"{SERVER_AUTHORITY}\"\n"),
        "",
    );
    assert_valid_server_rejection(&input);
}

#[test]
fn config_v3_server_accepts_explicit_target_open_policy() {
    let config = ServerRoleConfig::from_yaml_str(&server_yaml("h3")).unwrap();
    let role = config.direct_v3().unwrap();
    assert_eq!(role.target_open_timeout_ms(), 10_000);
    let egress = role.target_open_egress_policy();
    assert!(!egress.allow_loopback);
    assert!(!egress.allow_private);
    assert!(!egress.allow_link_local);
    assert!(!egress.allow_multicast);
    assert!(!egress.allow_unspecified);
}

#[test]
fn config_v3_server_requires_complete_strict_target_open_policy() {
    let base = server_yaml("h3");
    let mut cases = vec![
        replace_yaml_block(&base, "target_open:\n", Some("auth:\n"), ""),
        replace_yaml_block(
            &base,
            "target_open:\n",
            Some("auth:\n"),
            "target_open: null\n",
        ),
        base.replace("  timeout_ms: 10000\n", ""),
        base.replace("  timeout_ms: 10000", "  timeout_ms: null"),
        replace_yaml_block(&base, "  egress:\n", Some("auth:\n"), ""),
        replace_yaml_block(&base, "  egress:\n", Some("auth:\n"), "  egress: null\n"),
        base.replace(
            "  timeout_ms: 10000",
            "  timeout_ms: 10000\n  unknown_target_open: false",
        ),
        base.replace(
            "    allow_loopback: false",
            "    allow_loopback: false\n    unknown_egress: false",
        ),
        base.replace("  timeout_ms: 10000", "  timeout_ms: \"10000\""),
        base.replace("    allow_loopback: false", "    allow_loopback: 0"),
        base.replace("  timeout_ms: 10000", "  timeout_ms: 0"),
        base.replace("  timeout_ms: 10000", "  timeout_ms: 60001"),
    ];

    for field in [
        "allow_loopback",
        "allow_private",
        "allow_link_local",
        "allow_multicast",
        "allow_unspecified",
    ] {
        cases.push(base.replace(&format!("    {field}: false\n"), ""));
        cases.push(base.replace(
            &format!("    {field}: false"),
            &format!("    {field}: null"),
        ));
    }

    for input in cases {
        assert_valid_server_rejection(&input);
    }
}

#[test]
fn config_v3_server_rejects_duplicate_target_open_fields() {
    let base = server_yaml("h3");
    let duplicate_block = r#"target_open:
  timeout_ms: 10000
  egress:
    allow_loopback: false
    allow_private: false
    allow_link_local: false
    allow_multicast: false
    allow_unspecified: false
"#;
    let cases = [
        base.replace("auth:\n", &format!("{duplicate_block}auth:\n")),
        base.replace(
            "  timeout_ms: 10000",
            "  timeout_ms: 10000\n  timeout_ms: 10000",
        ),
        base.replace(
            "    allow_private: false",
            "    allow_private: false\n    allow_private: false",
        ),
    ];

    for input in cases {
        assert_server_rejection(&input);
    }
}

#[test]
fn config_v3_server_accepts_target_open_timeout_boundaries() {
    for timeout_ms in [1, 60_000] {
        let input = server_yaml("h2").replace(
            "  timeout_ms: 10000",
            &format!("  timeout_ms: {timeout_ms}"),
        );
        let config = ServerRoleConfig::from_yaml_str(&input).unwrap();
        assert_eq!(
            config.direct_v3().unwrap().target_open_timeout_ms(),
            timeout_ms
        );
    }
}

#[test]
fn config_v3_server_preserves_each_explicit_target_open_egress_bool() {
    let fields = [
        "allow_loopback",
        "allow_private",
        "allow_link_local",
        "allow_multicast",
        "allow_unspecified",
    ];

    for expected_true in fields {
        let input = server_yaml("h3").replace(
            &format!("    {expected_true}: false"),
            &format!("    {expected_true}: true"),
        );
        let config = ServerRoleConfig::from_yaml_str(&input).unwrap();
        let egress = config.direct_v3().unwrap().target_open_egress_policy();
        let actual = [
            ("allow_loopback", egress.allow_loopback),
            ("allow_private", egress.allow_private),
            ("allow_link_local", egress.allow_link_local),
            ("allow_multicast", egress.allow_multicast),
            ("allow_unspecified", egress.allow_unspecified),
        ];
        for (field, value) in actual {
            assert_eq!(value, field == expected_true, "wrong value for {field}");
        }
    }
}

#[test]
fn config_v3_client_rejects_server_only_target_open_policy() {
    let input = client_yaml("h3").replace(
        "auth:\n",
        r#"target_open:
  timeout_ms: 10000
  egress:
    allow_loopback: false
    allow_private: false
    allow_link_local: false
    allow_multicast: false
    allow_unspecified: false
auth:
"#,
    );
    assert_valid_client_rejection(&input);
}

#[test]
fn target_open_errors_and_role_debug_remain_fixed_and_value_free() {
    let marker = "SYNTHETIC_PRIVATE_TARGET_OPEN_MARKER_DO_NOT_ECHO";
    let input =
        server_yaml("h3").replace("  timeout_ms: 10000", &format!("  timeout_ms: {marker}"));
    let error = ServerRoleConfig::from_yaml_str(&input).unwrap_err();
    let display = error.to_string();
    let debug = format!("{error:?}");
    assert_eq!(display, SERVER_ERROR);
    assert!(error.source().is_none());
    assert!(!display.contains(marker));
    assert!(!debug.contains(marker));
    assert!(display.len() <= 128);
    assert!(debug.len() <= 160);

    let role = ServerRoleConfig::from_yaml_str(&server_yaml("h3")).unwrap();
    let debug = format!("{:?}", role.direct_v3().unwrap());
    for forbidden in ["10000", "allow_loopback", "false", SERVER_AUTHORITY] {
        assert!(!debug.contains(forbidden));
    }
}

#[test]
fn config_v3_client_rejects_server_name_with_port() {
    let input = replace_client_authority(&client_yaml("h2"), "client-origin.invalid:443");
    assert_valid_client_rejection(&input);
}

#[test]
fn expected_authority_preserves_legal_dns_hostname_bytes_for_both_roles() {
    let total_max = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    let legal = [
        "authority.invalid",
        "AUTHORITY.Example",
        "api-edge-1.invalid",
        "xn--bcher-kva.invalid",
        total_max.as_str(),
    ];

    for authority in legal {
        let client_input = replace_client_authority(&client_yaml("h2"), authority);
        let client = ClientRoleConfig::from_yaml_str(&client_input).unwrap();
        assert_eq!(client.direct_v3().unwrap().server_name(), authority);

        let server_input = replace_server_authority(&server_yaml("h3"), authority);
        let server = ServerRoleConfig::from_yaml_str(&server_input).unwrap();
        assert_eq!(server.direct_v3().unwrap().expected_authority(), authority);
    }
}

#[test]
fn expected_authority_shared_table_rejects_non_host_authorities_for_both_roles() {
    let label_too_long = format!("{}.invalid", "a".repeat(64));
    let total_too_long = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(62)
    );
    let invalid = [
        "".to_owned(),
        "authority.invalid:443".to_owned(),
        "user@authority.invalid".to_owned(),
        "authority.invalid/path".to_owned(),
        "authority.invalid?query".to_owned(),
        "authority.invalid#fragment".to_owned(),
        "authority%2einvalid".to_owned(),
        "authority\u{0001}.invalid".to_owned(),
        "authority invalid".to_owned(),
        "bad name".to_owned(),
        "authority\tinvalid".to_owned(),
        " authority.invalid".to_owned(),
        "authority.invalid ".to_owned(),
        "authority_invalid".to_owned(),
        "authorité.invalid".to_owned(),
        ".authority.invalid".to_owned(),
        "authority.invalid.".to_owned(),
        "authority..invalid".to_owned(),
        "-authority.invalid".to_owned(),
        "authority-.invalid".to_owned(),
        "192.0.2.1".to_owned(),
        "2001:db8::1".to_owned(),
        "[2001:db8::1]".to_owned(),
        label_too_long,
        total_too_long,
    ];

    for authority in invalid {
        let client_input = replace_client_authority(&client_yaml("h2"), &authority);
        assert_valid_client_rejection(&client_input);

        let server_input = replace_server_authority(&server_yaml("h3"), &authority);
        assert_valid_server_rejection(&server_input);
    }
}

#[test]
fn server_expected_authority_rejects_null_unknown_and_misplaced_fields() {
    let base = server_yaml("h2");
    let field = format!("  expected_authority: \"{SERVER_AUTHORITY}\"");
    let cases = [
        base.replace(&field, "  expected_authority: null"),
        base.replace(&field, &format!("{field}\n  authority_alias: invalid")),
        base.replace(
            &field,
            &format!("expected_authority: \"{SERVER_AUTHORITY}\""),
        ),
    ];
    for (index, input) in cases.into_iter().enumerate() {
        assert_valid_yaml_document(&input);
        assert!(
            ServerRoleConfig::from_yaml_str(&input).is_err(),
            "server authority mutation {index} must fail closed"
        );
        assert_server_rejection(&input);
    }
}

#[test]
fn neutral_client_h2_and_server_h3_project_to_preselected_primitives() {
    let client = ClientRoleConfig::from_yaml_str(&client_yaml("h2")).unwrap();
    assert_eq!(client.version(), 3);
    assert!(client.legacy_v1().is_none());
    let client = client.direct_v3().unwrap();
    assert_eq!(client.transport_strategy(), DirectV3TransportStrategy::H2);
    assert_eq!(client.local_socks5_listen().to_string(), "127.0.0.1:1080");
    assert_eq!(client.server_address(), "client-origin.invalid:443");
    assert_eq!(client.server_name(), "client-origin.invalid");
    assert_eq!(client.tunnel_path(), "/synthetic-direct-v3-client");
    assert!(client.ca_cert().is_none());
    assert!(client.cert_pin().is_none());
    exercise_primitives(
        client.transport_strategy().auth_v3_carrier(),
        client.tunnel_path(),
        client.preselected_profile(),
    );

    let server = ServerRoleConfig::from_yaml_str(&server_yaml("h3")).unwrap();
    assert_eq!(server.version(), 3);
    assert!(server.legacy_v1().is_none());
    let server = server.direct_v3().unwrap();
    assert_eq!(server.transport_strategy(), DirectV3TransportStrategy::H3);
    assert_eq!(server.listen().to_string(), "127.0.0.1:8443");
    assert_eq!(server.cert_path().to_str(), Some("./synthetic-cert.pem"));
    assert_eq!(server.key_path().to_str(), Some("./synthetic-key.pem"));
    assert_eq!(server.tunnel_path(), "/synthetic-direct-v3-server");
    assert_eq!(server.expected_authority(), SERVER_AUTHORITY);
    exercise_primitives(
        server.transport_strategy().auth_v3_carrier(),
        server.tunnel_path(),
        server.preselected_profile(),
    );
}

#[test]
fn same_nonzero_bytes_may_fill_handle_and_all_semantic_ids() {
    let mut input = client_yaml("h2");
    for value in [
        PRINCIPAL_TEXT,
        DEPLOYMENT_TEXT,
        NAMESPACE_TEXT,
        SERVER_ID_TEXT,
    ] {
        input = input.replace(value, HANDLE_TEXT);
    }
    let config = ClientRoleConfig::from_yaml_str(&input).unwrap();
    assert!(config.direct_v3().is_some());
}

#[test]
fn rejects_noncanonical_malformed_wrong_length_and_zero_opaque_values() {
    let fields = [
        ("provisioning_handle", HANDLE_TEXT),
        ("principal_id", PRINCIPAL_TEXT),
        ("deployment_profile_id", DEPLOYMENT_TEXT),
        ("credential_namespace_id", NAMESPACE_TEXT),
        ("server_identity_id", SERVER_ID_TEXT),
    ];
    for (field, original) in fields {
        for invalid in [
            ZERO_ID_TEXT,
            "short",
            "ERERERERERERERERERERE!",
            "EREREREREREREREREREREQ==",
            "ERERERERERERERERERERER",
            "ERERERERERERERERERERE ",
            "ERERERERERERERERERERé",
        ] {
            let input = client_yaml("h2").replace(
                &format!("      {field}: \"{original}\""),
                &format!("      {field}: \"{invalid}\""),
            );
            assert_client_rejection(&input);
        }
    }
}

#[test]
fn rejects_zero_epoch_zero_expiry_and_invalid_secret() {
    for input in [
        client_yaml("h2").replace("credential_epoch: 7", "credential_epoch: 0"),
        client_yaml("h2").replace(
            &format!("credential_not_after_unix: {NOT_AFTER}"),
            "credential_not_after_unix: 0",
        ),
        client_yaml("h2").replace(SECRET, "mv1_short"),
    ] {
        assert_client_rejection(&input);
    }
}

#[test]
fn rejects_unknown_keys_at_every_client_mapping_layer() {
    let base = client_yaml("h2");
    let cases = [
        base.replace("version: 3", "version: 3\nunknown_root: true"),
        base.replace(
            "  posture: standard",
            "  posture: standard\n  unknown: true",
        ),
        base.replace("  strategy: h2", "  strategy: h2\n  unknown: true"),
        base.replace(
            "  route: direct_to_maverick",
            "  route: direct_to_maverick\n  unknown: true",
        ),
        base.replace(
            "  minimum: plain_sni",
            "  minimum: plain_sni\n  unknown: true",
        ),
        base.replace("  policy: disabled", "  policy: disabled\n  unknown: true"),
        base.replace("local:\n", "local:\n  unknown: true\n"),
        base.replace(
            "    listen: \"127.0.0.1:1080\"",
            "    listen: \"127.0.0.1:1080\"\n    unknown: true",
        ),
        base.replace("  cert_pin: null", "  cert_pin: null\n  unknown: true"),
        base.replace(
            "  minimum: direct_v3_only",
            "  minimum: direct_v3_only\n  unknown: true",
        ),
        base.replace("  direct_v3:\n", "  direct_v3:\n    unknown: true\n"),
        base.replace(
            &format!("      secret: \"{SECRET}\""),
            &format!("      secret: \"{SECRET}\"\n      unknown: true"),
        ),
    ];
    for input in cases {
        assert_client_fail_closed(&input);
    }
}

#[test]
fn rejects_unknown_keys_at_every_server_specific_mapping_layer() {
    let base = server_yaml("h2");
    let cases = [
        base.replace(
            "  key_path: \"./synthetic-key.pem\"",
            "  key_path: \"./synthetic-key.pem\"\n  unknown: true",
        ),
        base.replace(
            &format!("  expected_authority: \"{SERVER_AUTHORITY}\""),
            &format!("  expected_authority: \"{SERVER_AUTHORITY}\"\n  unknown: true"),
        ),
    ];
    for input in cases {
        assert_server_rejection(&input);
    }
}

#[test]
fn rejects_duplicate_keys_at_root_policy_role_and_binding_layers() {
    let base = client_yaml("h2");
    let cases = [
        base.replace("version: 3", "version: 3\nversion: 3"),
        base.replace("role: client", "role: client\nrole: client"),
        base.replace(
            "security:\n  posture: standard",
            "security:\n  posture: standard\nsecurity:\n  posture: standard",
        ),
        base.replace(
            "  posture: standard",
            "  posture: standard\n  posture: standard",
        ),
        base.replace("  strategy: h2", "  strategy: h2\n  strategy: h3"),
        base.replace(
            "  route: direct_to_maverick",
            "  route: direct_to_maverick\n  route: direct_to_maverick",
        ),
        base.replace(
            "  minimum: plain_sni",
            "  minimum: plain_sni\n  minimum: plain_sni",
        ),
        base.replace(
            "  policy: disabled",
            "  policy: disabled\n  policy: disabled",
        ),
        base.replace(
            "    listen: \"127.0.0.1:1080\"",
            "    listen: \"127.0.0.1:1080\"\n    listen: \"127.0.0.1:1081\"",
        ),
        base.replace(
            "  minimum: direct_v3_only",
            "  minimum: direct_v3_only\n  minimum: direct_v3_only",
        ),
        base.replace(
            &format!("      principal_id: \"{PRINCIPAL_TEXT}\""),
            &format!(
                "      principal_id: \"{PRINCIPAL_TEXT}\"\n      principal_id: \"{PRINCIPAL_TEXT}\""
            ),
        ),
    ];
    for input in cases {
        assert_client_fail_closed(&input);
    }
}

#[test]
fn rejects_null_and_missing_required_role_policy_and_auth_fields() {
    let base = client_yaml("h2");
    assert_valid_yaml_document(&base);
    assert!(ClientRoleConfig::from_yaml_str(&base).is_ok());

    let null_cases = [
        base.replacen("role: client\n", "role: null\n", 1),
        base.replace("security:\n  posture: standard", "security: null"),
        base.replace("posture: standard", "posture: null"),
        base.replace("transport:\n  strategy: h2", "transport: null"),
        base.replace("strategy: h2", "strategy: null"),
        base.replace("trust:\n  route: direct_to_maverick", "trust: null"),
        base.replace("route: direct_to_maverick", "route: null"),
        base.replace("name_privacy:\n  minimum: plain_sni", "name_privacy: null"),
        base.replace("minimum: plain_sni", "minimum: null"),
        base.replace(
            "traffic_shaping:\n  policy: disabled",
            "traffic_shaping: null",
        ),
        base.replace("policy: disabled", "policy: null"),
        replace_yaml_block(&base, "auth:\n", None, "auth: null\n"),
        replace_yaml_block(&base, "  direct_v3:\n", None, "  direct_v3: null\n"),
        replace_yaml_block(&base, "    binding:\n", None, "    binding: null\n"),
        base.replace(
            &format!("      principal_id: \"{PRINCIPAL_TEXT}\""),
            "      principal_id: null",
        ),
        base.replace("credential_epoch: 7", "credential_epoch: null"),
        base.replace(&format!("secret: \"{SECRET}\""), "secret: null"),
    ];
    for input in null_cases {
        assert_valid_client_rejection(&input);
    }

    let missing_cases = [
        base.replacen("role: client\n", "", 1),
        base.replace("security:\n  posture: standard\n", ""),
        base.replace("security:\n  posture: standard\n", "security: {}\n"),
        base.replace("transport:\n  strategy: h2\n", ""),
        base.replace("transport:\n  strategy: h2\n", "transport: {}\n"),
        base.replace("trust:\n  route: direct_to_maverick\n", ""),
        base.replace("trust:\n  route: direct_to_maverick\n", "trust: {}\n"),
        base.replace("name_privacy:\n  minimum: plain_sni\n", ""),
        base.replace(
            "name_privacy:\n  minimum: plain_sni\n",
            "name_privacy: {}\n",
        ),
        base.replace("traffic_shaping:\n  policy: disabled\n", ""),
        base.replace(
            "traffic_shaping:\n  policy: disabled\n",
            "traffic_shaping: {}\n",
        ),
        replace_yaml_block(&base, "auth:\n", None, ""),
        base.replace("  minimum: direct_v3_only\n", ""),
        replace_yaml_block(&base, "  direct_v3:\n", None, ""),
        replace_yaml_block(&base, "  direct_v3:\n", None, "  direct_v3: {}\n"),
        base.replace(
            &format!("      provisioning_handle: \"{HANDLE_TEXT}\"\n"),
            "",
        ),
        base.replace(&format!("      secret: \"{SECRET}\"\n"), ""),
    ];
    for input in missing_cases {
        assert_valid_client_rejection(&input);
    }
}

#[test]
fn rejects_null_or_missing_role_and_binding_fields() {
    let client = client_yaml("h2");
    assert_valid_yaml_document(&client);
    assert!(ClientRoleConfig::from_yaml_str(&client).is_ok());
    let client_cases = [
        replace_yaml_block(&client, "local:\n", Some("server:\n"), "local: null\n"),
        replace_yaml_block(
            &client,
            "  socks5:\n",
            Some("server:\n"),
            "  socks5: null\n",
        ),
        client.replace("    listen: \"127.0.0.1:1080\"", "    listen: null"),
        replace_yaml_block(&client, "server:\n", Some("auth:\n"), "server: null\n"),
        client.replace("  address: \"client-origin.invalid:443\"\n", ""),
        client.replace("  server_name: \"client-origin.invalid\"\n", ""),
        client.replace("  tunnel_path: \"/synthetic-direct-v3-client\"\n", ""),
    ];
    for input in client_cases {
        assert_valid_client_rejection(&input);
    }

    for field in [
        "provisioning_handle",
        "principal_id",
        "deployment_profile_id",
        "credential_namespace_id",
        "server_identity_id",
        "credential_epoch",
        "credential_not_after_unix",
        "secret",
    ] {
        assert_valid_client_rejection(&replace_required_line(&client, field, None));
        assert_valid_client_rejection(&replace_required_line(&client, field, Some("null")));
    }

    let server = server_yaml("h2");
    assert_valid_yaml_document(&server);
    assert!(ServerRoleConfig::from_yaml_str(&server).is_ok());
    let server_cases = [
        server.replace("listen: \"127.0.0.1:8443\"", "listen: null"),
        replace_yaml_block(&server, "tls:\n", Some("maverick:\n"), "tls: null\n"),
        server.replace("  cert_path: \"./synthetic-cert.pem\"\n", ""),
        server.replace("  key_path: \"./synthetic-key.pem\"\n", ""),
        replace_yaml_block(&server, "maverick:\n", Some("auth:\n"), "maverick: null\n"),
        server.replace("  tunnel_path: \"/synthetic-direct-v3-server\"\n", ""),
        server.replace(
            &format!("  expected_authority: \"{SERVER_AUTHORITY}\"\n"),
            "",
        ),
        server.replace(
            &format!("  expected_authority: \"{SERVER_AUTHORITY}\""),
            "  expected_authority: null",
        ),
    ];
    for (index, input) in server_cases.into_iter().enumerate() {
        assert_valid_yaml_document(&input);
        assert!(
            ServerRoleConfig::from_yaml_str(&input).is_err(),
            "server required-field mutation {index} must fail closed"
        );
        assert_server_rejection(&input);
    }
}

#[test]
fn rejects_multidocument_wrong_role_and_bad_version_metadata() {
    let client = client_yaml("h2");
    let multi_error =
        ClientRoleConfig::from_yaml_str(&format!("{client}---\n{client}")).unwrap_err();
    assert_eq!(
        multi_error.to_string(),
        "configuration error: invalid configuration version metadata"
    );
    assert_server_rejection(&client);
    assert_client_rejection(&server_yaml("h2"));

    for input in [
        client.replacen("version: 3\n", "", 1),
        client.replace("version: 3", "version: null"),
        client.replace("version: 3", "version: \"3\""),
        client.replace("role: client", "role: future"),
    ] {
        let error = ClientRoleConfig::from_yaml_str(&input).unwrap_err();
        assert!(error.source().is_none());
        assert!(error.to_string().len() <= 128);
    }
}

#[test]
fn rejects_auto_fronting_and_all_legacy_or_mixed_auth_shapes() {
    let base = client_yaml("h2");
    let cases = [
        base.replace("strategy: h2", "strategy: auto"),
        base.replace("route: direct_to_maverick", "route: tls_terminating_front"),
        base.replace("version: 3", "version: 3\nmode: auto"),
        base.replace("version: 3", "version: 3\nusers: []"),
        base.replace("version: 3", "version: 3\nadvanced:\n  fronting: true"),
        base.replace("  direct_v3:", "  v2:\n    enabled: true\n  direct_v3:"),
        base.replace(
            "  direct_v3:",
            "  rotation:\n    active_epoch: 7\n  direct_v3:",
        ),
        base.replace(
            "  direct_v3:",
            "  channel_binding:\n    enabled: true\n  direct_v3:",
        ),
        base.replace(
            "  ca_cert: null",
            "  credential_id: legacy\n  ca_cert: null",
        ),
        base.replace(
            "  ca_cert: null",
            &format!("  secret: \"{SECRET}\"\n  ca_cert: null"),
        ),
        base.replace(
            "  direct_v3:\n    binding:",
            "  direct_v3:\n    bindings: []\n    binding:",
        ),
    ];
    for input in cases {
        assert_client_rejection(&input);
    }
}

#[test]
fn errors_and_debug_are_fixed_bounded_private_and_control_free() {
    let private_marker = "SYNTHETIC_PRIVATE_CONFIG_MARKER_DO_NOT_ECHO";
    let private_value = "SYNTHETIC_PRIVATE_VALUE_DO_NOT_ECHO";
    let long_suffix = "L".repeat(8_192);
    let input = client_yaml("h2").replace(
        "  posture: standard",
        &format!(
            "  posture: standard\n  \"{private_marker}\\n\\u001b{long_suffix}\": \"{private_value}\""
        ),
    );
    let error = ClientRoleConfig::from_yaml_str(&input).unwrap_err();
    let display = error.to_string();
    let debug = format!("{error:?}");
    assert!(error.source().is_none());
    for forbidden in [private_marker, private_value, long_suffix.as_str(), SECRET] {
        assert!(!display.contains(forbidden));
        assert!(!debug.contains(forbidden));
    }
    assert!(display.len() <= 128);
    assert!(debug.len() <= 160);
    assert!(display
        .chars()
        .chain(debug.chars())
        .all(|character| !character.is_control()));

    let client = ClientRoleConfig::from_yaml_str(&client_yaml("h2")).unwrap();
    let direct_debug = format!("{:?}", client.direct_v3().unwrap());
    let role_debug = format!("{client:?}");
    for output in [direct_debug, role_debug] {
        assert!(output.len() <= 64);
        for forbidden in [SECRET, HANDLE_TEXT, PRINCIPAL_TEXT, "client-origin"] {
            assert!(!output.contains(forbidden));
        }
    }

    let server = ServerRoleConfig::from_yaml_str(&server_yaml("h3")).unwrap();
    let direct_debug = format!("{:?}", server.direct_v3().unwrap());
    let role_debug = format!("{server:?}");
    for output in [direct_debug, role_debug] {
        assert!(output.len() <= 64);
        for forbidden in [SECRET, HANDLE_TEXT, PRINCIPAL_TEXT, SERVER_AUTHORITY] {
            assert!(!output.contains(forbidden));
        }
    }
}

#[test]
fn expected_authority_errors_are_fixed_bounded_and_source_free() {
    let marker = "private-authority-marker.invalid";
    let client_input = replace_client_authority(&client_yaml("h2"), marker);
    let client_input = client_input.replace(marker, &format!("{marker}:443"));
    let server_input = replace_server_authority(&server_yaml("h3"), marker);
    let server_input = server_input.replace(marker, &format!("{marker}:443"));

    for (input, expected, is_client) in [
        (client_input, CLIENT_ERROR, true),
        (server_input, SERVER_ERROR, false),
    ] {
        let error = if is_client {
            ClientRoleConfig::from_yaml_str(&input).unwrap_err()
        } else {
            ServerRoleConfig::from_yaml_str(&input).unwrap_err()
        };
        let display = error.to_string();
        let debug = format!("{error:?}");
        assert_eq!(display, expected);
        assert!(error.source().is_none());
        assert!(display.len() <= 128);
        assert!(debug.len() <= 160);
        assert!(!display.contains(marker));
        assert!(!debug.contains(marker));
    }
}

#[test]
fn legacy_v1_readers_and_new_role_readers_preserve_v1() {
    let client_input = legacy_client_yaml();
    let canonical_client = ClientConfig::from_yaml_str(&client_input).unwrap();
    let role_client = ClientRoleConfig::from_yaml_str(&client_input).unwrap();
    assert_eq!(role_client.version(), 1);
    assert!(role_client.direct_v3().is_none());
    let role_client = role_client.legacy_v1().unwrap();
    assert_eq!(role_client.version, canonical_client.version);
    assert_eq!(role_client.mode, canonical_client.mode);
    assert_eq!(
        role_client.local.socks5.listen,
        canonical_client.local.socks5.listen
    );
    assert_eq!(role_client.server.address, canonical_client.server.address);
    assert_eq!(role_client.server.secret, canonical_client.server.secret);

    let server_input = legacy_server_yaml();
    let canonical_server = ServerConfig::from_yaml_str(&server_input).unwrap();
    let role_server = ServerRoleConfig::from_yaml_str(&server_input).unwrap();
    assert_eq!(role_server.version(), 1);
    assert!(role_server.direct_v3().is_none());
    let role_server = role_server.legacy_v1().unwrap();
    assert_eq!(role_server.version, canonical_server.version);
    assert_eq!(role_server.listen, canonical_server.listen);
    assert_eq!(
        role_server.maverick.tunnel_path,
        canonical_server.maverick.tunnel_path
    );
    assert_eq!(
        role_server.users[0].secret,
        canonical_server.users[0].secret
    );
}

#[test]
fn old_canonical_and_direct_generic_v1_types_reject_complete_v3_documents() {
    let client = client_yaml("h2");
    let server = server_yaml("h3");
    assert_eq!(
        ClientConfig::from_yaml_str(&client)
            .unwrap_err()
            .to_string(),
        "configuration error: unsupported configuration version"
    );
    assert_eq!(
        ServerConfig::from_yaml_str(&server)
            .unwrap_err()
            .to_string(),
        "configuration error: unsupported configuration version"
    );
    assert!(serde_yaml_ng::from_str::<ClientConfig>(&client).is_err());
    assert!(serde_yaml_ng::from_str::<ServerConfig>(&server).is_err());
}

#[test]
fn version_domains_and_policy_only_v2_remain_independent() {
    let policy = r#"version: 2
security:
  posture: standard
transport:
  strategy: h2
trust:
  route: direct_to_maverick
name_privacy:
  minimum: plain_sni
traffic_shaping:
  policy: disabled
"#;
    assert_eq!(
        ClientRoleConfig::from_yaml_str(policy)
            .unwrap_err()
            .to_string(),
        "configuration error: config version 2 is policy-only"
    );
    assert_eq!(
        ServerRoleConfig::from_yaml_str(policy)
            .unwrap_err()
            .to_string(),
        "configuration error: config version 2 is policy-only"
    );
    assert_eq!(
        Policy::from_yaml_str(&client_yaml("h2"))
            .unwrap_err()
            .to_string(),
        "configuration error: unsupported config v2 policy version"
    );

    for version in ["0", "4", "65536"] {
        let input = client_yaml("h2").replace("version: 3", &format!("version: {version}"));
        assert_eq!(
            ClientRoleConfig::from_yaml_str(&input)
                .unwrap_err()
                .to_string(),
            "configuration error: unsupported client role configuration version"
        );
    }
}

#[test]
fn credential_error_type_remains_fixed_and_source_free() {
    let input = client_yaml("h2").replace(SECRET, "private-invalid-secret-marker");
    let error = ClientRoleConfig::from_yaml_str(&input).unwrap_err();
    assert!(matches!(error, Error::Config(_)));
    assert_eq!(error.to_string(), CLIENT_ERROR);
    assert!(error.source().is_none());
    assert!(!format!("{error:?}").contains("private-invalid-secret-marker"));
}
