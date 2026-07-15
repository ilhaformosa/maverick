use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::frame::TargetAddr;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunRoute {
    pub network: IpAddr,
    pub prefix_len: u8,
}

impl TunRoute {
    pub fn new(network: IpAddr, prefix_len: u8) -> Self {
        Self {
            network,
            prefix_len,
        }
    }

    fn validate(&self, field: &str) -> Result<()> {
        let max_prefix = match self.network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if self.prefix_len > max_prefix {
            return Err(Error::Config(format!(
                "{field}.prefix_len must be no greater than {max_prefix}"
            )));
        }
        Ok(())
    }

    fn display_cidr(&self) -> String {
        format!("{}/{}", self.network, self.prefix_len)
    }

    fn is_default_route(&self) -> bool {
        match self.network {
            IpAddr::V4(addr) => addr == Ipv4Addr::UNSPECIFIED && self.prefix_len == 0,
            IpAddr::V6(addr) => addr == Ipv6Addr::UNSPECIFIED && self.prefix_len == 0,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunRoutePlan {
    pub enabled: bool,
    pub device_name: String,
    pub include_routes: Vec<TunRoute>,
    pub exclude_routes: Vec<TunRoute>,
    pub dns_servers: Vec<IpAddr>,
}

impl TunRoutePlan {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            device_name: "maverick0".into(),
            include_routes: Vec::new(),
            exclude_routes: Vec::new(),
            dns_servers: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        validate_device_name(&self.device_name)?;
        for route in &self.include_routes {
            route.validate("include_routes")?;
        }
        for route in &self.exclude_routes {
            route.validate("exclude_routes")?;
        }
        if self.enabled && self.include_routes.is_empty() {
            return Err(Error::Config(
                "tun include_routes must not be empty when enabled".into(),
            ));
        }
        Ok(())
    }

    pub fn dry_run_steps(&self) -> Result<Vec<String>> {
        self.validate()?;
        if !self.enabled {
            return Ok(vec!["tun disabled: no system changes planned".into()]);
        }
        let mut steps = vec![format!("create tun device {}", self.device_name)];
        for route in &self.include_routes {
            steps.push(format!("add route {}", route.display_cidr()));
        }
        for route in &self.exclude_routes {
            steps.push(format!("exclude route {}", route.display_cidr()));
        }
        for dns in &self.dns_servers {
            steps.push(format!("set dns server {dns}"));
        }
        steps.push("record rollback plan".into());
        Ok(steps)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TunApplyBlocker {
    TunDisabled,
    DryRunRequired,
    OperatorApprovalRequired,
    ApprovedHostRequired,
    UnsupportedPlatform,
    PrivilegesRequired,
    ProxyVpnConflictCheckRequired,
    RollbackPlanRequired,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TunApplySafetyContext {
    pub dry_run_completed: bool,
    pub operator_approved: bool,
    pub approved_host: bool,
    pub platform_supported: bool,
    pub privileges_confirmed: bool,
    pub proxy_vpn_conflict_checked: bool,
    pub rollback_plan_writable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunApplySafetyDecision {
    pub allowed: bool,
    pub blockers: Vec<TunApplyBlocker>,
}

impl TunApplySafetyDecision {
    pub fn is_allowed(&self) -> bool {
        self.allowed && self.blockers.is_empty()
    }
}

pub fn evaluate_tun_apply_safety(
    plan: &TunRoutePlan,
    context: TunApplySafetyContext,
) -> Result<TunApplySafetyDecision> {
    plan.validate()?;

    let mut blockers = Vec::new();
    if !plan.enabled {
        blockers.push(TunApplyBlocker::TunDisabled);
        return Ok(TunApplySafetyDecision {
            allowed: false,
            blockers,
        });
    }
    if !context.dry_run_completed {
        blockers.push(TunApplyBlocker::DryRunRequired);
    }
    if !context.operator_approved {
        blockers.push(TunApplyBlocker::OperatorApprovalRequired);
    }
    if !context.approved_host {
        blockers.push(TunApplyBlocker::ApprovedHostRequired);
    }
    if !context.platform_supported {
        blockers.push(TunApplyBlocker::UnsupportedPlatform);
    }
    if !context.privileges_confirmed {
        blockers.push(TunApplyBlocker::PrivilegesRequired);
    }
    if !context.proxy_vpn_conflict_checked {
        blockers.push(TunApplyBlocker::ProxyVpnConflictCheckRequired);
    }
    if !context.rollback_plan_writable {
        blockers.push(TunApplyBlocker::RollbackPlanRequired);
    }

    Ok(TunApplySafetyDecision {
        allowed: blockers.is_empty(),
        blockers,
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum TunRuntimeAction {
    RecordRollbackPlan { rollback_action_count: usize },
    CreateTunDevice { device_name: String },
    BringDeviceUp { device_name: String },
    PreserveRoute { cidr: String },
    AddRoute { cidr: String, device_name: String },
    SetDnsServers { servers: Vec<String> },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum TunRuntimeRollbackAction {
    RestoreDnsServers,
    RestoreRoute { cidr: String },
    DeleteRoute { cidr: String, device_name: String },
    DeleteTunDevice { device_name: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TunRuntimePlan {
    pub device_name: String,
    pub apply_actions: Vec<TunRuntimeAction>,
    pub rollback_actions: Vec<TunRuntimeRollbackAction>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TunProductionPolicy {
    pub route_exclusions_ready: bool,
    pub default_route_ready: bool,
    pub global_dns_ready: bool,
    pub control_plane_bypass_ready: bool,
    pub leak_sentry_ready: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TunProductionPolicyBlocker {
    RouteExclusionPolicyMissing,
    DefaultRoutePolicyMissing,
    GlobalDnsPolicyMissing,
    ControlPlaneBypassMissing,
    LeakSentryMissing,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunProductionPolicyDecision {
    pub allowed: bool,
    pub blockers: Vec<TunProductionPolicyBlocker>,
}

impl TunProductionPolicyDecision {
    pub fn is_allowed(&self) -> bool {
        self.allowed && self.blockers.is_empty()
    }
}

pub fn evaluate_tun_production_policy(
    plan: &TunRoutePlan,
    policy: TunProductionPolicy,
) -> Result<TunProductionPolicyDecision> {
    plan.validate()?;

    let mut blockers = Vec::new();
    let default_route_requested = plan.include_routes.iter().any(TunRoute::is_default_route);
    let route_exclusions_requested = !plan.exclude_routes.is_empty();
    let dns_requested = !plan.dns_servers.is_empty();

    if route_exclusions_requested && !policy.route_exclusions_ready {
        blockers.push(TunProductionPolicyBlocker::RouteExclusionPolicyMissing);
    }
    if default_route_requested && !policy.default_route_ready {
        blockers.push(TunProductionPolicyBlocker::DefaultRoutePolicyMissing);
    }
    if dns_requested && !policy.global_dns_ready {
        blockers.push(TunProductionPolicyBlocker::GlobalDnsPolicyMissing);
    }
    if default_route_requested && !policy.control_plane_bypass_ready {
        blockers.push(TunProductionPolicyBlocker::ControlPlaneBypassMissing);
    }
    if (default_route_requested || dns_requested) && !policy.leak_sentry_ready {
        blockers.push(TunProductionPolicyBlocker::LeakSentryMissing);
    }

    Ok(TunProductionPolicyDecision {
        allowed: blockers.is_empty(),
        blockers,
    })
}

pub fn build_tun_runtime_plan(
    plan: &TunRoutePlan,
    context: TunApplySafetyContext,
) -> Result<TunRuntimePlan> {
    build_tun_runtime_plan_with_policy(plan, context, TunProductionPolicy::default())
}

pub fn build_tun_runtime_plan_with_policy(
    plan: &TunRoutePlan,
    context: TunApplySafetyContext,
    policy: TunProductionPolicy,
) -> Result<TunRuntimePlan> {
    let decision = evaluate_tun_apply_safety(plan, context)?;
    if !decision.is_allowed() {
        return Err(Error::Config(format!(
            "tun runtime helper blocked by safety gate: {:?}",
            decision.blockers
        )));
    }
    let policy_decision = evaluate_tun_production_policy(plan, policy)?;
    if !policy_decision.is_allowed() {
        return Err(Error::Config(format!(
            "tun runtime helper blocked by production policy gate: {:?}",
            policy_decision.blockers
        )));
    }

    let device_name = plan.device_name.clone();
    let mut rollback_actions = Vec::new();
    if !plan.dns_servers.is_empty() {
        rollback_actions.push(TunRuntimeRollbackAction::RestoreDnsServers);
    }
    for route in plan.exclude_routes.iter().rev() {
        rollback_actions.push(TunRuntimeRollbackAction::RestoreRoute {
            cidr: route.display_cidr(),
        });
    }
    for route in plan.include_routes.iter().rev() {
        rollback_actions.push(TunRuntimeRollbackAction::DeleteRoute {
            cidr: route.display_cidr(),
            device_name: device_name.clone(),
        });
    }
    rollback_actions.push(TunRuntimeRollbackAction::DeleteTunDevice {
        device_name: device_name.clone(),
    });

    let mut apply_actions = vec![
        TunRuntimeAction::RecordRollbackPlan {
            rollback_action_count: rollback_actions.len(),
        },
        TunRuntimeAction::CreateTunDevice {
            device_name: device_name.clone(),
        },
        TunRuntimeAction::BringDeviceUp {
            device_name: device_name.clone(),
        },
    ];
    for route in &plan.exclude_routes {
        apply_actions.push(TunRuntimeAction::PreserveRoute {
            cidr: route.display_cidr(),
        });
    }
    for route in &plan.include_routes {
        apply_actions.push(TunRuntimeAction::AddRoute {
            cidr: route.display_cidr(),
            device_name: device_name.clone(),
        });
    }
    if !plan.dns_servers.is_empty() {
        apply_actions.push(TunRuntimeAction::SetDnsServers {
            servers: plan.dns_servers.iter().map(ToString::to_string).collect(),
        });
    }

    Ok(TunRuntimePlan {
        device_name,
        apply_actions,
        rollback_actions,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunRuntimeReadinessBlocker {
    RoutePlanModelMissing,
    ApplySafetyModelMissing,
    ApprovedVmApplySmokeMissing,
    ProductionRoutePolicyMissing,
    DefaultRoutePolicyMissing,
    PlatformAdapterMissing,
    ServiceManagerIntegrationMissing,
    GlobalDnsPolicyMissing,
    LeakTestsMissing,
    CoexistenceTestsMissing,
    RuntimeHelperPlanModelMissing,
    RuntimeHelperPreflightMissing,
    RuntimeHelperRollbackJournalMissing,
    RuntimeHelperRecoveryMissing,
    RuntimeHelperNetworkBaselineChecksMissing,
    RuntimeHelperNamespaceSmokeMissing,
    RuntimeHelperDefaultRouteDnsSmokeMissing,
    RuntimeHelperMissing,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TunRuntimeReadinessSnapshot {
    pub route_plan_model_ready: bool,
    pub apply_safety_model_ready: bool,
    pub approved_vm_apply_smoke_ready: bool,
    pub production_route_policy_ready: bool,
    pub default_route_policy_ready: bool,
    pub platform_adapter_ready: bool,
    pub service_manager_integration_ready: bool,
    pub global_dns_policy_ready: bool,
    pub leak_tests_ready: bool,
    pub coexistence_tests_ready: bool,
    pub runtime_helper_plan_model_ready: bool,
    pub runtime_helper_preflight_ready: bool,
    pub runtime_helper_rollback_journal_ready: bool,
    pub runtime_helper_recovery_ready: bool,
    pub runtime_helper_network_baseline_checks_ready: bool,
    pub runtime_helper_namespace_smoke_ready: bool,
    pub runtime_helper_default_route_dns_smoke_ready: bool,
    pub runtime_helper_ready: bool,
    pub runtime_ready: bool,
    pub blockers: Vec<TunRuntimeReadinessBlocker>,
}

impl TunRuntimeReadinessSnapshot {
    pub fn current() -> Self {
        Self::from_inputs(TunRuntimeReadinessInputs::current())
    }

    fn from_inputs(inputs: TunRuntimeReadinessInputs) -> Self {
        let mut blockers = Vec::new();
        if !inputs.route_plan_model_ready {
            blockers.push(TunRuntimeReadinessBlocker::RoutePlanModelMissing);
        }
        if !inputs.apply_safety_model_ready {
            blockers.push(TunRuntimeReadinessBlocker::ApplySafetyModelMissing);
        }
        if !inputs.approved_vm_apply_smoke_ready {
            blockers.push(TunRuntimeReadinessBlocker::ApprovedVmApplySmokeMissing);
        }
        if !inputs.production_route_policy_ready {
            blockers.push(TunRuntimeReadinessBlocker::ProductionRoutePolicyMissing);
        }
        if !inputs.default_route_policy_ready {
            blockers.push(TunRuntimeReadinessBlocker::DefaultRoutePolicyMissing);
        }
        if !inputs.platform_adapter_ready {
            blockers.push(TunRuntimeReadinessBlocker::PlatformAdapterMissing);
        }
        if !inputs.service_manager_integration_ready {
            blockers.push(TunRuntimeReadinessBlocker::ServiceManagerIntegrationMissing);
        }
        if !inputs.global_dns_policy_ready {
            blockers.push(TunRuntimeReadinessBlocker::GlobalDnsPolicyMissing);
        }
        if !inputs.leak_tests_ready {
            blockers.push(TunRuntimeReadinessBlocker::LeakTestsMissing);
        }
        if !inputs.coexistence_tests_ready {
            blockers.push(TunRuntimeReadinessBlocker::CoexistenceTestsMissing);
        }
        if !inputs.runtime_helper_plan_model_ready {
            blockers.push(TunRuntimeReadinessBlocker::RuntimeHelperPlanModelMissing);
        }
        if !inputs.runtime_helper_preflight_ready {
            blockers.push(TunRuntimeReadinessBlocker::RuntimeHelperPreflightMissing);
        }
        if !inputs.runtime_helper_rollback_journal_ready {
            blockers.push(TunRuntimeReadinessBlocker::RuntimeHelperRollbackJournalMissing);
        }
        if !inputs.runtime_helper_recovery_ready {
            blockers.push(TunRuntimeReadinessBlocker::RuntimeHelperRecoveryMissing);
        }
        if !inputs.runtime_helper_network_baseline_checks_ready {
            blockers.push(TunRuntimeReadinessBlocker::RuntimeHelperNetworkBaselineChecksMissing);
        }
        if !inputs.runtime_helper_namespace_smoke_ready {
            blockers.push(TunRuntimeReadinessBlocker::RuntimeHelperNamespaceSmokeMissing);
        }
        if !inputs.runtime_helper_default_route_dns_smoke_ready {
            blockers.push(TunRuntimeReadinessBlocker::RuntimeHelperDefaultRouteDnsSmokeMissing);
        }
        if !inputs.runtime_helper_ready {
            blockers.push(TunRuntimeReadinessBlocker::RuntimeHelperMissing);
        }

        let runtime_ready = blockers.is_empty();
        Self {
            route_plan_model_ready: inputs.route_plan_model_ready,
            apply_safety_model_ready: inputs.apply_safety_model_ready,
            approved_vm_apply_smoke_ready: inputs.approved_vm_apply_smoke_ready,
            production_route_policy_ready: inputs.production_route_policy_ready,
            default_route_policy_ready: inputs.default_route_policy_ready,
            platform_adapter_ready: inputs.platform_adapter_ready,
            service_manager_integration_ready: inputs.service_manager_integration_ready,
            global_dns_policy_ready: inputs.global_dns_policy_ready,
            leak_tests_ready: inputs.leak_tests_ready,
            coexistence_tests_ready: inputs.coexistence_tests_ready,
            runtime_helper_plan_model_ready: inputs.runtime_helper_plan_model_ready,
            runtime_helper_preflight_ready: inputs.runtime_helper_preflight_ready,
            runtime_helper_rollback_journal_ready: inputs.runtime_helper_rollback_journal_ready,
            runtime_helper_recovery_ready: inputs.runtime_helper_recovery_ready,
            runtime_helper_network_baseline_checks_ready: inputs
                .runtime_helper_network_baseline_checks_ready,
            runtime_helper_namespace_smoke_ready: inputs.runtime_helper_namespace_smoke_ready,
            runtime_helper_default_route_dns_smoke_ready: inputs
                .runtime_helper_default_route_dns_smoke_ready,
            runtime_helper_ready: inputs.runtime_helper_ready,
            runtime_ready,
            blockers,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TunRuntimeReadinessInputs {
    route_plan_model_ready: bool,
    apply_safety_model_ready: bool,
    approved_vm_apply_smoke_ready: bool,
    production_route_policy_ready: bool,
    default_route_policy_ready: bool,
    platform_adapter_ready: bool,
    service_manager_integration_ready: bool,
    global_dns_policy_ready: bool,
    leak_tests_ready: bool,
    coexistence_tests_ready: bool,
    runtime_helper_plan_model_ready: bool,
    runtime_helper_preflight_ready: bool,
    runtime_helper_rollback_journal_ready: bool,
    runtime_helper_recovery_ready: bool,
    runtime_helper_network_baseline_checks_ready: bool,
    runtime_helper_namespace_smoke_ready: bool,
    runtime_helper_default_route_dns_smoke_ready: bool,
    runtime_helper_ready: bool,
}

impl TunRuntimeReadinessInputs {
    fn current() -> Self {
        Self {
            route_plan_model_ready: true,
            apply_safety_model_ready: true,
            approved_vm_apply_smoke_ready: true,
            production_route_policy_ready: true,
            default_route_policy_ready: true,
            platform_adapter_ready: false,
            service_manager_integration_ready: true,
            global_dns_policy_ready: true,
            leak_tests_ready: true,
            coexistence_tests_ready: true,
            runtime_helper_plan_model_ready: true,
            runtime_helper_preflight_ready: true,
            runtime_helper_rollback_journal_ready: true,
            runtime_helper_recovery_ready: true,
            runtime_helper_network_baseline_checks_ready: true,
            runtime_helper_namespace_smoke_ready: true,
            runtime_helper_default_route_dns_smoke_ready: true,
            runtime_helper_ready: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TunTransportProtocol {
    Tcp,
    Udp,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunPacketFlow {
    pub protocol: TunTransportProtocol,
    pub source: IpAddr,
    pub destination: IpAddr,
    pub source_port: u16,
    pub destination_port: u16,
    pub payload_offset: usize,
}

impl TunPacketFlow {
    pub fn target_addr(&self) -> TargetAddr {
        match self.destination {
            IpAddr::V4(addr) => TargetAddr::Ipv4(addr),
            IpAddr::V6(addr) => TargetAddr::Ipv6(addr),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TunPacketClassification {
    Flow(TunPacketFlow),
    Unsupported {
        ip_version: u8,
        protocol: Option<u8>,
        reason: &'static str,
    },
}

pub fn classify_tun_packet(packet: &[u8]) -> Result<TunPacketClassification> {
    let first = *packet
        .first()
        .ok_or(Error::MalformedFrame("tun packet is empty"))?;
    match first >> 4 {
        4 => classify_ipv4_packet(packet),
        6 => classify_ipv6_packet(packet),
        version => Ok(TunPacketClassification::Unsupported {
            ip_version: version,
            protocol: None,
            reason: "unsupported ip version",
        }),
    }
}

fn classify_ipv4_packet(packet: &[u8]) -> Result<TunPacketClassification> {
    if packet.len() < 20 {
        return Err(Error::MalformedFrame("truncated ipv4 packet"));
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl {
        return Err(Error::MalformedFrame("invalid ipv4 header length"));
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len < ihl || total_len > packet.len() {
        return Err(Error::MalformedFrame("invalid ipv4 total length"));
    }
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if fragment & 0x3fff != 0 {
        return Ok(TunPacketClassification::Unsupported {
            ip_version: 4,
            protocol: Some(packet[9]),
            reason: "fragmented ipv4 packet",
        });
    }
    let source = IpAddr::V4(Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ));
    let destination = IpAddr::V4(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ));
    classify_transport(
        4,
        packet[9],
        source,
        destination,
        &packet[ihl..total_len],
        ihl,
    )
}

fn classify_ipv6_packet(packet: &[u8]) -> Result<TunPacketClassification> {
    if packet.len() < 40 {
        return Err(Error::MalformedFrame("truncated ipv6 packet"));
    }
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let total_len = 40 + payload_len;
    if total_len > packet.len() {
        return Err(Error::MalformedFrame("invalid ipv6 payload length"));
    }
    let mut source = [0u8; 16];
    source.copy_from_slice(&packet[8..24]);
    let mut destination = [0u8; 16];
    destination.copy_from_slice(&packet[24..40]);
    classify_transport(
        6,
        packet[6],
        IpAddr::V6(Ipv6Addr::from(source)),
        IpAddr::V6(Ipv6Addr::from(destination)),
        &packet[40..total_len],
        40,
    )
}

fn classify_transport(
    ip_version: u8,
    protocol: u8,
    source: IpAddr,
    destination: IpAddr,
    segment: &[u8],
    base_offset: usize,
) -> Result<TunPacketClassification> {
    match protocol {
        6 => classify_tcp(source, destination, segment, base_offset),
        17 => classify_udp(source, destination, segment, base_offset),
        other => Ok(TunPacketClassification::Unsupported {
            ip_version,
            protocol: Some(other),
            reason: "unsupported transport protocol",
        }),
    }
}

fn classify_tcp(
    source: IpAddr,
    destination: IpAddr,
    segment: &[u8],
    base_offset: usize,
) -> Result<TunPacketClassification> {
    if segment.len() < 20 {
        return Err(Error::MalformedFrame("truncated tcp segment"));
    }
    let header_len = ((segment[12] >> 4) as usize) * 4;
    if header_len < 20 || segment.len() < header_len {
        return Err(Error::MalformedFrame("invalid tcp header length"));
    }
    Ok(TunPacketClassification::Flow(TunPacketFlow {
        protocol: TunTransportProtocol::Tcp,
        source,
        destination,
        source_port: u16::from_be_bytes([segment[0], segment[1]]),
        destination_port: u16::from_be_bytes([segment[2], segment[3]]),
        payload_offset: base_offset + header_len,
    }))
}

fn classify_udp(
    source: IpAddr,
    destination: IpAddr,
    segment: &[u8],
    base_offset: usize,
) -> Result<TunPacketClassification> {
    if segment.len() < 8 {
        return Err(Error::MalformedFrame("truncated udp datagram"));
    }
    let udp_len = u16::from_be_bytes([segment[4], segment[5]]) as usize;
    if udp_len < 8 || udp_len > segment.len() {
        return Err(Error::MalformedFrame("invalid udp length"));
    }
    Ok(TunPacketClassification::Flow(TunPacketFlow {
        protocol: TunTransportProtocol::Udp,
        source,
        destination,
        source_port: u16::from_be_bytes([segment[0], segment[1]]),
        destination_port: u16::from_be_bytes([segment[2], segment[3]]),
        payload_offset: base_offset + 8,
    }))
}

fn validate_device_name(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 32 {
        return Err(Error::Config(
            "tun device_name must be 1 to 32 characters".into(),
        ));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(Error::Config(
            "tun device_name must contain only ASCII letters, digits, '-' or '_'".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn disabled_plan_has_no_system_changes() {
        let steps = TunRoutePlan::disabled().dry_run_steps().unwrap();
        assert_eq!(steps, vec!["tun disabled: no system changes planned"]);
    }

    #[test]
    fn enabled_plan_requires_include_routes() {
        let plan = TunRoutePlan {
            enabled: true,
            device_name: "maverick0".into(),
            include_routes: Vec::new(),
            exclude_routes: Vec::new(),
            dns_servers: Vec::new(),
        };
        assert!(plan.validate().is_err());
    }

    #[test]
    fn rejects_invalid_prefix_lengths() {
        let plan = TunRoutePlan {
            enabled: true,
            device_name: "maverick0".into(),
            include_routes: vec![TunRoute::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 33)],
            exclude_routes: Vec::new(),
            dns_servers: Vec::new(),
        };
        assert!(plan.validate().is_err());
    }

    #[test]
    fn rejects_unsafe_device_names() {
        let plan = TunRoutePlan {
            enabled: false,
            device_name: "../tun0".into(),
            include_routes: Vec::new(),
            exclude_routes: Vec::new(),
            dns_servers: Vec::new(),
        };
        assert!(plan.validate().is_err());
    }

    #[test]
    fn dry_run_plan_lists_reversible_steps() {
        let plan = TunRoutePlan {
            enabled: true,
            device_name: "maverick0".into(),
            include_routes: vec![
                TunRoute::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8),
                TunRoute::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
            ],
            exclude_routes: vec![TunRoute::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8)],
            dns_servers: vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
        };
        let steps = plan.dry_run_steps().unwrap();
        assert_eq!(steps[0], "create tun device maverick0");
        assert!(steps.iter().any(|step| step == "add route 10.0.0.0/8"));
        assert!(steps.iter().any(|step| step == "exclude route 127.0.0.0/8"));
        assert!(steps.iter().any(|step| step == "set dns server 1.1.1.1"));
        assert_eq!(steps.last().unwrap(), "record rollback plan");
    }

    #[test]
    fn disabled_tun_plan_blocks_apply() {
        let decision =
            evaluate_tun_apply_safety(&TunRoutePlan::disabled(), TunApplySafetyContext::default())
                .unwrap();
        assert!(!decision.is_allowed());
        assert_eq!(decision.blockers, vec![TunApplyBlocker::TunDisabled]);
    }

    #[test]
    fn tun_apply_safety_requires_all_gates() {
        let plan = enabled_plan();
        let decision = evaluate_tun_apply_safety(&plan, TunApplySafetyContext::default()).unwrap();
        assert!(!decision.is_allowed());
        assert_eq!(
            decision.blockers,
            vec![
                TunApplyBlocker::DryRunRequired,
                TunApplyBlocker::OperatorApprovalRequired,
                TunApplyBlocker::ApprovedHostRequired,
                TunApplyBlocker::UnsupportedPlatform,
                TunApplyBlocker::PrivilegesRequired,
                TunApplyBlocker::ProxyVpnConflictCheckRequired,
                TunApplyBlocker::RollbackPlanRequired,
            ]
        );
    }

    #[test]
    fn tun_apply_safety_allows_only_after_explicit_gates() {
        let decision = evaluate_tun_apply_safety(
            &enabled_plan(),
            TunApplySafetyContext {
                dry_run_completed: true,
                operator_approved: true,
                approved_host: true,
                platform_supported: true,
                privileges_confirmed: true,
                proxy_vpn_conflict_checked: true,
                rollback_plan_writable: true,
            },
        )
        .unwrap();
        assert!(decision.is_allowed());
        assert!(decision.blockers.is_empty());
    }

    #[test]
    fn tun_apply_safety_validates_plan_before_gate_decision() {
        let plan = TunRoutePlan {
            enabled: true,
            device_name: "../tun0".into(),
            include_routes: vec![TunRoute::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8)],
            exclude_routes: Vec::new(),
            dns_servers: Vec::new(),
        };
        assert!(evaluate_tun_apply_safety(&plan, TunApplySafetyContext::default()).is_err());
    }

    #[test]
    fn tun_runtime_plan_requires_safety_gate() {
        let err = build_tun_runtime_plan(&enabled_plan(), TunApplySafetyContext::default())
            .expect_err("unsafe context must not produce a runtime plan");
        assert!(err
            .to_string()
            .contains("tun runtime helper blocked by safety gate"));
    }

    #[test]
    fn tun_runtime_plan_rejects_dns_until_global_policy_exists() {
        let mut plan = include_only_plan();
        plan.dns_servers = vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))];
        let err = build_tun_runtime_plan(&plan, approved_tun_apply_context())
            .expect_err("dns apply must remain blocked");
        assert!(err.to_string().contains("GlobalDnsPolicyMissing"));
    }

    #[test]
    fn tun_runtime_plan_rejects_excludes_until_policy_exists() {
        let mut plan = include_only_plan();
        plan.exclude_routes = vec![TunRoute::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8)];
        let err = build_tun_runtime_plan(&plan, approved_tun_apply_context())
            .expect_err("exclude route apply must remain blocked");
        assert!(err.to_string().contains("RouteExclusionPolicyMissing"));
    }

    #[test]
    fn tun_production_policy_requires_default_route_guards() {
        let plan = default_route_plan();
        let decision = evaluate_tun_production_policy(&plan, TunProductionPolicy::default())
            .expect("policy evaluation");
        assert!(!decision.is_allowed());
        assert_eq!(
            decision.blockers,
            vec![
                TunProductionPolicyBlocker::RouteExclusionPolicyMissing,
                TunProductionPolicyBlocker::DefaultRoutePolicyMissing,
                TunProductionPolicyBlocker::GlobalDnsPolicyMissing,
                TunProductionPolicyBlocker::ControlPlaneBypassMissing,
                TunProductionPolicyBlocker::LeakSentryMissing,
            ]
        );
    }

    #[test]
    fn tun_runtime_plan_with_policy_builds_default_route_dns_actions() {
        let runtime_plan = build_tun_runtime_plan_with_policy(
            &default_route_plan(),
            approved_tun_apply_context(),
            approved_production_policy(),
        )
        .unwrap();

        assert_eq!(
            runtime_plan.apply_actions,
            vec![
                TunRuntimeAction::RecordRollbackPlan {
                    rollback_action_count: 4
                },
                TunRuntimeAction::CreateTunDevice {
                    device_name: "maverick0".into()
                },
                TunRuntimeAction::BringDeviceUp {
                    device_name: "maverick0".into()
                },
                TunRuntimeAction::PreserveRoute {
                    cidr: "198.18.0.1/32".into()
                },
                TunRuntimeAction::AddRoute {
                    cidr: "0.0.0.0/0".into(),
                    device_name: "maverick0".into()
                },
                TunRuntimeAction::SetDnsServers {
                    servers: vec!["9.9.9.9".into()]
                },
            ]
        );
        assert_eq!(
            runtime_plan.rollback_actions,
            vec![
                TunRuntimeRollbackAction::RestoreDnsServers,
                TunRuntimeRollbackAction::RestoreRoute {
                    cidr: "198.18.0.1/32".into()
                },
                TunRuntimeRollbackAction::DeleteRoute {
                    cidr: "0.0.0.0/0".into(),
                    device_name: "maverick0".into()
                },
                TunRuntimeRollbackAction::DeleteTunDevice {
                    device_name: "maverick0".into()
                },
            ]
        );
    }

    #[test]
    fn tun_runtime_plan_builds_reversible_abstract_actions() {
        let runtime_plan =
            build_tun_runtime_plan(&include_only_plan(), approved_tun_apply_context()).unwrap();
        assert_eq!(runtime_plan.device_name, "maverick0");
        assert_eq!(
            runtime_plan.apply_actions,
            vec![
                TunRuntimeAction::RecordRollbackPlan {
                    rollback_action_count: 2
                },
                TunRuntimeAction::CreateTunDevice {
                    device_name: "maverick0".into()
                },
                TunRuntimeAction::BringDeviceUp {
                    device_name: "maverick0".into()
                },
                TunRuntimeAction::AddRoute {
                    cidr: "10.0.0.0/8".into(),
                    device_name: "maverick0".into()
                },
            ]
        );
        assert_eq!(
            runtime_plan.rollback_actions,
            vec![
                TunRuntimeRollbackAction::DeleteRoute {
                    cidr: "10.0.0.0/8".into(),
                    device_name: "maverick0".into()
                },
                TunRuntimeRollbackAction::DeleteTunDevice {
                    device_name: "maverick0".into()
                },
            ]
        );

        let rendered = serde_json::to_string(&runtime_plan).unwrap();
        assert!(rendered.contains("record_rollback_plan"));
        assert!(rendered.contains("delete_tun_device"));
        assert!(!rendered.contains("sudo"));
        assert!(!rendered.contains(" ip "));
    }

    #[test]
    fn classifies_ipv4_tcp_packet() {
        let packet = ipv4_packet(
            6,
            tcp_segment(50_000, 443, b"GET"),
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(93, 184, 216, 34),
            0,
        );
        let classification = classify_tun_packet(&packet).unwrap();
        let TunPacketClassification::Flow(flow) = classification else {
            panic!("expected flow");
        };
        assert_eq!(flow.protocol, TunTransportProtocol::Tcp);
        assert_eq!(flow.source, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(
            flow.destination,
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))
        );
        assert_eq!(flow.source_port, 50_000);
        assert_eq!(flow.destination_port, 443);
        assert_eq!(flow.payload_offset, 40);
        assert_eq!(
            flow.target_addr(),
            TargetAddr::Ipv4(Ipv4Addr::new(93, 184, 216, 34))
        );
    }

    #[test]
    fn classifies_ipv4_udp_packet() {
        let packet = ipv4_packet(
            17,
            udp_datagram(5353, 53, b"dns"),
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(1, 1, 1, 1),
            0,
        );
        let classification = classify_tun_packet(&packet).unwrap();
        let TunPacketClassification::Flow(flow) = classification else {
            panic!("expected flow");
        };
        assert_eq!(flow.protocol, TunTransportProtocol::Udp);
        assert_eq!(flow.destination_port, 53);
        assert_eq!(flow.payload_offset, 28);
    }

    #[test]
    fn classifies_ipv6_tcp_packet() {
        let packet = ipv6_packet(
            6,
            tcp_segment(50_000, 443, b"GET"),
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::new(0x2606, 0x2800, 0x220, 1, 0x248, 0x1893, 0x25c8, 0x1946),
        );
        let classification = classify_tun_packet(&packet).unwrap();
        let TunPacketClassification::Flow(flow) = classification else {
            panic!("expected flow");
        };
        assert_eq!(flow.protocol, TunTransportProtocol::Tcp);
        assert_eq!(flow.source, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(flow.destination_port, 443);
        assert_eq!(flow.payload_offset, 60);
    }

    #[test]
    fn fragmented_ipv4_packet_is_unsupported() {
        let packet = ipv4_packet(
            6,
            tcp_segment(50_000, 443, b"GET"),
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(93, 184, 216, 34),
            0x2000,
        );
        let classification = classify_tun_packet(&packet).unwrap();
        assert_eq!(
            classification,
            TunPacketClassification::Unsupported {
                ip_version: 4,
                protocol: Some(6),
                reason: "fragmented ipv4 packet",
            }
        );
    }

    #[test]
    fn rejects_truncated_tun_packets() {
        assert!(classify_tun_packet(&[]).is_err());
        assert!(classify_tun_packet(&[0x45, 0, 0, 20]).is_err());
        let mut packet = ipv6_packet(
            17,
            udp_datagram(5353, 53, b"dns"),
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::LOCALHOST,
        );
        packet[4] = 0xff;
        packet[5] = 0xff;
        assert!(classify_tun_packet(&packet).is_err());
    }

    #[test]
    fn current_tun_runtime_readiness_tracks_missing_product_adapter() {
        let snapshot = TunRuntimeReadinessSnapshot::current();
        assert!(snapshot.route_plan_model_ready);
        assert!(snapshot.apply_safety_model_ready);
        assert!(snapshot.approved_vm_apply_smoke_ready);
        assert!(snapshot.production_route_policy_ready);
        assert!(snapshot.default_route_policy_ready);
        assert!(snapshot.global_dns_policy_ready);
        assert!(!snapshot.platform_adapter_ready);
        assert!(snapshot.service_manager_integration_ready);
        assert!(snapshot.leak_tests_ready);
        assert!(snapshot.coexistence_tests_ready);
        assert!(snapshot.runtime_helper_plan_model_ready);
        assert!(snapshot.runtime_helper_preflight_ready);
        assert!(snapshot.runtime_helper_rollback_journal_ready);
        assert!(snapshot.runtime_helper_recovery_ready);
        assert!(snapshot.runtime_helper_network_baseline_checks_ready);
        assert!(snapshot.runtime_helper_namespace_smoke_ready);
        assert!(snapshot.runtime_helper_default_route_dns_smoke_ready);
        assert!(snapshot.runtime_helper_ready);
        assert!(!snapshot.runtime_ready);
        assert_eq!(
            snapshot.blockers,
            vec![TunRuntimeReadinessBlocker::PlatformAdapterMissing]
        );
    }

    #[test]
    fn all_tun_runtime_readiness_inputs_are_required() {
        let ready_inputs = ready_tun_runtime_inputs();
        let ready = TunRuntimeReadinessSnapshot::from_inputs(ready_inputs);
        assert!(ready.runtime_ready);
        assert!(ready.blockers.is_empty());

        let cases = [
            (
                TunRuntimeReadinessInputs {
                    route_plan_model_ready: false,
                    ..ready_inputs
                },
                TunRuntimeReadinessBlocker::RoutePlanModelMissing,
            ),
            (
                TunRuntimeReadinessInputs {
                    apply_safety_model_ready: false,
                    ..ready_inputs
                },
                TunRuntimeReadinessBlocker::ApplySafetyModelMissing,
            ),
            (
                TunRuntimeReadinessInputs {
                    approved_vm_apply_smoke_ready: false,
                    ..ready_inputs
                },
                TunRuntimeReadinessBlocker::ApprovedVmApplySmokeMissing,
            ),
            (
                TunRuntimeReadinessInputs {
                    production_route_policy_ready: false,
                    ..ready_inputs
                },
                TunRuntimeReadinessBlocker::ProductionRoutePolicyMissing,
            ),
            (
                TunRuntimeReadinessInputs {
                    default_route_policy_ready: false,
                    ..ready_inputs
                },
                TunRuntimeReadinessBlocker::DefaultRoutePolicyMissing,
            ),
            (
                TunRuntimeReadinessInputs {
                    platform_adapter_ready: false,
                    ..ready_inputs
                },
                TunRuntimeReadinessBlocker::PlatformAdapterMissing,
            ),
            (
                TunRuntimeReadinessInputs {
                    service_manager_integration_ready: false,
                    ..ready_inputs
                },
                TunRuntimeReadinessBlocker::ServiceManagerIntegrationMissing,
            ),
            (
                TunRuntimeReadinessInputs {
                    global_dns_policy_ready: false,
                    ..ready_inputs
                },
                TunRuntimeReadinessBlocker::GlobalDnsPolicyMissing,
            ),
            (
                TunRuntimeReadinessInputs {
                    leak_tests_ready: false,
                    ..ready_inputs
                },
                TunRuntimeReadinessBlocker::LeakTestsMissing,
            ),
            (
                TunRuntimeReadinessInputs {
                    coexistence_tests_ready: false,
                    ..ready_inputs
                },
                TunRuntimeReadinessBlocker::CoexistenceTestsMissing,
            ),
            (
                TunRuntimeReadinessInputs {
                    runtime_helper_plan_model_ready: false,
                    ..ready_inputs
                },
                TunRuntimeReadinessBlocker::RuntimeHelperPlanModelMissing,
            ),
            (
                TunRuntimeReadinessInputs {
                    runtime_helper_preflight_ready: false,
                    ..ready_inputs
                },
                TunRuntimeReadinessBlocker::RuntimeHelperPreflightMissing,
            ),
            (
                TunRuntimeReadinessInputs {
                    runtime_helper_rollback_journal_ready: false,
                    ..ready_inputs
                },
                TunRuntimeReadinessBlocker::RuntimeHelperRollbackJournalMissing,
            ),
            (
                TunRuntimeReadinessInputs {
                    runtime_helper_recovery_ready: false,
                    ..ready_inputs
                },
                TunRuntimeReadinessBlocker::RuntimeHelperRecoveryMissing,
            ),
            (
                TunRuntimeReadinessInputs {
                    runtime_helper_network_baseline_checks_ready: false,
                    ..ready_inputs
                },
                TunRuntimeReadinessBlocker::RuntimeHelperNetworkBaselineChecksMissing,
            ),
            (
                TunRuntimeReadinessInputs {
                    runtime_helper_namespace_smoke_ready: false,
                    ..ready_inputs
                },
                TunRuntimeReadinessBlocker::RuntimeHelperNamespaceSmokeMissing,
            ),
            (
                TunRuntimeReadinessInputs {
                    runtime_helper_default_route_dns_smoke_ready: false,
                    ..ready_inputs
                },
                TunRuntimeReadinessBlocker::RuntimeHelperDefaultRouteDnsSmokeMissing,
            ),
            (
                TunRuntimeReadinessInputs {
                    runtime_helper_ready: false,
                    ..ready_inputs
                },
                TunRuntimeReadinessBlocker::RuntimeHelperMissing,
            ),
        ];

        for (inputs, blocker) in cases {
            let snapshot = TunRuntimeReadinessSnapshot::from_inputs(inputs);
            assert!(!snapshot.runtime_ready);
            assert_eq!(snapshot.blockers, vec![blocker]);
        }
    }

    fn ready_tun_runtime_inputs() -> TunRuntimeReadinessInputs {
        TunRuntimeReadinessInputs {
            route_plan_model_ready: true,
            apply_safety_model_ready: true,
            approved_vm_apply_smoke_ready: true,
            production_route_policy_ready: true,
            default_route_policy_ready: true,
            platform_adapter_ready: true,
            service_manager_integration_ready: true,
            global_dns_policy_ready: true,
            leak_tests_ready: true,
            coexistence_tests_ready: true,
            runtime_helper_plan_model_ready: true,
            runtime_helper_preflight_ready: true,
            runtime_helper_rollback_journal_ready: true,
            runtime_helper_recovery_ready: true,
            runtime_helper_network_baseline_checks_ready: true,
            runtime_helper_namespace_smoke_ready: true,
            runtime_helper_default_route_dns_smoke_ready: true,
            runtime_helper_ready: true,
        }
    }

    fn enabled_plan() -> TunRoutePlan {
        TunRoutePlan {
            enabled: true,
            device_name: "maverick0".into(),
            include_routes: vec![TunRoute::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8)],
            exclude_routes: vec![TunRoute::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8)],
            dns_servers: Vec::new(),
        }
    }

    fn include_only_plan() -> TunRoutePlan {
        TunRoutePlan {
            enabled: true,
            device_name: "maverick0".into(),
            include_routes: vec![TunRoute::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8)],
            exclude_routes: Vec::new(),
            dns_servers: Vec::new(),
        }
    }

    fn default_route_plan() -> TunRoutePlan {
        TunRoutePlan {
            enabled: true,
            device_name: "maverick0".into(),
            include_routes: vec![TunRoute::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)],
            exclude_routes: vec![TunRoute::new(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)), 32)],
            dns_servers: vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))],
        }
    }

    fn approved_production_policy() -> TunProductionPolicy {
        TunProductionPolicy {
            route_exclusions_ready: true,
            default_route_ready: true,
            global_dns_ready: true,
            control_plane_bypass_ready: true,
            leak_sentry_ready: true,
        }
    }

    fn approved_tun_apply_context() -> TunApplySafetyContext {
        TunApplySafetyContext {
            dry_run_completed: true,
            operator_approved: true,
            approved_host: true,
            platform_supported: true,
            privileges_confirmed: true,
            proxy_vpn_conflict_checked: true,
            rollback_plan_writable: true,
        }
    }

    fn ipv4_packet(
        protocol: u8,
        payload: Vec<u8>,
        source: Ipv4Addr,
        destination: Ipv4Addr,
        flags_fragment: u16,
    ) -> Vec<u8> {
        let total_len = 20 + payload.len();
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[6..8].copy_from_slice(&flags_fragment.to_be_bytes());
        packet[8] = 64;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        packet.extend_from_slice(&payload);
        packet
    }

    fn ipv6_packet(
        next_header: u8,
        payload: Vec<u8>,
        source: Ipv6Addr,
        destination: Ipv6Addr,
    ) -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        packet[6] = next_header;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source.octets());
        packet[24..40].copy_from_slice(&destination.octets());
        packet.extend_from_slice(&payload);
        packet
    }

    fn tcp_segment(source_port: u16, destination_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut segment = vec![0u8; 20];
        segment[0..2].copy_from_slice(&source_port.to_be_bytes());
        segment[2..4].copy_from_slice(&destination_port.to_be_bytes());
        segment[12] = 0x50;
        segment.extend_from_slice(payload);
        segment
    }

    fn udp_datagram(source_port: u16, destination_port: u16, payload: &[u8]) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let mut datagram = vec![0u8; 8];
        datagram[0..2].copy_from_slice(&source_port.to_be_bytes());
        datagram[2..4].copy_from_slice(&destination_port.to_be_bytes());
        datagram[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        datagram.extend_from_slice(payload);
        datagram
    }
}
