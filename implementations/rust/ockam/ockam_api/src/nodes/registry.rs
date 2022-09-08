use crate::nodes::service::Alias;
use ockam_core::compat::collections::BTreeMap;
use ockam_core::{Address, Route};
use ockam_identity::IdentityIdentifier;

use super::models::secure_channel::CredentialExchangeMode;

#[derive(Default)]
pub(crate) struct SecureChannelRegistry {
    channels: Vec<SecureChannelInfo>,
}

impl SecureChannelRegistry {
    pub fn get_by_route(&self, route: &Route) -> Option<&SecureChannelInfo> {
        self.channels.iter().find(|&x| x.route() == route)
    }

    pub fn get_by_addr(&self, addr: &Address) -> Option<&SecureChannelInfo> {
        self.channels.iter().find(|&x| x.addr() == addr)
    }

    pub fn insert(&mut self, info: SecureChannelInfo) {
        self.channels.push(info)
    }

    pub fn remove_by_addr(&mut self, addr: &Address) -> Option<SecureChannelInfo> {
        if let Some(i) = self.channels.iter().position(|ch| ch.addr() == addr) {
            let info = self.channels.remove(i);
            return Some(info)
        }
        None
    }

    pub fn list(&self) -> &[SecureChannelInfo] {
        &self.channels
    }
}

#[derive(Clone, Debug)]
pub struct SecureChannelInfo {
    // Target route of the channel
    route: Route,
    // Local address of the created channel
    addr: Address,
    authorized_identifiers: Option<Vec<IdentityIdentifier>>,
    mode: CredentialExchangeMode
}

impl SecureChannelInfo {
    pub fn new(
        route: Route,
        addr: Address,
        authorized_identifiers: Option<Vec<IdentityIdentifier>>,
        mode: CredentialExchangeMode
    ) -> Self {
        Self {
            addr,
            route,
            authorized_identifiers,
            mode
        }
    }

    pub fn route(&self) -> &Route {
        &self.route
    }

    pub fn addr(&self) -> &Address {
        &self.addr
    }

    pub fn authorized_identifiers(&self) -> Option<&Vec<IdentityIdentifier>> {
        self.authorized_identifiers.as_ref()
    }
    
    pub fn mode(&self) -> CredentialExchangeMode {
        self.mode
    }
}

#[derive(Default)]
pub(crate) struct SecureChannelListenerInfo {}

#[derive(Default)]
pub(crate) struct VaultServiceInfo {}

#[derive(Default)]
pub(crate) struct IdentityServiceInfo {}

#[derive(Default)]
pub(crate) struct AuthenticatedServiceInfo {}

#[derive(Default)]
pub(crate) struct UppercaseServiceInfo {}

#[derive(Default)]
pub(crate) struct EchoerServiceInfo {}

#[derive(Default)]
pub(crate) struct VerifierServiceInfo {}

#[derive(Default)]
pub(crate) struct CredentialsServiceInfo {}

#[derive(Default)]
pub(crate) struct AuthenticatorServiceInfo {}

pub(crate) struct InletInfo {
    pub(crate) bind_addr: String,
    pub(crate) worker_addr: Address,
}

impl InletInfo {
    pub(crate) fn new(bind_addr: &str, worker_addr: Option<&Address>) -> Self {
        let worker_addr = match worker_addr {
            Some(addr) => addr.clone(),
            None => Address::from_string(""),
        };
        Self {
            bind_addr: bind_addr.to_owned(),
            worker_addr,
        }
    }
}

pub(crate) struct OutletInfo {
    pub(crate) tcp_addr: String,
    pub(crate) worker_addr: Address,
}

impl OutletInfo {
    pub(crate) fn new(tcp_addr: &str, worker_addr: Option<&Address>) -> Self {
        let worker_addr = match worker_addr {
            Some(addr) => addr.clone(),
            None => Address::from_string(""),
        };
        Self {
            tcp_addr: tcp_addr.to_owned(),
            worker_addr,
        }
    }
}

#[derive(Default)]
pub(crate) struct Registry {
    pub(crate) secure_channels: SecureChannelRegistry,
    pub(crate) secure_channel_listeners: BTreeMap<Address, SecureChannelListenerInfo>,
    pub(crate) vault_services: BTreeMap<Address, VaultServiceInfo>,
    pub(crate) identity_services: BTreeMap<Address, IdentityServiceInfo>,
    pub(crate) authenticated_services: BTreeMap<Address, AuthenticatedServiceInfo>,
    pub(crate) uppercase_services: BTreeMap<Address, UppercaseServiceInfo>,
    pub(crate) echoer_services: BTreeMap<Address, EchoerServiceInfo>,
    pub(crate) verifier_services: BTreeMap<Address, VerifierServiceInfo>,
    pub(crate) credentials_services: BTreeMap<Address, CredentialsServiceInfo>,
    #[cfg(feature = "direct-authenticator")]
    pub(crate) authenticator_service: BTreeMap<Address, AuthenticatorServiceInfo>,

    // FIXME: wow this is a terrible way to store data
    pub(crate) inlets: BTreeMap<Alias, InletInfo>,
    pub(crate) outlets: BTreeMap<Alias, OutletInfo>,
}
