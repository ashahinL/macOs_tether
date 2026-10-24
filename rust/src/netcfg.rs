//! Plan the two /1 routes and a temporary DNS service.
//! Callers pass plain values. This module does not change routes or DNS on the Mac.

use std::net::Ipv4Addr;

/// What the caller observed when it tried to add one route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddOutcome {
    Succeeded,
    Eexist,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    pub destination: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub interface_index: u32,
}

/// Previous process id read from the pidfile. This module does not signal that process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pidfile {
    pub pid: u32,
}

/// The only routes a session may add: `0.0.0.0/1` and `128.0.0.0/1`.
/// Neither entry is `0.0.0.0/0`.
pub fn planned_routes(gateway: Ipv4Addr, interface_index: u32) -> [Route; 2] {
    [
        Route {
            destination: Ipv4Addr::new(0, 0, 0, 0),
            mask: Ipv4Addr::new(128, 0, 0, 0),
            gateway,
            interface_index,
        },
        Route {
            destination: Ipv4Addr::new(128, 0, 0, 0),
            mask: Ipv4Addr::new(128, 0, 0, 0),
            gateway,
            interface_index,
        },
    ]
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Session {
    recorded: Vec<Route>,
}

impl Session {
    pub fn new() -> Self {
        Self {
            recorded: Vec::new(),
        }
    }

    pub fn recorded(&self) -> &[Route] {
        &self.recorded
    }

    /// Keep `route` only when the caller reports that the add succeeded.
    /// `EEXIST` means the route was already there, so a later cleanup must not delete it.
    pub fn record_added(&mut self, route: Route, outcome: AddOutcome) {
        if outcome == AddOutcome::Succeeded {
            self.recorded.push(route);
        }
    }

    /// Recorded routes that still match `current` on destination, mask, gateway, and interface index.
    pub fn cleanup(&self, current: &[Route]) -> Vec<Route> {
        self.recorded
            .iter()
            .copied()
            .filter(|route| current.contains(route))
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsPlan {
    pub service_id: String,
    pub servers: Vec<Ipv4Addr>,
    pub keys: [String; 3],
}

impl DnsPlan {
    pub fn new(service_id: impl Into<String>, servers: Vec<Ipv4Addr>) -> Self {
        let service_id = service_id.into();
        let prefix = format!("State:/Network/Service/{service_id}");
        Self {
            keys: [
                format!("{prefix}/IPv4"),
                format!("{prefix}/DNS"),
                format!("{prefix}/Interface"),
            ],
            service_id,
            servers,
        }
    }
}

/// Routes to delete because `pidfile.pid` is not alive and a saved record exists.
/// A live process yields nothing, even when `saved` is present.
pub fn startup_cleanup(pidfile: &Pidfile, alive: bool, saved: Option<&[Route]>) -> Vec<Route> {
    // The caller already decided whether this pid is alive. Do not signal it.
    let Pidfile { pid: _ } = *pidfile;
    if alive {
        return Vec::new();
    }
    saved.unwrap_or(&[]).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(destination: [u8; 4], mask: [u8; 4], gateway: [u8; 4], interface_index: u32) -> Route {
        Route {
            destination: Ipv4Addr::new(
                destination[0],
                destination[1],
                destination[2],
                destination[3],
            ),
            mask: Ipv4Addr::new(mask[0], mask[1], mask[2], mask[3]),
            gateway: Ipv4Addr::new(gateway[0], gateway[1], gateway[2], gateway[3]),
            interface_index,
        }
    }

    #[test]
    fn plans_two_slash_one_routes_and_not_the_default() {
        let gateway = Ipv4Addr::new(192, 168, 42, 129);
        let routes = planned_routes(gateway, 12);
        let default_route = route([0, 0, 0, 0], [0, 0, 0, 0], [192, 168, 42, 129], 12);

        assert_eq!(
            routes,
            [
                route([0, 0, 0, 0], [128, 0, 0, 0], [192, 168, 42, 129], 12),
                route([128, 0, 0, 0], [128, 0, 0, 0], [192, 168, 42, 129], 12),
            ]
        );
        assert!(routes.iter().all(|planned| *planned != default_route));
    }

    #[test]
    fn record_added_keeps_success_and_skips_eexist() {
        let routes = planned_routes(Ipv4Addr::new(192, 168, 42, 129), 4);
        let mut session = Session::new();

        assert_eq!(session.recorded(), &[] as &[Route]);
        session.record_added(routes[0], AddOutcome::Eexist);
        assert_eq!(session.recorded(), &[] as &[Route]);

        session.record_added(routes[0], AddOutcome::Succeeded);
        session.record_added(routes[1], AddOutcome::Eexist);
        assert_eq!(session.recorded(), &[routes[0]]);
    }

    #[test]
    fn cleanup_returns_only_recorded_routes_still_present() {
        let low = route([0, 0, 0, 0], [128, 0, 0, 0], [192, 168, 42, 129], 7);
        let high = route([128, 0, 0, 0], [128, 0, 0, 0], [192, 168, 42, 129], 7);
        let foreign = route([10, 0, 0, 0], [255, 0, 0, 0], [10, 0, 0, 1], 1);
        let mut other_gateway = high;
        other_gateway.gateway = Ipv4Addr::new(1, 2, 3, 4);
        let mut other_mask = low;
        other_mask.mask = Ipv4Addr::new(255, 255, 255, 0);
        let mut other_index = low;
        other_index.interface_index = 9;

        let mut session = Session::new();
        session.record_added(low, AddOutcome::Succeeded);
        session.record_added(high, AddOutcome::Succeeded);

        assert_eq!(session.cleanup(&[low, high, foreign]), vec![low, high]);
        assert_eq!(session.cleanup(&[low, foreign]), vec![low]);
        assert_eq!(session.cleanup(&[foreign]), Vec::<Route>::new());
        assert_eq!(session.cleanup(&[other_gateway]), Vec::<Route>::new());
        assert_eq!(session.cleanup(&[other_mask]), Vec::<Route>::new());
        assert_eq!(session.cleanup(&[other_index]), Vec::<Route>::new());
    }

    #[test]
    fn dns_plan_uses_service_keys_and_not_global_dns() {
        let plan = DnsPlan::new(
            "tether-9f3a",
            vec![Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)],
        );

        assert_eq!(plan.service_id, "tether-9f3a");
        assert_eq!(
            plan.servers,
            vec![Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)]
        );
        assert_eq!(
            plan.keys,
            [
                "State:/Network/Service/tether-9f3a/IPv4",
                "State:/Network/Service/tether-9f3a/DNS",
                "State:/Network/Service/tether-9f3a/Interface",
            ]
        );
        assert!(plan
            .keys
            .iter()
            .all(|key| key != "State:/Network/Global/DNS"));
    }

    #[test]
    fn startup_cleanup_returns_saved_routes_only_when_the_previous_process_is_dead() {
        let pidfile = Pidfile { pid: 4242 };
        let saved = planned_routes(Ipv4Addr::new(192, 168, 42, 129), 3);

        assert_eq!(pidfile.pid, 4242);
        assert_eq!(
            startup_cleanup(&pidfile, true, Some(&saved)),
            Vec::<Route>::new()
        );
        assert_eq!(
            startup_cleanup(&pidfile, false, Some(&saved)),
            saved.to_vec()
        );
        assert_eq!(startup_cleanup(&pidfile, false, None), Vec::<Route>::new());
    }
}
