use std::collections::{BinaryHeap, HashMap};

use crate::*;

#[test]
fn test_decl_monotonicity_enforcement() {
    // Valid constraint folds
    assert!(
        AttrDecl::new(
            10,
            "test_match",
            ValueKind::Enum,
            Fold::MustMatch,
            Order::Incomparable,
            Role::Constraint,
            Scope::Edge,
            None,
        )
        .is_ok()
    );

    assert!(
        AttrDecl::new(
            11,
            "test_all_true",
            ValueKind::Flag,
            Fold::AllTrue,
            Order::HigherBetter,
            Role::Constraint,
            Scope::Node,
            None,
        )
        .is_ok()
    );

    assert!(
        AttrDecl::new(
            12,
            "test_intersect",
            ValueKind::Bits,
            Fold::Intersect,
            Order::Incomparable,
            Role::Constraint,
            Scope::Edge,
            None,
        )
        .is_ok()
    );

    // Invalid constraint folds must be rejected by constructor
    assert!(
        AttrDecl::new(
            13,
            "test_sum",
            ValueKind::Int,
            Fold::Sum,
            Order::LowerBetter,
            Role::Constraint,
            Scope::Edge,
            None,
        )
        .is_err()
    );

    assert!(
        AttrDecl::new(
            14,
            "test_product",
            ValueKind::Float,
            Fold::Product,
            Order::LowerBetter,
            Role::Constraint,
            Scope::Edge,
            None,
        )
        .is_err()
    );

    assert!(
        AttrDecl::new(
            15,
            "test_count",
            ValueKind::Int,
            Fold::Count,
            Order::LowerBetter,
            Role::Constraint,
            Scope::Edge,
            None,
        )
        .is_err()
    );

    // Non-constraint roles CAN use non-monotonic folds
    assert!(
        AttrDecl::new(
            16,
            "test_metric_sum",
            ValueKind::Int,
            Fold::Sum,
            Order::LowerBetter,
            Role::Metric,
            Scope::Edge,
            None,
        )
        .is_ok()
    );
}

#[test]
fn test_fold_monotonicity_cannot_recover() {
    // 1. MustMatch
    let tcp = Value::Enum(TunnelKind::Tcp as u16);
    let udp = Value::Enum(TunnelKind::Udp as u16);

    let state1 = fold_constraint_value(Fold::MustMatch, None, &tcp);
    assert_eq!(state1, Some(tcp.clone()));

    let state2 = fold_constraint_value(Fold::MustMatch, state1.as_ref(), &tcp);
    assert_eq!(state2, Some(tcp.clone()));

    // Different value causes violation
    let state_violated = fold_constraint_value(Fold::MustMatch, state2.as_ref(), &udp);
    assert_eq!(state_violated, None);

    // 2. AllTrue
    let t = Value::Flag(true);
    let f = Value::Flag(false);

    let s1 = fold_constraint_value(Fold::AllTrue, None, &t);
    assert_eq!(s1, Some(t.clone()));

    let s2 = fold_constraint_value(Fold::AllTrue, s1.as_ref(), &t);
    assert_eq!(s2, Some(t.clone()));

    let s_violated = fold_constraint_value(Fold::AllTrue, s2.as_ref(), &f);
    assert_eq!(s_violated, None);

    // 3. Intersect
    let b1 = Value::Bits(0b0110);
    let b2 = Value::Bits(0b0010);
    let b3 = Value::Bits(0b0100);

    let i1 = fold_constraint_value(Fold::Intersect, None, &b1);
    assert_eq!(i1, Some(b1.clone()));

    let i2 = fold_constraint_value(Fold::Intersect, i1.as_ref(), &b2);
    assert_eq!(i2, Some(b2.clone()));

    let i_violated = fold_constraint_value(Fold::Intersect, i2.as_ref(), &b3);
    assert_eq!(i_violated, None); // 0b0010 & 0b0100 == 0 -> None
}

#[test]
fn test_unknown_semantics() {
    let unk = Value::Unknown;
    let tcp = Value::Enum(TunnelKind::Tcp as u16);
    let t = Value::Flag(true);

    assert_eq!(fold_constraint_value(Fold::MustMatch, None, &unk), None);
    assert_eq!(
        fold_constraint_value(Fold::MustMatch, Some(&tcp), &unk),
        None
    );

    assert_eq!(fold_constraint_value(Fold::AllTrue, None, &unk), None);
    assert_eq!(fold_constraint_value(Fold::AllTrue, Some(&t), &unk), None);

    let mut edge_attrs = AttrSet::new();
    // TUNNEL_TYPE is missing -> get_or_unknown returns Unknown
    let node_attrs = AttrSet::new();

    let tracked = [TUNNEL_TYPE.clone(), GSO_CAPABLE.clone()];
    let state = ConstraintState::initial(&tracked, &node_attrs);
    assert_eq!(state, None); // start node has Unknown gso -> immediately None!

    let mut start_attrs = AttrSet::new();
    start_attrs.set_decl(&GSO_CAPABLE, Value::Flag(true));
    let valid_start = ConstraintState::initial(&tracked, &start_attrs).unwrap();

    // Edge has no tunnel_type -> fold_into must return None
    let res = valid_start.fold_into(&edge_attrs, &start_attrs, &tracked);
    assert_eq!(res, None);

    // Edge has tunnel_type, but target node has unknown gso -> None
    edge_attrs.set_decl(&TUNNEL_TYPE, tcp.clone());
    let res2 = valid_start.fold_into(&edge_attrs, &AttrSet::new(), &tracked);
    assert_eq!(res2, None);
}

// Random graph verification against brute-force simple path enumeration
#[derive(Clone, Debug)]
struct TestGraph {
    num_nodes: usize,
    edges: Vec<(usize, usize, usize, TunnelKind)>, // (u, v, cost, tunnel_kind)
    node_gso: Vec<bool>,
}

impl TestGraph {
    fn brute_force_shortest_path(
        &self,
        start: usize,
        dst: usize,
        req_tunnel: TunnelKind,
    ) -> Option<(usize, usize)> {
        // Returns (min_cost, first_hop)
        if !self.node_gso[start] || !self.node_gso[dst] {
            return None;
        }

        let mut best: Option<(usize, usize)> = None;
        let mut visited = vec![false; self.num_nodes];
        visited[start] = true;

        self.dfs(start, dst, 0, None, req_tunnel, &mut visited, &mut best);

        best
    }

    fn dfs(
        &self,
        curr: usize,
        dst: usize,
        current_cost: usize,
        first_hop: Option<usize>,
        req_tunnel: TunnelKind,
        visited: &mut [bool],
        best: &mut Option<(usize, usize)>,
    ) {
        if curr == dst {
            let hop = first_hop.unwrap_or(dst);
            match *best {
                None => *best = Some((current_cost, hop)),
                Some((min_c, _)) if current_cost < min_c => {
                    *best = Some((current_cost, hop));
                }
                _ => {}
            }
            return;
        }

        for &(u, v, cost, tunnel) in &self.edges {
            if u == curr && !visited[v] {
                if !self.node_gso[v] || tunnel != req_tunnel {
                    continue;
                }
                let next_first_hop = first_hop.or(Some(v));
                let next_cost = current_cost + cost;
                if let Some((min_c, _)) = best {
                    if next_cost >= *min_c {
                        continue;
                    }
                }
                visited[v] = true;
                self.dfs(v, dst, next_cost, next_first_hop, req_tunnel, visited, best);
                visited[v] = false;
            }
        }
    }

    fn dijkstra_state_machine(
        &self,
        start: usize,
        tracked: &[AttrDecl],
    ) -> HashMap<(usize, ConstraintState), (usize, usize)> {
        // State-keyed Dijkstra: returns (cost, first_hop)
        let mut node_attr_sets = Vec::new();
        for &gso in &self.node_gso {
            let mut s = AttrSet::new();
            s.set_decl(&GSO_CAPABLE, Value::Flag(gso));
            node_attr_sets.push(s);
        }

        let mut dist: HashMap<(usize, ConstraintState), usize> = HashMap::new();
        let mut first_hop: HashMap<(usize, ConstraintState), usize> = HashMap::new();

        #[derive(Clone, Eq, PartialEq)]
        struct StateCost {
            cost: usize,
            node: usize,
            state: ConstraintState,
        }
        impl Ord for StateCost {
            fn cmp(&self, other: &Self) -> std::cmp::Ordering {
                other.cost.cmp(&self.cost)
            }
        }
        impl PartialOrd for StateCost {
            fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }

        let mut pq = BinaryHeap::new();

        let initial_constrained = ConstraintState::initial(tracked, &node_attr_sets[start]);
        if let Some(init_s) = initial_constrained {
            dist.insert((start, init_s.clone()), 0);
            first_hop.insert((start, init_s.clone()), start);
            pq.push(StateCost {
                cost: 0,
                node: start,
                state: init_s,
            });
        }

        while let Some(StateCost { cost, node, state }) = pq.pop() {
            if dist
                .get(&(node, state.clone()))
                .copied()
                .unwrap_or(usize::MAX)
                < cost
            {
                continue;
            }

            for &(u, v, edge_cost, tunnel) in &self.edges {
                if u != node {
                    continue;
                }
                let mut edge_attrs = AttrSet::new();
                edge_attrs.set_decl(&TUNNEL_TYPE, Value::Enum(tunnel as u16));

                let next_state = state.fold_into(&edge_attrs, &node_attr_sets[v], tracked);
                if let Some(s_next) = next_state {
                    let next_cost = cost + edge_cost;
                    let curr_best = dist
                        .get(&(v, s_next.clone()))
                        .copied()
                        .unwrap_or(usize::MAX);
                    if next_cost < curr_best {
                        dist.insert((v, s_next.clone()), next_cost);
                        let hop = if node == start {
                            v
                        } else {
                            first_hop[&(node, state.clone())]
                        };
                        first_hop.insert((v, s_next.clone()), hop);
                        pq.push(StateCost {
                            cost: next_cost,
                            node: v,
                            state: s_next,
                        });
                    }
                }
            }
        }

        let mut results = HashMap::new();
        for ((node, st), c) in dist {
            let hop = first_hop[&(node, st.clone())];
            results.insert((node, st), (c, hop));
        }
        results
    }
}

#[test]
fn test_state_machine_matches_brute_force_on_random_graphs() {
    let tracked = [TUNNEL_TYPE.clone(), GSO_CAPABLE.clone()];
    let kinds = [TunnelKind::Tcp, TunnelKind::Udp];

    // Run 20 random graph instances
    let mut rng_seed: u64 = 42;
    let mut next_rand = || -> u64 {
        rng_seed = rng_seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        rng_seed
    };

    for _ in 0..20 {
        let num_nodes = 6;
        let mut node_gso = Vec::new();
        for _ in 0..num_nodes {
            node_gso.push((next_rand() % 10) > 2); // 70% gso true
        }
        node_gso[0] = true; // start node gso true

        let mut edges = Vec::new();
        for u in 0..num_nodes {
            for v in 0..num_nodes {
                if u != v && (next_rand() % 100) < 45 {
                    let cost = (next_rand() % 10 + 1) as usize;
                    let tunnel = kinds[(next_rand() % 2) as usize];
                    edges.push((u, v, cost, tunnel));
                }
            }
        }

        let graph = TestGraph {
            num_nodes,
            edges,
            node_gso,
        };

        let dijkstra_results = graph.dijkstra_state_machine(0, &tracked);

        for target in 1..num_nodes {
            let brute_force = graph.brute_force_shortest_path(0, target, TunnelKind::Tcp);

            let req = [
                Constraint::new(&TUNNEL_TYPE, Value::Enum(TunnelKind::Tcp as u16)),
                Constraint::new(&GSO_CAPABLE, Value::Flag(true)),
            ];

            let state_result = dijkstra_results.iter().find_map(|((n, st), &(cost, hop))| {
                if *n == target && st.satisfies_requirement(&req) {
                    Some((cost, hop))
                } else {
                    None
                }
            });

            match (brute_force, state_result) {
                (None, None) => {}
                (Some((expected_cost, expected_hop)), Some((actual_cost, actual_hop))) => {
                    assert_eq!(
                        actual_cost, expected_cost,
                        "Cost mismatch for target {target}"
                    );
                    assert_eq!(actual_hop, expected_hop, "Hop mismatch for target {target}");
                }
                (bf, st) => {
                    panic!(
                        "Mismatch for target {target}: brute_force={bf:?}, state_machine={st:?}"
                    );
                }
            }
        }
    }
}
