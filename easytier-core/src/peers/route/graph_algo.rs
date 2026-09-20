use core::cmp::Ordering;
use petgraph::{
    algo::Measure,
    visit::{EdgeRef, IntoEdges, VisitMap, Visitable},
};
use std::collections::HashMap;
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::{collections::BinaryHeap, hash::Hash};

/// `MinScored<K, T>` holds a score `K` and a scored object `T` in
/// a pair for use with a `BinaryHeap`.
///
/// `MinScored` compares in reverse order by the score, so that we can
/// use `BinaryHeap` as a min-heap to extract the score-value pair with the
/// least score.
///
/// **Note:** `MinScored` implements a total order (`Ord`), so that it is
/// possible to use float types as scores.
#[derive(Copy, Clone, Debug)]
pub struct MinScored<K, T>(pub K, pub T);

impl<K: PartialOrd, T> PartialEq for MinScored<K, T> {
    #[inline]
    fn eq(&self, other: &MinScored<K, T>) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl<K: PartialOrd, T> Eq for MinScored<K, T> {}

impl<K: PartialOrd, T> PartialOrd for MinScored<K, T> {
    #[inline]
    fn partial_cmp(&self, other: &MinScored<K, T>) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<K: PartialOrd, T> Ord for MinScored<K, T> {
    #[inline]
    fn cmp(&self, other: &MinScored<K, T>) -> Ordering {
        let a = &self.0;
        let b = &other.0;
        if a == b {
            Ordering::Equal
        } else if a < b {
            Ordering::Greater
        } else if a > b {
            Ordering::Less
        } else if a.ne(a) && b.ne(b) {
            // these are the NaN cases
            Ordering::Equal
        } else if a.ne(a) {
            // Order NaN less, so that it is last in the MinScore order
            Ordering::Less
        } else {
            Ordering::Greater
        }
    }
}

use easytier_attrs::{AttrDecl, AttrSet, ConstraintState, fold_into};
use std::collections::HashSet;

#[allow(dead_code)]
pub type DijkstraResult<K, NodeId> = (HashMap<NodeId, K>, HashMap<NodeId, (NodeId, usize)>);

pub type ConstrainedDijkstraResult<K, NodeId> = (
    HashMap<(NodeId, ConstraintState), K>,
    HashMap<(NodeId, ConstraintState), (NodeId, usize)>,
);

pub fn dijkstra_with_first_hop_and_constraints<G, F, E, N, K>(
    graph: G,
    start: G::NodeId,
    mut edge_cost: F,
    mut edge_attrs: E,
    node_attrs: N,
    tracked_decls: &[AttrDecl],
) -> ConstrainedDijkstraResult<K, G::NodeId>
where
    G: IntoEdges,
    G::NodeId: Eq + Hash + Clone + Ord,
    F: FnMut(G::EdgeRef) -> K,
    E: FnMut(G::EdgeRef) -> AttrSet,
    N: Fn(G::NodeId) -> AttrSet,
    K: Measure + Copy,
{
    let mut scores = HashMap::new();
    let mut first_hop = HashMap::new();
    let mut visit_next = BinaryHeap::new();
    let zero_score = K::default();

    // 1. Unconstrained state
    let unconstrained = ConstraintState::unconstrained();
    scores.insert((start, unconstrained.clone()), zero_score);
    first_hop.insert((start, unconstrained.clone()), (start, 0));
    visit_next.push(MinScored(zero_score, (start, unconstrained)));

    // 2. Initial constrained state
    let start_node_attrs = node_attrs(start);
    let init_state = ConstraintState::initial(tracked_decls, &start_node_attrs);
    let mut initial_state_count = 1;
    if let Some(init_state) = init_state {
        scores.insert((start, init_state.clone()), zero_score);
        first_hop.insert((start, init_state.clone()), (start, 0));
        visit_next.push(MinScored(zero_score, (start, init_state)));
        initial_state_count = 2;
    }

    let mut node_state_counts: HashMap<G::NodeId, usize> = HashMap::new();
    node_state_counts.insert(start, initial_state_count);

    let mut visited: HashSet<(G::NodeId, ConstraintState)> = HashSet::new();

    while let Some(MinScored(node_score, (node, state))) = visit_next.pop() {
        let node_state_key = (node, state.clone());
        if visited.contains(&node_state_key) {
            continue;
        }

        if scores
            .get(&node_state_key)
            .is_some_and(|best| node_score > *best)
        {
            continue;
        }

        for edge in graph.edges(node) {
            let next_node = edge.target();
            let e_attrs = edge_attrs(edge);
            let target_node_attrs = node_attrs(next_node);

            let next_state = match fold_into(&state, &e_attrs, &target_node_attrs, tracked_decls) {
                Some(s) => s,
                None => continue,
            };

            let next_key = (next_node, next_state);
            if visited.contains(&next_key) {
                continue;
            }

            let next_score = node_score + edge_cost(edge);
            match scores.entry(next_key.clone()) {
                Occupied(mut ent) => {
                    if next_score < *ent.get() {
                        *ent.get_mut() = next_score;
                        visit_next.push(MinScored(next_score, next_key.clone()));
                        let hop = if node == start {
                            (next_node, 0)
                        } else {
                            first_hop[&node_state_key]
                        };
                        first_hop.insert(next_key, (hop.0, hop.1 + 1));
                    }
                }
                Vacant(ent) => {
                    let count = node_state_counts.entry(next_node).or_insert(0);
                    if *count >= easytier_attrs::MAX_CONSTRAINT_STATES {
                        tracing::warn!("exceeded max constraint states per node");
                        continue;
                    }
                    *count += 1;
                    ent.insert(next_score);
                    visit_next.push(MinScored(next_score, next_key.clone()));
                    let hop = if node == start {
                        (next_node, 0)
                    } else {
                        first_hop[&node_state_key]
                    };
                    first_hop.insert(next_key, (hop.0, hop.1 + 1));
                }
            }
        }
        visited.insert(node_state_key);
    }

    (scores, first_hop)
}

#[allow(dead_code)]
pub fn dijkstra_with_first_hop<G, F, K>(
    graph: G,
    start: G::NodeId,
    mut edge_cost: F,
) -> DijkstraResult<K, G::NodeId>
where
    G: IntoEdges + Visitable,
    G::NodeId: Eq + Hash + Clone,
    F: FnMut(G::EdgeRef) -> K,
    K: Measure + Copy,
{
    let mut visited = graph.visit_map();
    let mut scores = HashMap::new();
    let mut first_hop = HashMap::new();
    let mut visit_next = BinaryHeap::new();
    let zero_score = K::default();
    scores.insert(start, zero_score);
    visit_next.push(MinScored(zero_score, start));
    first_hop.insert(start, (start, 0));

    while let Some(MinScored(node_score, node)) = visit_next.pop() {
        if visited.is_visited(&node) {
            continue;
        }
        for edge in graph.edges(node) {
            let next = edge.target();
            if visited.is_visited(&next) {
                continue;
            }
            let next_score = node_score + edge_cost(edge);
            match scores.entry(next) {
                Occupied(mut ent) => {
                    if next_score < *ent.get() {
                        *ent.get_mut() = next_score;
                        visit_next.push(MinScored(next_score, next));
                        // 继承前驱的 first_hop，或自己就是第一跳
                        let hop = if node == start {
                            (next, 0)
                        } else {
                            first_hop[&node]
                        };
                        first_hop.insert(next, (hop.0, hop.1 + 1));
                    }
                }
                Vacant(ent) => {
                    ent.insert(next_score);
                    visit_next.push(MinScored(next_score, next));
                    let hop = if node == start {
                        (next, 0)
                    } else {
                        first_hop[&node]
                    };
                    first_hop.insert(next, (hop.0, hop.1 + 1));
                }
            }
        }
        visited.visit(node);
    }

    (scores, first_hop)
}

#[cfg(test)]
mod tests {
    use super::*;
    use petgraph::graph::DiGraph;

    #[test]
    fn test_dijkstra_with_first_hop_4node() {
        let mut graph = DiGraph::<&str, u32>::new();
        let a = graph.add_node("a");
        let b = graph.add_node("b");
        let c = graph.add_node("c");
        let d = graph.add_node("d");

        graph.extend_with_edges([(a, b, 1)]);
        graph.extend_with_edges([(b, c, 1)]);
        graph.extend_with_edges([(c, d, 2)]);

        let (scores, first_hop) = dijkstra_with_first_hop(&graph, a, |edge| *edge.weight());

        assert_eq!(scores[&b], 1);
        assert_eq!(scores[&c], 2);
        assert_eq!(scores[&d], 4);

        assert_eq!(first_hop[&b], (b, 1));
        assert_eq!(first_hop[&c], (b, 2));
        assert_eq!(first_hop[&d], (b, 3));
    }

    #[test]
    fn test_dijkstra_with_first_hop() {
        let mut graph = DiGraph::<&str, u32>::new();
        let a = graph.add_node("a");
        let b = graph.add_node("b");
        let c = graph.add_node("c");
        let d = graph.add_node("d");
        let e = graph.add_node("e");

        graph.extend_with_edges([(a, b, 1), (a, c, 2), (b, d, 1), (c, d, 3), (d, e, 1)]);

        let (scores, first_hop) = dijkstra_with_first_hop(&graph, a, |edge| *edge.weight());

        assert_eq!(scores[&b], 1);
        assert_eq!(scores[&c], 2);
        assert_eq!(scores[&d], 2);
        assert_eq!(scores[&e], 3);

        assert_eq!(first_hop[&b], (b, 1));
        assert_eq!(first_hop[&c], (c, 1));
        assert_eq!(first_hop[&d], (b, 2)); // d is reached via b
        assert_eq!(first_hop[&e], (b, 3)); // e is reached via d
    }

    #[test]
    fn test_dijkstra_with_first_hop_and_constraints() {
        use easytier_attrs::{Constraint, GSO_CAPABLE, TUNNEL_TYPE, TunnelKind, Value};

        let mut graph = DiGraph::<&str, (u32, TunnelKind)>::new();
        let a = graph.add_node("a");
        let b = graph.add_node("b");
        let c = graph.add_node("c");
        let d = graph.add_node("d");

        // Path 1: a -> b -> d: cost 1 + 1 = 2, but b -> d is UDP!
        graph.add_edge(a, b, (1, TunnelKind::Tcp));
        graph.add_edge(b, d, (1, TunnelKind::Udp));

        // Path 2: a -> c -> d: cost 2 + 2 = 4, both are TCP!
        graph.add_edge(a, c, (2, TunnelKind::Tcp));
        graph.add_edge(c, d, (2, TunnelKind::Tcp));

        let tracked = [TUNNEL_TYPE.clone(), GSO_CAPABLE.clone()];

        let node_attrs = |_n| {
            let mut s = AttrSet::new();
            s.set_decl(&GSO_CAPABLE, Value::Flag(true));
            s
        };

        let (scores, first_hop) = dijkstra_with_first_hop_and_constraints(
            &graph,
            a,
            |e| e.weight().0,
            |e| {
                let mut s = AttrSet::new();
                s.set_decl(&TUNNEL_TYPE, Value::Enum(e.weight().1 as u16));
                s
            },
            node_attrs,
            &tracked,
        );

        // Unconstrained: d should be reached via b with cost 2
        let unconstrained = ConstraintState::unconstrained();
        assert_eq!(scores[&(d, unconstrained.clone())], 2);
        assert_eq!(first_hop[&(d, unconstrained)].0, b);

        // Constrained (TCP + GSO):
        let req = [
            Constraint::new(&TUNNEL_TYPE, Value::Enum(TunnelKind::Tcp as u16)),
            Constraint::new(&GSO_CAPABLE, Value::Flag(true)),
        ];

        let tcp_d = scores
            .iter()
            .find(|((n, s), _)| *n == d && s.satisfies_requirement(&req));
        assert!(tcp_d.is_some());
        let ((_, state), &cost) = tcp_d.unwrap();
        // Path a -> c -> d has cost 4
        assert_eq!(cost, 4);
        assert_eq!(first_hop[&(d, state.clone())].0, c);
    }
}
