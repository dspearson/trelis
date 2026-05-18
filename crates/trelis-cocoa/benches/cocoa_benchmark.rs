//! Benchmarks for trelis-cocoa optimisation targets.
//!
//! Run with: `cargo bench -p trelis-cocoa`

// Internal benchmarks; pedantic warnings have no value here and are silenced
// wholesale.
#![allow(clippy::pedantic, missing_docs)]

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

use trelis_cocoa::tree::{NodeIndex, NodeState, PartialTreeView, Resolution, TreeNode};

/// Benchmark Resolution union operation.
///
/// This is currently O(n^2) due to Vec::contains() check.
/// Target: use HashSet for O(n) union.
fn bench_resolution_union(c: &mut Criterion) {
    let mut group = c.benchmark_group("resolution_union");

    for size in [2, 4, 8, 16, 32, 64] {
        // Create two resolutions of equal size
        let res1: Resolution = (0..size).fold(Resolution::empty(), |acc, i| {
            acc.union(Resolution::singleton(NodeIndex::new(4, i)))
        });

        let res2: Resolution = (size..(size * 2)).fold(Resolution::empty(), |acc, i| {
            acc.union(Resolution::singleton(NodeIndex::new(4, i)))
        });

        group.bench_with_input(
            BenchmarkId::new("disjoint", size),
            &(res1.clone(), res2.clone()),
            |b, (r1, r2)| {
                b.iter(|| {
                    let result = r1.clone().union(r2.clone());
                    black_box(result)
                })
            },
        );

        // Test with overlapping sets (worst case for dedup)
        let res3: Resolution = (0..size).fold(Resolution::empty(), |acc, i| {
            acc.union(Resolution::singleton(NodeIndex::new(4, i)))
        });

        group.bench_with_input(
            BenchmarkId::new("identical", size),
            &(res1.clone(), res3),
            |b, (r1, r3)| {
                b.iter(|| {
                    let result = r1.clone().union(r3.clone());
                    black_box(result)
                })
            },
        );
    }

    group.finish();
}

/// Benchmark Resolution singleton creation.
fn bench_resolution_singleton(c: &mut Criterion) {
    let idx = NodeIndex::new(4, 7);

    c.bench_function("resolution_singleton", |b| {
        b.iter(|| {
            let res = Resolution::singleton(black_box(idx));
            black_box(res)
        })
    });
}

/// Benchmark PartialTreeView operations.
///
/// Currently uses BTreeMap for node storage.
/// Target: consider HashMap for O(1) average lookup.
fn bench_tree_view_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("tree_view");

    for depth in [4, 6, 8, 10] {
        // Create a tree view with some nodes
        let mut view = PartialTreeView::new(0, depth);

        // Insert nodes along a path
        for d in 0..=depth {
            let node = TreeNode::new_blank(NodeIndex::new(d, 0));
            view.insert(node);
        }

        let existing_idx = NodeIndex::new(depth / 2, 0);
        let missing_idx = NodeIndex::new(depth, 100);

        group.bench_with_input(
            BenchmarkId::new("get_existing", depth),
            &existing_idx,
            |b, idx| {
                b.iter(|| {
                    let result = view.get(black_box(idx));
                    black_box(result)
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("get_missing", depth),
            &missing_idx,
            |b, idx| {
                b.iter(|| {
                    let result = view.get(black_box(idx));
                    black_box(result)
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("contains", depth),
            &existing_idx,
            |b, idx| {
                b.iter(|| {
                    let result = view.contains(black_box(idx));
                    black_box(result)
                })
            },
        );
    }

    group.finish();
}

/// Benchmark tree view insert operation.
fn bench_tree_view_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("tree_view_insert");

    for depth in [4, 6, 8] {
        let mut view = PartialTreeView::new(0, depth);

        // Pre-populate with some nodes
        for d in 0..depth {
            let node = TreeNode::new_blank(NodeIndex::new(d, 0));
            view.insert(node);
        }

        group.bench_with_input(BenchmarkId::new("insert", depth), &depth, |b, &d| {
            let mut counter = 0u32;
            b.iter(|| {
                let node = TreeNode::new_blank(NodeIndex::new(d, counter));
                view.insert(black_box(node));
                counter = counter.wrapping_add(1);
            })
        });
    }

    group.finish();
}

/// Benchmark NodeIndex linear index conversion.
///
/// This is called on every tree operation for BTreeMap key lookup.
/// Target: cache linear index in TreeNode.
fn bench_node_index_linear(c: &mut Criterion) {
    let mut group = c.benchmark_group("node_index");

    for depth in [2, 4, 8, 16] {
        let idx = NodeIndex::new(depth, (1 << depth) - 1);

        group.bench_with_input(BenchmarkId::new("to_linear", depth), &idx, |b, idx| {
            b.iter(|| {
                let linear = idx.to_linear();
                black_box(linear)
            })
        });

        let linear = idx.to_linear();
        group.bench_with_input(
            BenchmarkId::new("from_linear", depth),
            &linear,
            |b, &lin| {
                b.iter(|| {
                    let idx = NodeIndex::from_linear(black_box(lin));
                    black_box(idx)
                })
            },
        );
    }

    group.finish();
}

/// Benchmark unmerged leaf operations.
///
/// Currently uses Vec::contains() which is O(n).
/// Target: use HashSet for O(1) lookup.
fn bench_unmerged_leaves(c: &mut Criterion) {
    let mut group = c.benchmark_group("unmerged_leaves");

    for count in [2u32, 4, 8, 16, 32] {
        let mut state = NodeState::blank();

        // Add some unmerged leaves (leaf positions, not user IDs)
        for i in 0..count {
            state.add_unmerged_leaf(i);
        }

        // Benchmark adding a new leaf (includes contains check)
        let new_leaf_pos: u32 = 0xFF;

        group.bench_with_input(
            BenchmarkId::new("add_new", count),
            &new_leaf_pos,
            |b, leaf_pos| {
                b.iter(|| {
                    let mut s = state.clone();
                    s.add_unmerged_leaf(black_box(*leaf_pos));
                    black_box(s)
                })
            },
        );

        // Benchmark adding a duplicate (worst case - must check all)
        let existing_leaf_pos: u32 = count - 1;

        group.bench_with_input(
            BenchmarkId::new("add_duplicate", count),
            &existing_leaf_pos,
            |b, leaf_pos| {
                b.iter(|| {
                    let mut s = state.clone();
                    s.add_unmerged_leaf(black_box(*leaf_pos));
                    black_box(s)
                })
            },
        );
    }

    group.finish();
}

/// Benchmark path computation.
fn bench_path_computation(c: &mut Criterion) {
    let mut group = c.benchmark_group("path");

    for depth in [4, 8, 12, 16] {
        let view = PartialTreeView::new(0, depth);

        group.bench_with_input(BenchmarkId::new("our_path", depth), &depth, |b, _| {
            b.iter(|| {
                let path = view.our_path();
                black_box(path)
            })
        });

        group.bench_with_input(BenchmarkId::new("our_copath", depth), &depth, |b, _| {
            b.iter(|| {
                let copath = view.our_copath();
                black_box(copath)
            })
        });
    }

    group.finish();
}

/// Benchmark depth_for_members computation.
fn bench_depth_for_members(c: &mut Criterion) {
    let mut group = c.benchmark_group("depth_for_members");

    for count in [8, 64, 256, 1024, 4096] {
        group.bench_with_input(BenchmarkId::new("compute", count), &count, |b, &n| {
            b.iter(|| {
                let depth = PartialTreeView::depth_for_members(black_box(n));
                black_box(depth)
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_resolution_union,
    bench_resolution_singleton,
    bench_tree_view_operations,
    bench_tree_view_insert,
    bench_node_index_linear,
    bench_unmerged_leaves,
    bench_path_computation,
    bench_depth_for_members,
);

criterion_main!(benches);
