use iref::IriBuf;
use linked_data::{
	to_lexical_quads, to_lexical_subject_quads, LinkedData, LinkedDataGraph, LinkedDataResource,
	LinkedDataSubject, RdfQuad, ResourceInterpretation, SubjectVisitor, Visitor,
};
use rdf_types::{
	dataset::{DatasetGraphView, DatasetView, IndexedBTreeDataset},
	generator, Id, Interpretation, Quad, Term, Vocabulary,
};

const EDGE: &str = "https://example.com/edge";

struct DefaultGraph<T>(T);

struct IdentifiedSubject<R, T>(R, T);

impl<I, V, T> LinkedData<I, V> for DefaultGraph<T>
where
	I: Interpretation,
	V: Vocabulary,
	T: LinkedDataGraph<I, V>,
{
	fn visit<S>(&self, mut visitor: S) -> Result<S::Ok, S::Error>
	where
		S: Visitor<I, V>,
	{
		visitor.default_graph(&self.0)?;
		visitor.end()
	}
}

impl<I, V, R, T> LinkedDataResource<I, V> for IdentifiedSubject<R, T>
where
	I: Interpretation,
	V: Vocabulary,
	R: LinkedDataResource<I, V>,
{
	fn interpretation(
		&self,
		vocabulary: &mut V,
		interpretation: &mut I,
	) -> ResourceInterpretation<'_, I, V> {
		self.0.interpretation(vocabulary, interpretation)
	}
}

impl<I, V, R, T> LinkedDataSubject<I, V> for IdentifiedSubject<R, T>
where
	I: Interpretation,
	V: Vocabulary,
	T: LinkedDataSubject<I, V>,
{
	fn visit_subject<S>(&self, visitor: S) -> Result<S::Ok, S::Error>
	where
		S: SubjectVisitor<I, V>,
	{
		self.1.visit_subject(visitor)
	}
}

fn iri(value: impl Into<String>) -> IriBuf {
	IriBuf::new(value.into()).expect("test IRIs are valid")
}

fn id(value: impl Into<String>) -> Id {
	Id::Iri(iri(value))
}

fn resource(value: impl Into<String>) -> Term {
	Term::Id(id(value))
}

fn dataset_quad(subject: &str, predicate: &str, object: &str, graph: Option<&str>) -> Quad {
	Quad(
		resource(subject),
		resource(predicate),
		resource(object),
		graph.map(resource),
	)
}

fn lexical_quad(subject: &str, predicate: &str, object: &str, graph: Option<&str>) -> RdfQuad {
	Quad(
		id(subject),
		iri(predicate),
		Term::Id(id(object)),
		graph.map(id),
	)
}

#[test]
fn dataset_view_terminates_named_graph_cycle_in_stable_order() {
	const ROOT: &str = "https://example.com/root";
	const GRAPH_A: &str = "https://example.com/graph-a";
	const GRAPH_B: &str = "https://example.com/graph-b";
	const NODE_A: &str = "https://example.com/node-a";
	const NODE_B: &str = "https://example.com/node-b";

	let mut dataset = IndexedBTreeDataset::new();
	dataset.insert(dataset_quad(ROOT, EDGE, GRAPH_A, None));
	dataset.insert(dataset_quad(NODE_A, EDGE, GRAPH_B, Some(GRAPH_A)));
	dataset.insert(dataset_quad(NODE_B, EDGE, GRAPH_A, Some(GRAPH_B)));

	let view = DatasetView {
		dataset: &dataset,
		graph: None,
	};
	let quads = to_lexical_quads(generator::Blank::new(), &DefaultGraph(view))
		.expect("cyclic named graphs must terminate");

	assert_eq!(
		quads,
		vec![
			lexical_quad(NODE_B, EDGE, GRAPH_A, Some(GRAPH_B)),
			lexical_quad(NODE_A, EDGE, GRAPH_B, Some(GRAPH_A)),
			lexical_quad(ROOT, EDGE, GRAPH_A, None),
		]
	);
}

#[test]
fn dataset_graph_view_terminates_self_cycle_in_stable_order() {
	const ROOT: &str = "https://example.com/root";
	const SEED: &str = "https://example.com/seed";

	let mut dataset = IndexedBTreeDataset::new();
	// Seed `ROOT` so the indexed dataset reuses one resource slot when it is
	// both the subject and object of the following quad.
	dataset.insert(dataset_quad(SEED, EDGE, ROOT, None));
	dataset.insert(dataset_quad(ROOT, EDGE, ROOT, None));

	let root = resource(ROOT);
	let view = DatasetGraphView {
		dataset: &dataset,
		graph: None,
		resource: &root,
	};
	let subject_view = IdentifiedSubject(&root, view);
	let (subject, quads) = to_lexical_subject_quads(generator::Blank::new(), None, &subject_view)
		.expect("a subject self-cycle must terminate");

	assert_eq!(subject, id(ROOT));
	assert_eq!(quads, vec![lexical_quad(ROOT, EDGE, ROOT, None)]);
}

#[test]
fn dataset_graph_view_terminates_two_subject_cycle_in_stable_postorder() {
	const NODE_A: &str = "https://example.com/node-a";
	const NODE_B: &str = "https://example.com/node-b";

	let mut dataset = IndexedBTreeDataset::new();
	dataset.insert(dataset_quad(NODE_A, EDGE, NODE_B, None));
	dataset.insert(dataset_quad(NODE_B, EDGE, NODE_A, None));

	let root = resource(NODE_A);
	let view = DatasetGraphView {
		dataset: &dataset,
		graph: None,
		resource: &root,
	};
	let subject_view = IdentifiedSubject(&root, view);
	let (subject, quads) = to_lexical_subject_quads(generator::Blank::new(), None, &subject_view)
		.expect("a two-subject cycle must terminate");

	assert_eq!(subject, id(NODE_A));
	assert_eq!(
		quads,
		vec![
			lexical_quad(NODE_B, EDGE, NODE_A, None),
			lexical_quad(NODE_A, EDGE, NODE_B, None),
		]
	);
}

#[test]
fn dataset_graph_view_revisits_shared_subject_per_path_in_stable_order() {
	const ROOT: &str = "https://example.com/root";
	const LEFT: &str = "https://example.com/left";
	const RIGHT: &str = "https://example.com/right";
	const SHARED: &str = "https://example.com/shared";
	const LEAF: &str = "https://example.com/leaf";
	const LEFT_EDGE: &str = "https://example.com/edge-a-left";
	const RIGHT_EDGE: &str = "https://example.com/edge-b-right";

	let mut dataset = IndexedBTreeDataset::new();
	dataset.insert(dataset_quad(ROOT, LEFT_EDGE, LEFT, None));
	dataset.insert(dataset_quad(ROOT, RIGHT_EDGE, RIGHT, None));
	dataset.insert(dataset_quad(LEFT, EDGE, SHARED, None));
	dataset.insert(dataset_quad(RIGHT, EDGE, SHARED, None));
	dataset.insert(dataset_quad(SHARED, EDGE, LEAF, None));

	let root = resource(ROOT);
	let view = DatasetGraphView {
		dataset: &dataset,
		graph: None,
		resource: &root,
	};
	let subject_view = IdentifiedSubject(&root, view);
	let (subject, quads) = to_lexical_subject_quads(generator::Blank::new(), None, &subject_view)
		.expect("repeated subjects must terminate");

	assert_eq!(subject, id(ROOT));
	assert_eq!(
		quads,
		vec![
			lexical_quad(SHARED, EDGE, LEAF, None),
			lexical_quad(LEFT, EDGE, SHARED, None),
			lexical_quad(ROOT, LEFT_EDGE, LEFT, None),
			lexical_quad(SHARED, EDGE, LEAF, None),
			lexical_quad(RIGHT, EDGE, SHARED, None),
			lexical_quad(ROOT, RIGHT_EDGE, RIGHT, None),
		]
	);
}

#[test]
fn dataset_graph_view_preserves_deep_postorder_traversal() {
	const DEPTH: usize = 2_048;
	const STACK_SIZE: usize = 16 * 1024 * 1024;

	std::thread::Builder::new()
		.name("deep-dataset-graph-view".into())
		.stack_size(STACK_SIZE)
		.spawn(|| {
			fn node(index: usize) -> String {
				format!("https://example.com/node/{index:04}")
			}

			let mut dataset = IndexedBTreeDataset::new();
			for index in 0..DEPTH {
				dataset.insert(dataset_quad(&node(index), EDGE, &node(index + 1), None));
			}

			let root = resource(node(0));
			let view = DatasetGraphView {
				dataset: &dataset,
				graph: None,
				resource: &root,
			};
			let subject_view = IdentifiedSubject(&root, view);
			let (_, quads) = to_lexical_subject_quads(generator::Blank::new(), None, &subject_view)
				.expect("deep acyclic traversal must succeed");
			let expected: Vec<_> = (0..DEPTH)
				.rev()
				.map(|index| lexical_quad(&node(index), EDGE, &node(index + 1), None))
				.collect();

			assert_eq!(quads, expected);
		})
		.expect("deep traversal test thread must start")
		.join()
		.expect("deep traversal test thread must not panic");
}

#[test]
#[ignore = "manual bounded performance comparison"]
fn benchmark_deep_and_cyclic_traversal() {
	const DEPTH: usize = 256;
	const DEEP_ITERATIONS: u32 = 100;
	const CYCLIC_ITERATIONS: u32 = 1_000;

	fn node(index: usize) -> String {
		format!("https://example.com/bench/node/{index:04}")
	}

	let mut deep_dataset = IndexedBTreeDataset::new();
	for index in 0..DEPTH {
		deep_dataset.insert(dataset_quad(&node(index), EDGE, &node(index + 1), None));
	}
	let root = resource(node(0));
	let deep_view = IdentifiedSubject(
		&root,
		DatasetGraphView {
			dataset: &deep_dataset,
			graph: None,
			resource: &root,
		},
	);
	let started = std::time::Instant::now();
	for _ in 0..DEEP_ITERATIONS {
		let (_, quads) = to_lexical_subject_quads(generator::Blank::new(), None, &deep_view)
			.expect("deep benchmark traversal must succeed");
		assert_eq!(quads.len(), DEPTH);
		std::hint::black_box(quads);
	}
	let deep_elapsed = started.elapsed();

	const ROOT: &str = "https://example.com/bench/root";
	const GRAPH_A: &str = "https://example.com/bench/graph-a";
	const GRAPH_B: &str = "https://example.com/bench/graph-b";
	let mut cyclic_dataset = IndexedBTreeDataset::new();
	cyclic_dataset.insert(dataset_quad(ROOT, EDGE, GRAPH_A, None));
	cyclic_dataset.insert(dataset_quad(
		"https://example.com/bench/node-a",
		EDGE,
		GRAPH_B,
		Some(GRAPH_A),
	));
	cyclic_dataset.insert(dataset_quad(
		"https://example.com/bench/node-b",
		EDGE,
		GRAPH_A,
		Some(GRAPH_B),
	));
	let cyclic_view = DefaultGraph(DatasetView {
		dataset: &cyclic_dataset,
		graph: None,
	});
	let started = std::time::Instant::now();
	for _ in 0..CYCLIC_ITERATIONS {
		let quads = to_lexical_quads(generator::Blank::new(), &cyclic_view)
			.expect("cyclic benchmark traversal must succeed");
		assert_eq!(quads.len(), 3);
		std::hint::black_box(quads);
	}
	let cyclic_elapsed = started.elapsed();

	println!(
		"deep: depth={DEPTH}, iterations={DEEP_ITERATIONS}, total={deep_elapsed:?}, ns/iteration={}; cyclic: iterations={CYCLIC_ITERATIONS}, total={cyclic_elapsed:?}, ns/iteration={}",
		deep_elapsed.as_nanos() / u128::from(DEEP_ITERATIONS),
		cyclic_elapsed.as_nanos() / u128::from(CYCLIC_ITERATIONS),
	);
}
