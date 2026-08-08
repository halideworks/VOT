//! Writes the whole commit transition relation, one row per (machine, event).
//!
//! Run with `cargo run -p vot-commit-model --bin vot-commit-transitions`.
//! `tools/validate_commit_fixtures.py` reimplements the relation from
//! `spec/commit.md` and checks every row it prints, so agreement between the
//! two is evidence rather than a tautology.

fn main() {
    let rows = vot_commit_model::transition_corpus();
    println!("{{");
    println!("  \"rows\": [");
    for (index, row) in rows.iter().enumerate() {
        let comma = if index + 1 == rows.len() { "" } else { "," };
        println!("    {row}{comma}");
    }
    println!("  ]");
    println!("}}");
}
