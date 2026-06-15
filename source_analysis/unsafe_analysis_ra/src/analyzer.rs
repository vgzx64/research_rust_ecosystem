use anyhow::Result;
use hir::{Crate, Function, HasSource, Module, ModuleDef, Trait};
use hir_expand::HirFileId;
use ide_db::RootDatabase;
use ide_db::base_db::SourceDatabase;
use span::TextSize;
use syntax::{AstNode, ast};
use vfs::{FileId, Vfs};

/// Represents a function found during analysis
#[derive(Debug, Clone, serde::Serialize)]
pub struct FunctionInfo {
    pub name: String,
    pub node_id: String,
    pub header_span: String,
    pub body_span: String,
    pub unsafety: bool,
}

/// Represents an unsafe block found within a function body
#[derive(Debug, Clone, serde::Serialize)]
pub struct BlockInfo {
    pub fn_id: String,
    pub block_span: String,
    pub unsafety: bool,
}

/// Represents an unsafe trait or trait impl
#[derive(Debug, Clone, serde::Serialize)]
pub struct UnsafeItemInfo {
    pub name: String,
    pub safe: bool,
    pub loc: String,
}

/// Complete analysis result
pub struct AnalysisResult {
    pub functions: Vec<FunctionInfo>,
    pub blocks: Vec<Vec<BlockInfo>>,
    pub unsafe_traits: Vec<UnsafeItemInfo>,
    pub unsafe_trait_impls: Vec<UnsafeItemInfo>,
    pub safe_fn_count: i32,
    pub unsafe_fn_count: i32,
    pub unsafe_block_count: i32,
    pub safe_block_count: i32,
}

/// Convert HirFileId to a raw FileId
fn hir_file_to_file_id<'a>(db: &'a RootDatabase, hir_file_id: HirFileId) -> Option<FileId> {
    match hir_file_id {
        HirFileId::FileId(editioned) => Some(editioned.file_id(db)),
        _ => None,
    }
}

/// Main analysis function - walks the HIR to find all unsafe items
pub fn analyze(db: &RootDatabase, vfs: &Vfs) -> Result<AnalysisResult> {
    let mut result = AnalysisResult {
        functions: Vec::new(),
        blocks: Vec::new(),
        unsafe_traits: Vec::new(),
        unsafe_trait_impls: Vec::new(),
        safe_fn_count: 0,
        unsafe_fn_count: 0,
        unsafe_block_count: 0,
        safe_block_count: 0,
    };

    // Get all crates in the workspace
    let crates = hir::Crate::all(db);

    for krate in crates {
        analyze_crate(db, vfs, krate, &mut result)?;
    }

    Ok(result)
}

/// Analyze a single crate
fn analyze_crate(
    db: &RootDatabase,
    vfs: &Vfs,
    krate: Crate,
    result: &mut AnalysisResult,
) -> Result<()> {
    let modules = krate.modules(db);

    for module in modules {
        analyze_module(db, vfs, module, result)?;
    }

    // Analyze unsafe trait impls for this crate
    let impls = hir::Impl::all_in_crate(db, krate);
    for impl_ in impls {
        analyze_impl(db, vfs, impl_, result)?;
    }

    Ok(())
}

/// Analyze a single module
fn analyze_module(
    db: &RootDatabase,
    vfs: &Vfs,
    module: Module,
    result: &mut AnalysisResult,
) -> Result<()> {
    let declarations = module.declarations(db);

    for decl in declarations {
        match decl {
            ModuleDef::Function(func) => {
                analyze_function(db, vfs, func, result)?;
            }
            ModuleDef::Trait(trait_) => {
                analyze_trait(db, vfs, trait_, result)?;
            }
            // Other item types are not relevant for unsafe analysis
            _ => {}
        }
    }

    Ok(())
}

/// Analyze a single function
fn analyze_function(
    db: &RootDatabase,
    vfs: &Vfs,
    func: Function,
    result: &mut AnalysisResult,
) -> Result<()> {
    let is_unsafe = func.is_unsafe(db);
    let name = func.name(db).display(db, span::Edition::Edition2021).to_string();
    let module = func.module(db);
    let module_name = module.name(db).map(|n| n.display(db, span::Edition::Edition2021).to_string()).unwrap_or_default();

    // Get source location for the function
    let (header_span, body_span) = get_function_spans(db, vfs, func)?;

    // Skip functions without valid source locations (e.g., from macros in external crates)
    if header_span.is_empty() {
        return Ok(());
    }

    // Skip functions from .cargo/ or rustc/ paths (dependencies)
    if header_span.contains("/.cargo/") || header_span.contains("/rustc/") {
        return Ok(());
    }

    let node_id = format!("{}::{}", module_name, name);

    if is_unsafe {
        result.unsafe_fn_count += 1;
    } else {
        result.safe_fn_count += 1;
    }

    result.functions.push(FunctionInfo {
        name,
        node_id,
        header_span,
        body_span,
        unsafety: is_unsafe,
    });

    // Find unsafe blocks within this function body
    let unsafe_blocks = find_unsafe_blocks_in_function(db, vfs, func)?;
    if !unsafe_blocks.is_empty() {
        for block in &unsafe_blocks {
            if block.unsafety {
                result.unsafe_block_count += 1;
            } else {
                result.safe_block_count += 1;
            }
        }
        result.blocks.push(unsafe_blocks);
    }

    Ok(())
}

/// Get the header and body spans of a function
fn get_function_spans(
    db: &RootDatabase,
    vfs: &Vfs,
    func: Function,
) -> Result<(String, String)> {
    let source = func.source(db);

    match source {
        Some(in_file) => {
            let hir_file_id = in_file.file_id;
            let file_id_raw = match hir_file_to_file_id(db, hir_file_id) {
                Some(id) => id,
                None => return Ok((String::new(), String::new())),
            };
            let ast_fn = in_file.value;

            // Get file path from file ID
            let file_path = get_file_path(vfs, file_id_raw);

            // Get the text range of the function signature (header)
            let header_range = ast_fn.syntax().text_range();
            let header_start = header_range.start();
            let header_end = header_range.end();

            // Convert byte offsets to line numbers
            let header_start_line = byte_offset_to_line(db, file_id_raw, header_start);
            let header_end_line = byte_offset_to_line(db, file_id_raw, header_end);

            // Get the body span
            let body_span = if let Some(body) = ast_fn.body() {
                let body_range = body.syntax().text_range();
                let body_start_line = byte_offset_to_line(db, file_id_raw, body_range.start());
                let body_end_line = byte_offset_to_line(db, file_id_raw, body_range.end());
                format!("{}: {}-{}", file_path, body_start_line, body_end_line)
            } else {
                format!("{}: {}-{}", file_path, header_start_line, header_end_line)
            };

            let header_span = format!("{}: {}-{}", file_path, header_start_line, header_end_line);

            Ok((header_span, body_span))
        }
        None => Ok((String::new(), String::new())),
    }
}

/// Find unsafe blocks within a function body
fn find_unsafe_blocks_in_function(
    db: &RootDatabase,
    vfs: &Vfs,
    func: Function,
) -> Result<Vec<BlockInfo>> {
    let mut blocks = Vec::new();

    let source = func.source(db);
    if let Some(in_file) = source {
        let hir_file_id = in_file.file_id;
        let file_id_raw = match hir_file_to_file_id(db, hir_file_id) {
            Some(id) => id,
            None => return Ok(blocks),
        };
        let ast_fn = in_file.value;
        let fn_name = func.name(db).display(db, span::Edition::Edition2021).to_string();
        let module = func.module(db);
        let module_name = module.name(db).map(|n| n.display(db, span::Edition::Edition2021).to_string()).unwrap_or_default();
        let fn_id = format!("{}::{}", module_name, fn_name);

        // Walk the function body looking for unsafe blocks
        if let Some(body) = ast_fn.body() {
            find_unsafe_blocks_recursive(db, vfs, file_id_raw, &body.syntax(), &fn_id, &mut blocks)?;
        }
    }

    Ok(blocks)
}

/// Recursively walk AST nodes looking for unsafe blocks
fn find_unsafe_blocks_recursive(
    db: &RootDatabase,
    vfs: &Vfs,
    file_id: FileId,
    node: &syntax::SyntaxNode,
    fn_id: &str,
    blocks: &mut Vec<BlockInfo>,
) -> Result<()> {
    // Check if this node is a block expression with unsafe
    if let Some(block_expr) = ast::BlockExpr::cast(node.clone()) {
        if block_expr.unsafe_token().is_some() {
            let file_path = get_file_path(vfs, file_id);
            let range = block_expr.syntax().text_range();
            let start_line = byte_offset_to_line(db, file_id, range.start());
            let end_line = byte_offset_to_line(db, file_id, range.end());
            let block_span = format!("{}: {}-{}", file_path, start_line, end_line);

            blocks.push(BlockInfo {
                fn_id: fn_id.to_string(),
                block_span,
                unsafety: true,
            });
        }
    }

    // Recurse into children
    for child in node.children() {
        find_unsafe_blocks_recursive(db, vfs, file_id, &child, fn_id, blocks)?;
    }

    Ok(())
}

/// Analyze a trait for unsafety
fn analyze_trait(
    db: &RootDatabase,
    vfs: &Vfs,
    trait_: Trait,
    result: &mut AnalysisResult,
) -> Result<()> {
    let is_unsafe = trait_.is_unsafe(db);
    let name = trait_.name(db).display(db, span::Edition::Edition2021).to_string();

    // Get source location
    let source = trait_.source(db);
    let loc = match source {
        Some(in_file) => {
            let hir_file_id = in_file.file_id;
            let file_id_raw = match hir_file_to_file_id(db, hir_file_id) {
                Some(id) => id,
                None => return Ok(()),
            };
            let file_path = get_file_path(vfs, file_id_raw);
            let range = in_file.value.syntax().text_range();
            let start_line = byte_offset_to_line(db, file_id_raw, range.start());
            let end_line = byte_offset_to_line(db, file_id_raw, range.end());
            format!("file: \"{}\" line \"{}-{}\"", file_path, start_line, end_line)
        }
        None => return Ok(()),
    };

    // Skip external crate items
    if loc.contains("/.cargo/") || loc.contains("/rustc/") {
        return Ok(());
    }

    result.unsafe_traits.push(UnsafeItemInfo {
        name,
        safe: !is_unsafe,
        loc,
    });

    Ok(())
}

/// Analyze an impl block for unsafe trait implementations
fn analyze_impl(
    db: &RootDatabase,
    vfs: &Vfs,
    impl_: hir::Impl,
    result: &mut AnalysisResult,
) -> Result<()> {
    let source = impl_.source(db);
    let ast_impl = match source {
        Some(in_file) => in_file,
        None => return Ok(()),
    };

    let hir_file_id = ast_impl.file_id;
    let file_id_raw = match hir_file_to_file_id(db, hir_file_id) {
        Some(id) => id,
        None => return Ok(()),
    };
    let impl_ast = ast_impl.value;

    // Check if the impl is for an unsafe trait
    let is_unsafe_trait_impl = impl_ast.trait_().is_some() && impl_ast.unsafe_token().is_some();

    if !is_unsafe_trait_impl {
        return Ok(());
    }

    // Get the trait name from the impl's text representation
    let impl_text = impl_ast.syntax().text().to_string();
    let trait_name = impl_text
        .lines()
        .find(|line| line.contains("impl") && line.contains("for"))
        .and_then(|line| {
            let parts: Vec<&str> = line.splitn(3, ' ').collect();
            if parts.len() >= 3 {
                // Format: "unsafe impl TraitName for Type"
                // or: "impl TraitName for Type"
                let after_impl = if parts[0] == "unsafe" { &parts[1..] } else { &parts[..] };
                if after_impl.len() >= 2 && after_impl[0] == "impl" {
                    Some(after_impl[1].to_string())
                } else {
                    None
                }
            } else {
                None
            }
        })
        .unwrap_or_default();

    let file_path = get_file_path(vfs, file_id_raw);
    let range = impl_ast.syntax().text_range();
    let start_line = byte_offset_to_line(db, file_id_raw, range.start());
    let end_line = byte_offset_to_line(db, file_id_raw, range.end());
    let loc = format!("file: \"{}\" line \"{}-{}\"", file_path, start_line, end_line);

    // Skip external crate items
    if loc.contains("/.cargo/") || loc.contains("/rustc/") {
        return Ok(());
    }

    result.unsafe_trait_impls.push(UnsafeItemInfo {
        name: trait_name,
        safe: false,
        loc,
    });

    Ok(())
}

/// Get the file path from a file ID
fn get_file_path(vfs: &Vfs, file_id: FileId) -> String {
    let vfs_path = vfs.file_path(file_id);

    if let Some(abs_path) = vfs_path.as_path() {
        abs_path.to_string()
    } else {
        format!("virtual:{}", file_id.index())
    }
}

/// Convert a byte offset to a 1-based line number
fn byte_offset_to_line(
    db: &RootDatabase,
    file_id: FileId,
    offset: TextSize,
) -> u32 {
    match db.line_column(file_id, offset) {
        Ok((line, _col)) => (line + 1) as u32,
        Err(_) => 1,
    }
}
