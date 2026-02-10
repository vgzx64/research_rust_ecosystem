use rustc_lint::LateContext;
use rustc_hir::intravisit::{Visitor, FnKind};
use rustc_hir::{FnDecl, BodyId};
use rustc_hir::def_id::DefId;
use rustc_hir::def_id::LocalDefId;
use rustc_middle::ty::TyCtxt;
use rustc_span::Span;

use decls::items::UnsafeItemInfo;
use crate::utils::{get_node_name, get_file_and_line};
use crate::items::UnsafeItem::{MyUnsafeTraitImpl, MyUnsafeTrait, MyUnsafeBlock, MyUnsafeFn};

pub enum UnsafeItem{
    MyUnsafeTraitImpl,
    MyUnsafeTrait,
    MyUnsafeBlock,
    MyUnsafeFn,
}

pub fn run_analysis(cx: & LateContext<'_>) -> ItemsAnalysis {
    let mut visitor = ItemVisitor::new(cx.tcx);
    cx.tcx.hir_walk_toplevel_module(&mut visitor);
    let mut unsafe_fn: Vec<UnsafeItemInfo> = Vec::new();
    for item in visitor.unsafe_fn {
        let node_name: String = get_node_name(cx.tcx, item.id);
        let file_and_line: String = get_file_and_line(&cx.tcx, item.span);
        unsafe_fn.push(UnsafeItemInfo::new(node_name, false, file_and_line));
    }
    for item in visitor.safe_fn {
        let node_name: String = get_node_name(cx.tcx, item.id);
        let file_and_line: String = get_file_and_line(&cx.tcx, item.span);
        unsafe_fn.push(UnsafeItemInfo::new(node_name, true, file_and_line));
    }
    ItemsAnalysis{
        unsafe_traits_impls: visitor.unsafe_traits_impls,
        unsafe_traits: visitor.unsafe_traits,
        unsafe_fn: unsafe_fn,
    }
}

pub struct ItemsAnalysis {
    pub unsafe_traits_impls: Vec<UnsafeItemInfo>,
    pub unsafe_traits: Vec<UnsafeItemInfo>,
    pub unsafe_fn: Vec<UnsafeItemInfo>,
}

struct ItemCompilerInfo{
    id: DefId,
    span: Span,
}
impl ItemCompilerInfo {
    pub fn new(id: DefId, span: Span) -> Self {
        ItemCompilerInfo { id, span }
    }
}

struct ItemVisitor<'tcx> {
    tcx: TyCtxt<'tcx>,
    unsafe_traits_impls: Vec<UnsafeItemInfo>,
    unsafe_traits: Vec<UnsafeItemInfo>,
    unsafe_fn: Vec<ItemCompilerInfo>,
    safe_fn: Vec<ItemCompilerInfo>,
    unsafe_block_num: i32,
    safe_block_num: i32, 
}

impl<'tcx> ItemVisitor<'tcx> {
    pub fn new(tcx: TyCtxt<'tcx>) -> Self {
        ItemVisitor {
            unsafe_traits_impls: Vec::new(),
            unsafe_traits: Vec::new(),
            safe_fn: Vec::new(),
            unsafe_fn: Vec::new(),
            unsafe_block_num: 0,
            safe_block_num: 0,
            tcx:tcx,
        }
    }

    pub fn add(&mut self, unsafe_item: UnsafeItem, id: DefId, span: Span, safety: bool){
        let node_name: String = get_node_name(self.tcx, id);
        let file_and_line: String = get_file_and_line(&self.tcx, span);
        match unsafe_item{
            MyUnsafeTraitImpl => {
                self.unsafe_traits_impls.push(UnsafeItemInfo::new(node_name, safety, file_and_line));
            }
            MyUnsafeTrait => {
                self.unsafe_traits.push(UnsafeItemInfo::new(node_name, safety, file_and_line));
            }
            MyUnsafeBlock => {
                if let Some(index) = self.safe_fn.iter().position(|info| (*info).id == id){
                    self.safe_fn.remove(index);
                }
                if let None = self.unsafe_fn.iter().position(|info| (*info).id == id){
                    self.unsafe_fn.push(ItemCompilerInfo::new(id, span));
                }
            }
            MyUnsafeFn => {
                if safety {
                    self.safe_fn.push(ItemCompilerInfo::new(id, span));
                }
                else{
                    self.unsafe_fn.push(ItemCompilerInfo::new(id, span));
                }
            }
        }
        
    }
}

impl<'tcx> Visitor<'tcx> for ItemVisitor<'tcx> {
    type NestedFilter = rustc_middle::hir::nested_filter::All;

    fn maybe_tcx(&mut self) -> Self::MaybeTyCtxt {
        self.tcx
    }

    fn visit_block(&mut self, b: &'tcx rustc_hir::Block<'tcx>) {
        match b.rules {
            rustc_hir::BlockCheckMode::DefaultBlock => self.safe_block_num += 1,
            rustc_hir::BlockCheckMode::UnsafeBlock(_) => {
                self.add(MyUnsafeBlock, b.hir_id.owner.to_def_id(), b.span, false);
                self.unsafe_block_num += 1;
            }
        }
        rustc_hir::intravisit::walk_block(self, b);
    }

    fn visit_item(&mut self, item: &'tcx rustc_hir::Item<'tcx>) {
        match &item.kind {
            // Handle unsafe trait impl
            rustc_hir::ItemKind::Impl(impl_item) => {
                if let Some(trait_impl_header) = impl_item.of_trait {
                    if trait_impl_header.safety.is_unsafe() {
                        self.add(
                            MyUnsafeTraitImpl,
                            item.owner_id.to_def_id(),
                            item.span,
                            false,
                        );
                    }
                }
            }
            // Handle unsafe trait definition
            rustc_hir::ItemKind::Trait(_, _, safety, _, _, _, _) => {
                if safety.is_unsafe() {
                    self.add(
                        MyUnsafeTrait,
                        item.owner_id.to_def_id(),
                        item.span,
                        false,
                    );
                }
            }
            _ => {}
        }
        
        rustc_hir::intravisit::walk_item(self, item);
    }

    fn visit_fn(&mut self, fk: FnKind<'tcx>, fd: &'tcx FnDecl<'tcx>, b: BodyId, s: Span, id: LocalDefId){
        let mut safety: bool = true;
        match fk {
            FnKind::ItemFn(_ident, _generics, header) => {
                if header.is_unsafe() {
                    safety = false;
                }
            }
            FnKind::Method(_ident, sig) => {
                if sig.header.is_unsafe() {
                    safety = false;
                }
            }
            FnKind::Closure => {
                // Do nothing
            }
        }
        // self.add(MyUnsafeFn, self.tcx.hir().local_def_id(id).to_def_id(), s, safety);
        self.add(MyUnsafeFn, id.to_def_id(), s, safety);
        rustc_hir::intravisit::walk_fn(self, fk, fd, b, id);
    }
}
