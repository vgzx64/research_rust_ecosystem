use sea_orm::DbConn;

/// Application state containing database connection (must be Clone for Axum)
#[derive(Clone)]
pub struct AppState {
    pub db: DbConn,
}

/// Type alias for shared application state
pub type SharedState = AppState;

/// Create new shared application state
pub fn create_state(db: DbConn) -> SharedState {
    AppState { db }
}
