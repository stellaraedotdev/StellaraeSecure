// Database module for staffdb
// Provides repository abstraction layer, enabling SQLite now and PostgreSQL later

pub mod migrations;
pub mod pool;
pub mod repository;

pub use pool::{create_pool, health_check, DbPool};
pub use repository::{
	AccountRepository,
	AuditLogRepository,
	RbacRepository,
	RoleRepository,
	SqliteAccountRepository,
	SqliteAuditLogRepository,
	SqliteRbacRepository,
	SqliteRoleRepository,
};
