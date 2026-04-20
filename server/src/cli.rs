use clap::{Parser, Subcommand};
use sqlx::SqlitePool;
use tracing::info;

use crate::db::DbEntity;
use crate::errors::AppError;
use crate::role::{Role, ROLE_ADMIN};
use crate::user::auth::Authenticator;
use crate::user::User;

#[derive(Parser)]
#[command(name = "authere")]
#[command(about = "Lightweight authentication and authorization service")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Start the HTTP server (default if no command specified)
    Serve,

    /// Initialize the first admin user
    InitAdmin {
        /// Admin username
        #[arg(short, long)]
        username: String,

        /// Admin password (will prompt if not provided)
        #[arg(short, long)]
        password: Option<String>,

        /// Admin display name
        #[arg(short, long, default_value = "Administrator")]
        name: String,

        /// Admin email (optional)
        #[arg(short, long)]
        email: Option<String>,
    },
}

/// Initialize the admin user
pub async fn init_admin(
    pool: &SqlitePool,
    username: String,
    password: String,
    name: String,
    email: Option<String>,
) -> Result<(), AppError> {
    if let Err(e) = User::validate_username(&username) {
        return Err(AppError::InputError(vec![e]));
    }
    if let Err(e) = User::validate_name(&name) {
        return Err(AppError::InputError(vec![e]));
    }
    if let Err(e) = Authenticator::validate_password(&password) {
        return Err(AppError::InputError(vec![e]));
    }
    if let Err(e) = User::validate_email(&email) {
        return Err(AppError::InputError(vec![e]));
    }

    let mut conn = pool.acquire().await?;

    let existing_admins = sqlx::query_scalar!(
        r#"SELECT COUNT(*) as count FROM user_roles ur
           INNER JOIN roles r ON ur.role_id = r.id
           WHERE r.name = 'admin'"#
    )
    .fetch_one(&mut *conn)
    .await?;

    if existing_admins > 0 {
        return Err(AppError::UniqueError(
            "An admin user already exists. Use the web portal to manage admins.".to_string(),
        ));
    }

    let admin_role = Role::get_by_name(ROLE_ADMIN, &mut conn)
        .await?
        .ok_or_else(|| AppError::InternalError("Admin role not found in database".to_string()))?;

    let user = User::new(username.clone(), name, email);
    let authenticator = Authenticator::new_password(password, user.id).map_err(|e| {
        AppError::InternalError(format!(
            "Failed to create Authenticator for user {user:?} ({e})"
        ))
    })?;

    let mut tx = pool.begin().await?;
    user.save(&mut tx).await?;
    authenticator.save(&mut tx).await?;

    sqlx::query!(
        "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)",
        user.id,
        admin_role.id
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    info!(username = %username, user_id = %user.id, "admin user created via CLI");

    Ok(())
}

/// Prompt for password if not provided
pub fn prompt_password() -> Result<String, std::io::Error> {
    use std::io::{self, Write};

    print!("Enter admin password: ");
    io::stdout().flush()?;

    let mut password = String::new();
    io::stdin().read_line(&mut password)?;
    let password = password.trim().to_string();

    if password.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Password cannot be empty",
        ));
    }

    Ok(password)
}
