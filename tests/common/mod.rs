use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;

pub async fn create_test_db() -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(2)
        .connect(":memory:")
        .await
        .expect("Failed to create test DB");

    let sql = include_str!("../../migrations/001_init.sql");
    sqlx::query(sql)
        .execute(&pool)
        .await
        .expect("Failed to run migrations");

    pool
}
