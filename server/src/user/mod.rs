mod auth;

pub mod user {
    use uuid::Uuid;

    pub struct User {
        pub id: Uuid,
        pub username: String,
        pub name: String,
        /// Manually-created users don't need an email address, but it's always nice to have one.
        pub email: Option<String>,
    }

    impl User {
        pub fn new(username: String, name: String, email: Option<String>) -> User {
            User {
                id: Uuid::now_v7(),
                username,
                name,
                email
            }
        }
    }
}
