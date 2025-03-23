// Database schema definitions
diesel::table! {
    user_account (user_id) {
        user_id -> Int4,
        email -> Varchar,
        password_hash -> Varchar,
        first_name -> Nullable<Varchar>,
        last_name -> Nullable<Varchar>,
        phone_number -> Nullable<Varchar>,
        date_registered -> Timestamp,
        is_active -> Bool,
        last_login -> Nullable<Timestamp>,
        profile_image -> Nullable<Varchar>,
    }
}

diesel::table! {
    role_type (role_id) {
        role_id -> Int4,
        role_name -> Varchar,
        description -> Nullable<Varchar>,
    }
}

diesel::table! {
    user_role (user_id, role_id) {
        user_id -> Int4,
        role_id -> Int4,
        assigned_date -> Timestamp,
        is_primary -> Bool,
    }
}

diesel::table! {
    admin (admin_id) {
        admin_id -> Int4,
        email -> Varchar,
        password_hash -> Varchar,
        first_name -> Nullable<Varchar>,
        last_name -> Nullable<Varchar>,
        role_type_id -> Int4,
        last_login -> Nullable<Timestamp>,
        permission_level -> Int4,
    }
}

diesel::table! {
    admin_role_type (role_type_id) {
        role_type_id -> Int4,
        role_name -> Varchar,
        description -> Nullable<Varchar>,
    }
}

diesel::table! {
    refresh_token (token_id) {
        token_id -> Int4,
        user_id -> Int4,
        token -> Varchar,
        expires_at -> Timestamp,
        created_at -> Timestamp,
    }
}

diesel::table! {
    admin_session (session_id) {
        session_id -> Int4,
        admin_id -> Int4,
        session_token -> Varchar,
        ip_address -> Nullable<Varchar>,
        user_agent -> Nullable<Varchar>,
        expires_at -> Timestamp,
        created_at -> Timestamp,
    }
}

diesel::joinable!(user_role -> user_account (user_id));
diesel::joinable!(user_role -> role_type (role_id));
diesel::joinable!(admin -> admin_role_type (role_type_id));
diesel::joinable!(refresh_token -> user_account (user_id));
diesel::joinable!(admin_session -> admin (admin_id));

diesel::allow_tables_to_appear_in_same_query!(
    user_account, role_type, user_role, admin,
    admin_role_type, refresh_token, admin_session,
);