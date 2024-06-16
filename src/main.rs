use actix_web::{
    cookie::Key, delete, error, get, middleware::Logger, post, put, web::{self, Json, ServiceConfig}, Result
};
use actix_session::{Session, SessionMiddleware, storage::CookieSessionStore};
use serde::{Deserialize, Serialize};
use shuttle_actix_web::ShuttleActixWeb;
use sqlx::{FromRow, PgPool};

#[post("/register")]
async fn register(user: web::Json<UserNew>, state: web::Data<AppState>) -> Result<Json<User>> {
    let user = sqlx::query_as::<_, User>(
        "INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id, username, password"
    )
    .bind(&user.username)
    .bind(&user.password)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| error::ErrorBadRequest(e.to_string()))?;

    Ok(Json(user))
}

#[post("/login")]
async fn login(user: web::Json<UserNew>, state: web::Data<AppState>, session: Session) -> Result<Json<User>> {
    let user_result = sqlx::query_as::<_, User>(
        "SELECT id, username, password FROM users WHERE username = $1 AND password = $2"
    )
    .bind(&user.username)
    .bind(&user.password)
    .fetch_one(&state.pool)
    .await;

    match user_result {
        Ok(user) => {
            session.insert("user_id", user.id).map_err(|e| error::ErrorInternalServerError(e.to_string()))?;
            Ok(Json(user))
        },
        Err(e) => Err(error::ErrorBadRequest(e.to_string())),
    }
}

#[post("/logout")]
async fn logout(session: Session) -> Result<Json<&'static str>> {
    session.clear();
    Ok(Json("Logged out"))
}

#[post("/passwords")]
async fn add_password(
    password: web::Json<PasswordNew>,
    state: web::Data<AppState>,
    session: Session,
) -> Result<Json<Password>> {
    // Verificar se o usuário está autenticado
    if let Some(user_id) = session.get::<i32>("user_id").map_err(|e| error::ErrorInternalServerError(e.to_string()))? {
        // Inserir a nova senha no banco de dados associada ao user_id da sessão
        let password = sqlx::query_as::<_, Password>(
            "INSERT INTO passwords (service, username, password, folder, user_id) VALUES ($1, $2, $3, $4, $5) RETURNING id, service, username, password, folder, user_id"
        )
        .bind(&password.service)
        .bind(&password.username)
        .bind(&password.password)
        .bind(&password.folder)
        .bind(user_id) // Usar o user_id da sessão
        .fetch_one(&state.pool)
        .await
        .map_err(|e| error::ErrorBadRequest(e.to_string()))?;

        Ok(Json(password))
    } else {
        // Se o usuário não estiver autenticado, retornar um erro de autorização
        Err(error::ErrorUnauthorized("Unauthorized"))
    }
}

#[get("/passwords")]
async fn list_passwords(state: web::Data<AppState>, session: Session) -> Result<Json<Vec<Password>>> {
    if let Some(user_id) = session.get::<i32>("user_id").map_err(|e| error::ErrorInternalServerError(e.to_string()))? {
        let passwords = sqlx::query_as::<_, Password>(
            "SELECT * FROM passwords WHERE user_id = $1"
        )
        .bind(user_id)
        .fetch_all(&state.pool)
        .await
        .map_err(|e| error::ErrorBadRequest(e.to_string()))?;

        Ok(Json(passwords))
    } else {
        Err(error::ErrorUnauthorized("Unauthorized"))
    }
}

#[get("/passwords/folders")]
async fn list_passwords_by_folder(
    state: web::Data<AppState>,
    session: Session,
    query: web::Query<FolderQuery>,
) -> Result<Json<Vec<Password>>> {
    // Verificar se o usuário está autenticado
    if let Some(user_id) = session.get::<i32>("user_id").map_err(|e| error::ErrorInternalServerError(e.to_string()))? {
        // Buscar as senhas do usuário autenticado no banco de dados
        let passwords = sqlx::query_as::<_, Password>(
            "SELECT * FROM passwords WHERE user_id = $1 AND folder = $2"
        )
        .bind(user_id)
        .bind(&query.folder)
        .fetch_all(&state.pool)
        .await
        .map_err(|e| error::ErrorBadRequest(e.to_string()))?;

        Ok(Json(passwords))
    } else {
        // Se o usuário não estiver autenticado, retornar um erro de autorização
        Err(error::ErrorUnauthorized("Unauthorized"))
    }
}

#[get("/folders")]
async fn list_folders(
    state: web::Data<AppState>,
    session: Session,
) -> Result<web::Json<Vec<String>>> {
    // Verificar se o usuário está autenticado
    if let Some(user_id) = session.get::<i32>("user_id").map_err(|e| error::ErrorInternalServerError(e.to_string()))? {
        // Buscar as pastas do usuário autenticado no banco de dados
        let folders = sqlx::query_as::<_, Folder>(
            "SELECT DISTINCT folder FROM passwords WHERE user_id = $1"
        )
        .bind(user_id)
        .fetch_all(&state.pool)
        .await
        .map_err(|e| error::ErrorBadRequest(e.to_string()))?;

        let folder_names: Vec<String> = folders.into_iter()
            .map(|folder| folder.folder)
            .collect();

        Ok(web::Json(folder_names))
    } else {
        // Se o usuário não estiver autenticado, retornar um erro de autorização
        Err(error::ErrorUnauthorized("Unauthorized"))
    }
}

#[put("/passwords/{id}")]
async fn edit_password(
    path: web::Path<i32>,
    password: web::Json<PasswordUpdate>,
    state: web::Data<AppState>,
    session: Session,
) -> Result<Json<Password>> {
    // Verificar se o usuário está autenticado
    if let Some(user_id) = session.get::<i32>("user_id").map_err(|e| error::ErrorInternalServerError(e.to_string()))? {
        // Verificar se a senha pertence ao usuário autenticado
        let password_exists = sqlx::query(
            "SELECT 1 FROM passwords WHERE id = $1 AND user_id = $2"
        )
        .bind(*path)
        .bind(user_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| error::ErrorBadRequest(e.to_string()))?;

        if password_exists.is_none() {
            return Err(error::ErrorUnauthorized("Unauthorized"));
        }

        // Atualizar a senha no banco de dados
        let updated_password = sqlx::query_as::<_, Password>(
            "UPDATE passwords SET username = $1, password = $2, folder = $3 WHERE id = $4 RETURNING id, service, username, password, folder, user_id"
        )
        .bind(&password.username)
        .bind(&password.password)
        .bind(&password.folder)
        .bind(*path)
        .fetch_one(&state.pool)
        .await
        .map_err(|e| error::ErrorBadRequest(e.to_string()))?;

        Ok(Json(updated_password))
    } else {
        // Se o usuário não estiver autenticado, retornar um erro de autorização
        Err(error::ErrorUnauthorized("Unauthorized"))
    }
}

#[delete("/passwords/{id}")]
async fn delete_password(
    path: web::Path<i32>,
    state: web::Data<AppState>,
    session: Session,
) -> Result<web::Json<&'static str>> {
    // Verificar se o usuário está autenticado
    if let Some(user_id) = session.get::<i32>("user_id").map_err(|e| error::ErrorInternalServerError(e.to_string()))? {
        // Verificar se a senha pertence ao usuário autenticado
        let password_exists = sqlx::query(
            "SELECT 1 FROM passwords WHERE id = $1 AND user_id = $2"
        )
        .bind(*path)
        .bind(user_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| error::ErrorBadRequest(e.to_string()))?;

        if password_exists.is_none() {
            return Err(error::ErrorUnauthorized("Unauthorized"));
        }

        // Deletar a senha do banco de dados
        sqlx::query("DELETE FROM passwords WHERE id = $1")
            .bind(*path)
            .execute(&state.pool)
            .await
            .map_err(|e| error::ErrorBadRequest(e.to_string()))?;

        Ok(web::Json("Password deleted"))
    } else {
        // Se o usuário não estiver autenticado, retornar um erro de autorização
        Err(error::ErrorUnauthorized("Unauthorized"))
    }
}

#[shuttle_runtime::main]
async fn main(
    #[shuttle_shared_db::Postgres] pool: PgPool,
) -> ShuttleActixWeb<impl FnOnce(&mut ServiceConfig) + Send + Clone + 'static> {
    sqlx::migrate!()
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    let state = web::Data::new(AppState { pool });
    let secret_key = Key::generate(); // chave secreta para criptografia de cookies

    let config = move |cfg: &mut ServiceConfig| {
        cfg.service(
            web::scope("/api/v1")
                .wrap(Logger::default())
                .wrap(SessionMiddleware::builder(CookieSessionStore::default(), secret_key.clone()).build())
                .service(register)
                .service(login)
                .service(logout)
                .service(add_password)
                .service(list_passwords)
                .service(list_passwords_by_folder)
                .service(list_folders)
                .service(edit_password)
                .service(delete_password)
                .app_data(state.clone()),
        );
    };

    Ok(config.into())
}

#[derive(Clone)]
struct AppState {
    pool: PgPool,
}

#[derive(Serialize, Deserialize, FromRow)]
struct Password {
    pub id: i32,
    pub service: String,
    pub username: String,
    pub password: String,
    pub folder: String,
    pub user_id: i32,
}

#[derive(Serialize, Deserialize)]
struct PasswordNew {
    pub service: String,
    pub username: String,
    pub password: String,
    pub folder: String,
}

#[derive(Serialize, Deserialize)]
struct PasswordUpdate {
    pub username: String,
    pub password: String,
    pub folder: String,
}

#[derive(Serialize, Deserialize, sqlx::FromRow)]
struct User {
    pub id: i32,
    pub username: String,
    pub password: String,
}

#[derive(Serialize, Deserialize)]
struct UserNew {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
struct FolderQuery {
    folder: String,
}

#[derive(sqlx::FromRow)]
struct Folder {
    folder: String,
}