#![allow(unused_imports)]

use actix_web::{
    cookie::{Key, SameSite}, delete, error, get, http, middleware::Logger, post, put, web::{self, Json, ServiceConfig}, Result
};
use actix_session::{Session, SessionMiddleware, storage::CookieSessionStore};
use serde::{Deserialize, Serialize};
use shuttle_actix_web::ShuttleActixWeb;
use sqlx::{FromRow, PgPool, Row};
use aes_gcm::aead::{Aead, KeyInit, OsRng, consts::U12};
use aes_gcm::aes::Aes256;
use aes_gcm::{AesGcm, Nonce};
use rand::{Rng, RngCore};
use actix_cors::Cors;


#[post("/register")]
async fn register(user: web::Json<UserNew>, state: web::Data<AppState>) -> Result<Json<User>> {
    let user = sqlx::query_as::<_, User>(
        "INSERT INTO users (username, password, chave_criptografia) VALUES ($1, $2, $3) RETURNING chave_criptografia, username, password"
    )
    .bind(&user.username)
    .bind(&user.password)
    .bind(gerar_chave())
    .fetch_one(&state.pool)
    .await
    .map_err(|e| error::ErrorBadRequest(e.to_string()))?;

    Ok(Json(user))
}

#[post("/login")]
async fn login(user: web::Json<UserNew>, state: web::Data<AppState>, session: Session) -> Result<Json<User>> {
    let user_result = sqlx::query_as::<_, User>(
        "SELECT chave_criptografia, username, password FROM users WHERE username = $1 AND password = $2"
    )
    .bind(&user.username)
    .bind(&user.password)
    .fetch_one(&state.pool)
    .await;

    match user_result {
        Ok(user) => {
            session.insert("chave", user.chave_criptografia).map_err(|e| error::ErrorInternalServerError(e.to_string()))?;
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
    if let Some(chave) = session.get::<Vec<u8>>("chave").map_err(|e| error::ErrorInternalServerError(e.to_string()))? {
        //criptografa a senha;
        let chavee:[u8;32] = chave.as_slice().try_into().expect("chave invalida");
        let(nonce,senha) = encrypt(&chavee, password.password.as_bytes());

        // Inserir a nova senha no banco de dados associada ao user_id da sessão
        let password = sqlx::query_as::<_, Password>(
            "INSERT INTO passwords (nonce, service, username, password, folder, chave) VALUES ($1, $2, $3, $4, $5, $6) RETURNING nonce, id, service, username, password, folder, chave"
        )
        .bind(nonce)
        .bind(&password.service)
        .bind(&password.username)
        .bind(senha)
        .bind(&password.folder)
        .bind(chave) // Usar a chave da sessão
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
async fn list_passwords(state: web::Data<AppState>, session: Session) -> Result<Json<Vec<SenhaSaida>>> {
    if let Some(chave) = session.get::<Vec<u8>>("chave").map_err(|e| error::ErrorInternalServerError(e.to_string()))? {
        let passwords = sqlx::query_as::<_, Password>(
            "SELECT * FROM passwords WHERE chave = $1"
        )
        .bind(chave.clone())
        .fetch_all(&state.pool)
        .await
        .map_err(|e| error::ErrorBadRequest(e.to_string()))?;

        let chavee:[u8;32] = chave.as_slice().try_into().expect("chave invalida");

        let senhaoutput: Vec<SenhaSaida> = passwords.into_iter().map(|password| {
            SenhaSaida {
                nonce: password.nonce,
                id: password.id,
                service: password.service,
                username: password.username,
                password: String::from_utf8(decrypt(&chavee, &password.nonce, &password.password)).expect("Senha invalida"),
                folder: password.folder,
                chave: password.chave,
            }
        }).collect();

        Ok(Json(senhaoutput))
    } else {
        Err(error::ErrorUnauthorized("Unauthorized"))
    }
}

#[get("/passwords/folders")]
async fn list_passwords_by_folder(
    state: web::Data<AppState>,
    session: Session,
    query: web::Query<FolderQuery>,
) -> Result<Json<Vec<SenhaSaida>>> {
    // Verificar se o usuário está autenticado
    if let Some(chave) = session.get::<Vec<u8>>("chave").map_err(|e| error::ErrorInternalServerError(e.to_string()))? {
        // Buscar as senhas do usuário autenticado no banco de dados
        let passwords = sqlx::query_as::<_, Password>(
            "SELECT * FROM passwords WHERE chave = $1 AND folder = $2"
        )
        .bind(chave.clone())
        .bind(&query.folder)
        .fetch_all(&state.pool)
        .await
        .map_err(|e| error::ErrorBadRequest(e.to_string()))?;

        let chavee:[u8;32] = chave.as_slice().try_into().expect("chave invalida");

        let senhaoutput: Vec<SenhaSaida> = passwords.into_iter().map(|password| {
            SenhaSaida {
                nonce: password.nonce,
                id: password.id,
                service: password.service,
                username: password.username,
                password: String::from_utf8(decrypt(&chavee, &password.nonce, &password.password)).expect("Senha invalida"),
                folder: password.folder,
                chave: password.chave,
            }
        }).collect();

        Ok(Json(senhaoutput))
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
    if let Some(chave) = session.get::<Vec<u8>>("chave").map_err(|e| error::ErrorInternalServerError(e.to_string()))? {
        // Buscar as pastas do usuário autenticado no banco de dados
        let folders = sqlx::query_as::<_, Folder>(
            "SELECT DISTINCT folder FROM passwords WHERE chave = $1"
        )
        .bind(chave)
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
    if let Some(chave) = session.get::<Vec<u8>>("chave").map_err(|e| error::ErrorInternalServerError(e.to_string()))? {
        // Verificar se a senha pertence ao usuário autenticado
        let password_exists = sqlx::query(
            "SELECT 1 FROM passwords WHERE id = $1 AND chave = $2"
        )
        .bind(*path)
        .bind(chave.clone())
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| error::ErrorBadRequest(e.to_string()))?;

        if password_exists.is_none() {
            return Err(error::ErrorUnauthorized("Unauthorized"));
        }

        let chavee:[u8;32] = chave.as_slice().try_into().expect("chave invalida");
        let(nonce,senha) = encrypt(&chavee, password.password.as_bytes());
        // Atualizar a senha no banco de dados
        let updated_password = sqlx::query_as::<_, Password>(
            "UPDATE passwords SET username = $1, password = $2, folder = $3, nonce = $4, service = $5 WHERE id = $6 RETURNING nonce, id, service, username, password, folder, chave"
        )
        .bind(&password.username)
        .bind(senha)
        .bind(&password.folder)
        .bind(nonce)
        .bind(*path)
        .bind(&password.service)
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
    if let Some(chave) = session.get::<Vec<u8>>("chave").map_err(|e| error::ErrorInternalServerError(e.to_string()))? {
        // Verificar se a senha pertence ao usuário autenticado
        let password_exists = sqlx::query(
            "SELECT 1 FROM passwords WHERE id = $1 AND chave = $2"
        )
        .bind(*path)
        .bind(chave)
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
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allowed_headers(vec![http::header::AUTHORIZATION, http::header::ACCEPT, http::header::CONTENT_TYPE, http::header::ORIGIN, http::header::COOKIE, http::header::SET_COOKIE])
            .supports_credentials();

        let session_middleware = SessionMiddleware::builder(CookieSessionStore::default(), secret_key.clone())
            .cookie_secure(true) // Garante que os cookies são enviados apenas via HTTPS
            .cookie_same_site(SameSite::None) // Define SameSite como None
            .build();

        cfg.service(
            web::scope("/api/v1")
                .wrap(Logger::default())
                .wrap(session_middleware)
                .wrap(cors)
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
    pub nonce:[u8;12],
    pub id:i32,
    pub service: String,
    pub username: String,
    pub password: Vec<u8>,
    pub folder: String,
    pub chave:[u8;32]

}

#[derive(Debug, Serialize)]
struct SenhaSaida {
    pub nonce: [u8; 12],
    pub id: i32,
    pub service: String,
    pub username: String,
    pub password: String, 
    pub folder: String,
    pub chave: [u8; 32],
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
    pub service: String,
}

#[derive(Serialize, Deserialize, sqlx::FromRow)]
struct User {
    pub chave_criptografia: [u8;32],
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

//função para criptografar.
pub fn encrypt(chave: &[u8; 32],senha_criptografar: &[u8]) ->(Vec<u8>,Vec<u8>){
    //inicia a cifra AES-GCM com a chave fornecida;

    let cifra = AesGcm::<Aes256, U12>::new_from_slice(chave).unwrap();
    //gera un nonce aleatorio;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    //criptografa os dados;
    let senha_criptografada = cifra.encrypt(Nonce::from_slice(&nonce),senha_criptografar).expect("Falha ao criptografar");

    //retorna uma tupla com a senha ja criptografada e o nonce;

    (nonce.to_vec(),senha_criptografada)
}

pub fn decrypt(chave: &[u8;32], nonce: &[u8], senha_criptografada: &[u8]) -> Vec<u8>{
    //inicia a cifra;
    let cifra = AesGcm::<Aes256, U12>::new_from_slice(chave).unwrap();

    //Descriptografa;
    let senha_descriptografada = cifra.decrypt(Nonce::from_slice(nonce), senha_criptografada).expect("Erro ao descriptografar");

    senha_descriptografada

}

pub fn gerar_chave()->[u8;32]{
    let mut chave = [0u8;32];
    OsRng.fill_bytes(&mut chave);
    chave
}