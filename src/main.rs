use actix_web::{
    error, get,
    middleware::Logger,
    post,
    web::{self, Data, Json, Path, ServiceConfig},
    App, HttpResponse, HttpServer, Result,
};
use serde::{Deserialize, Serialize};
use shuttle_actix_web::ShuttleActixWeb;
use sqlx::{FromRow, PgPool};

mod criptografia;
mod utilitarios;
use criptografia::*;
use dotenv::dotenv;
use mysql::prelude::*;
use mysql::*;
use rand::rngs::OsRng;
use rand::RngCore;
use rpassword::prompt_password;
use std::env;
use std::io::{self, Write};
use utilitarios::*;

#[derive(Clone)]
struct AppState {
    pg_pool: PgPool,
    mysql_pool: Pool,
    chave_usuario_logado: Option<Vec<u8>>,
}

#[get("/todos/{id}")]
async fn retrieve(path: web::Path<i32>, state: web::Data<AppState>) -> Result<Json<Todo>> {
    let todo = sqlx::query_as("SELECT * FROM todos WHERE id = $1")
        .bind(*path)
        .fetch_one(&state.pg_pool)
        .await
        .map_err(|e| error::ErrorBadRequest(e.to_string()))?;

    Ok(Json(todo))
}

#[post("/todos")]
async fn add(todo: web::Json<TodoNew>, state: web::Data<AppState>) -> Result<Json<Todo>> {
    let todo = sqlx::query_as("INSERT INTO todos(note) VALUES ($1) RETURNING id, note")
        .bind(&todo.note)
        .fetch_one(&state.pg_pool)
        .await
        .map_err(|e| error::ErrorBadRequest(e.to_string()))?;

    Ok(Json(todo))
}
#[post("/criar_usuario")]
async fn criar_usuario(state: Data<AppState>) -> Result<HttpResponse> {
    let sucesso = state.criar_usuario();
    if sucesso {
        Ok(HttpResponse::Ok().body("Usuário criado com sucesso"))
    } else {
        Ok(HttpResponse::BadRequest().body("Falha ao criar usuário"))
    }
}

#[get("/consulta_bd")]
async fn consulta_bd(state: Data<AppState>) -> Result<HttpResponse> {
    state.consulta_bd();
    Ok(HttpResponse::Ok().body("Consulta realizada com sucesso"))
}

#[post("/fazer_login")]
async fn fazer_login(state: Data<AppState>) -> Result<HttpResponse> {
    let mut state = state.into_inner();
    let sucesso = &state.fazer_login();
    if sucesso {
        Ok(HttpResponse::Ok().body("Login realizado com sucesso"))
    } else {
        Ok(HttpResponse::BadRequest().body("Falha ao realizar login"))
    }
}

#[post("/inserir_senha")]
async fn inserir_senha(state: Data<AppState>) -> Result<HttpResponse> {
    state.inserir_senha();
    Ok(HttpResponse::Ok().body("Senha inserida com sucesso"))
}

#[get("/consultar_senhas")]
async fn consultar_senhas(state: Data<AppState>) -> Result<HttpResponse> {
    state.consultar_senhas();
    Ok(HttpResponse::Ok().body("Consulta de senhas realizada com sucesso"))
}

#[derive(Deserialize)]
struct TodoNew {
    pub note: String,
}

#[derive(Serialize, Deserialize, FromRow)]
struct Todo {
    pub id: i32,
    pub note: String,
}

impl AppState {
    pub fn gerar_chave_aleatoria() -> [u8; 32] {
        let mut chave = [0u8; 32];
        OsRng.fill_bytes(&mut chave);
        chave
    }

    pub fn criar_usuario(&self) -> bool {
        let mut conn = self.mysql_pool.get_conn().expect("Erro ao obter a conexão");
        let chave = AppState::gerar_chave_aleatoria();

        print!("Digite o email: ");
        io::stdout().flush().unwrap();
        let mut email = String::new();
        io::stdin()
            .read_line(&mut email)
            .expect("Falha ao ler o email");
        let email = email.trim();

        print!("Digite o nome de usuario: ");
        io::stdout().flush().unwrap();
        let mut nome_usuario = String::new();
        io::stdin()
            .read_line(&mut nome_usuario)
            .expect("Falha ao ler o nome de usuario");
        let nome_usuario = nome_usuario.trim();

        let senha = prompt_password("Digite a senha: ").expect("Falha ao ler a senha");
        let senha = senha.trim();
        let senha_novamente =
            prompt_password("Digite novamente a senha: ").expect("Falha ao ler a senha");
        let senha_novamente = senha_novamente.trim();

        if utilitarios::validar_email(&email)
            && senha == senha_novamente
            && utilitarios::validar_senha(&senha)
            && utilitarios::validar_usuario(&nome_usuario)
        {
            conn.exec_drop(
                r"INSERT INTO usuarios (chave_criptografia, usuario, email, senha) VALUES (:chave, :usuario, :email, :senha)",
                params! {
                    "chave" => &chave[..],
                    "usuario" => &nome_usuario[..],
                    "email" => &email[..],
                    "senha" => &senha[..],
                }
            ).expect("Erro ao inserir dados no banco de dados");
            true
        } else {
            false
        }
    }
    pub fn consulta_bd(&self) {
        let mut conn = self.mysql_pool.get_conn().expect("Erro ao obter a conexão");

        let lista_linhas: Vec<(Vec<u8>, String, String, String)> = conn
            .query("SELECT chave_criptografia, usuario, email, senha FROM usuarios")
            .expect("Erro ao consultar dados do banco de dados");

        for linha in lista_linhas {
            println!("Chave_criptografia:  {:?}", linha.0);
            println!("Usuario: {:?}", linha.1);
            println!("Email: {:?}", linha.2);
            println!("Senha: {:?}", linha.3);
            println!();
        }
    }

    pub fn fazer_login(&mut self) -> bool {
        let mut conn = self
            .mysql_pool
            .get_conn()
            .expect("Erro ao obter conexão do pool");

        print!("Digite o seu usuario:  ");
        io::stdout().flush().unwrap();
        let mut nome_usuario = String::new();
        io::stdin()
            .read_line(&mut nome_usuario)
            .expect("Falha ao ler o seu nome");
        let nome_usuario = nome_usuario.trim();

        let senha = prompt_password("Digite a senha:  ").expect("Falha ao ler a senha");
        let senha = senha.trim();

        let (chave_criptografia, usuario, senha_encontrada): (Vec<u8>, String, String) = conn
            .exec_first(
                "SELECT chave_criptografia, usuario, senha FROM usuarios WHERE usuario = :usuario",
                params! {
                    "usuario" => nome_usuario,
                },
            )
            .expect("Erro ao consultar os dados do usuario")
            .unwrap();

        if senha == senha_encontrada {
            self.chave_usuario_logado = Some(chave_criptografia);
            println!("Logado com sucesso como:  {:?}", usuario);
            true
        } else {
            false
        }
    }
    pub fn inserir_senha(&self) {
        let chave = self
            .chave_usuario_logado
            .as_ref()
            .expect("Usuário não logado");

        print!("Digite a url do site:  ");
        io::stdout().flush().unwrap();
        let mut url_site = String::new();
        io::stdin()
            .read_line(&mut url_site)
            .expect("Falha ao ler a URL do site");
        let url_site = url_site.trim();

        print!("Digite o seu usuario nesse site:  ");
        io::stdout().flush().unwrap();
        let mut usuario_site = String::new();
        io::stdin()
            .read_line(&mut usuario_site)
            .expect("Falha ao ler o nome de usuário");
        let usuario_site = usuario_site.trim();

        let senha = prompt_password("Digite a senha: ").expect("Falha ao ler a senha");
        let senha = senha.trim();
        let chave: [u8; 32] = chave
            .as_slice()
            .try_into()
            .expect("Chave de criptografia inválida");
        let (nonce, senha_criptografada) = encrypt(&chave, senha.as_bytes());

        let mut conn = self.mysql_pool.get_conn().expect("Erro ao obter a conexão");

        conn.exec_drop(
            r"INSERT INTO senhas_sites (url_site, usuario_site, senha_site, nonce) VALUES (:url_site, :usuario_site, :senha_site, :nonce)",
            params! {
                "url_site" => &url_site[..],
                "usuario_site" => &usuario_site[..],
                "senha_site" => &senha_criptografada[..],
                "nonce" => &nonce[..],
            },
        ).expect("Erro ao inserir a senha no banco de dados");
    }

    pub fn consultar_senhas(&self) {
        let chave = self
            .chave_usuario_logado
            .as_ref()
            .expect("Usuário não logado");
        let chave: [u8; 32] = chave
            .as_slice()
            .try_into()
            .expect("Chave de criptografia inválida");
        let mut conn = self.mysql_pool.get_conn().expect("Erro ao obter a conexão");

        let lista_linhas: Vec<(String, String, Vec<u8>, Vec<u8>)> = conn
            .query("SELECT url_site, usuario_site, senha_site, nonce FROM senhas_sites")
            .expect("Erro ao consultar os dados no banco de dados");

        for linha in lista_linhas {
            let url_site = linha.0;
            let usuario_site = linha.1;
            let senha = decrypt(&chave, &linha.3, &linha.2);

            println!("Site:  {:?}", url_site);
            println!("Usuario:  {:?}", usuario_site);
            println!("Senha:  {:?}", senha);
            println!();
        }
    }
}

#[shuttle_runtime::main]
async fn main(
    #[shuttle_shared_db::Postgres] pg_pool: PgPool,
    #[shuttle_shared_db::MySql] mysql_url: String,
) -> ShuttleActixWeb<impl FnOnce(&mut ServiceConfig) + Send + Clone + 'static> {
    dotenv().ok();

    sqlx::migrate!()
        .run(&pg_pool)
        .await
        .expect("Failed to run migrations");
    let mysql_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let mysql_pool = Pool::new(mysql_url).expect("Erro ao criar pool de conexão MySQL");

    let state = Data::new(AppState {
        pg_pool,
        mysql_pool,
        chave_usuario_logado: None,
    });

    let config = move |cfg: &mut ServiceConfig| {
        cfg.service(
            web::scope("/todos")
                .wrap(Logger::default())
                .service(retrieve)
                .service(add)
                .app_data(state.clone()),
        )
        .service(criar_usuario)
        .service(consulta_bd)
        .service(fazer_login)
        .service(inserir_senha)
        .service(consultar_senhas);
    };

    Ok(config.into())
}
