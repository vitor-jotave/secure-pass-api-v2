use rpassword::prompt_password;

pub fn limpar_tela(){
    print!("{esc}c", esc =27 as char)
}
pub fn esperar_enter(){
    prompt_password("Pressione ENTER").unwrap();
}
pub fn validar_nome(nome_para_validar: &str) ->bool {
    if nome_para_validar.len() <= 50{
        return true;
    } else{
        return false;
    }
}
pub fn validar_email(email_para_validar: &str) ->bool {
    if email_para_validar.len() <= 100{
        return true;
    } else{
        return false;
    }
}
pub fn validar_usuario(usuario_para_validar: &str) ->bool {
    if usuario_para_validar.len() <= 30{
        return true;
    } else{
        return false;
    }
}
pub fn validar_senha(senha_para_validar: &str) ->bool {
    if senha_para_validar.len() <= 20{
        return true;
    } else{
        return false;
    }
}