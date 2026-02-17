pub mod api;

use actix_web::{web};
use actix_files as fs;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .configure(api::configure)
    )
    .service(
        fs::Files::new("/", "./dashboard/dist")
            .index_file("index.html")
    );
}
