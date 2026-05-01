## Setup
### env
`cp .env.demo .env`<br>
generate secrete using `openssl rand -hex 32`

### db
```bash
cargo install sqlx-cli
sqlx migrate run
```

### running the server
build using `cargo build` after that run using run using `cargo run`
