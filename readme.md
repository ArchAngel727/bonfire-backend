## Setup
### env
Copy the demo `.env` file and use it as a base<br>
`cp .env.demo .env`<br>
Generate secrete using `openssl rand -hex 32` and enter it into the `.env` file

### Database setup
Install the sqlx cli tool<br>
`cargo install sqlx-cli`<br>

Create the database by running

```bash
sqlx database create
sqlx migrate run
```

If you are updating from an older issue and are facing database issues please drop the old database and recreate it

```bash
sqlx database drop
sqlx database create
sqlx migrate run
```

### running the server
Build using `cargo build` after that run using run using `cargo run`<br>
The first user that you create will be the admin user, the admin user can be changed in the `.env` file
