# oa_DB

# Example of how to generate migration and model files using sequelize
npx sequelize-cli model:generate --name UserPassword --attributes ownerUserId:integer,url:string,username:string,password:string,sharedByUserId:integer

npx sequelize-cli migration:create --name modify_users_passwords_add_weak_encryption_column

# Run migration
npx sequelize-cli db:migrate

# undo migration
npx sequelize-cli db:migrate:undo