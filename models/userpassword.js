'use strict';
import { Sequelize, Model } from "sequelize";

export default (sequelize, DataTypes) => {
  class UserPassword extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static associate(models) {
      UserPassword.belongsTo(models.User, {foreignKey: 'ownerUserId'})
    }
  }
  UserPassword.init({
    ownerUserId: DataTypes.INTEGER,
    url: DataTypes.STRING,
    username: DataTypes.STRING,
    password: DataTypes.STRING,
    sharedByUserId: DataTypes.INTEGER,
    label: DataTypes.STRING,
    weak_encryption: DataTypes.BOOLEAN,
    source_password_id: DataTypes.INTEGER
  }, {
    sequelize,
    modelName: 'UserPassword',
  });
  return UserPassword;
};