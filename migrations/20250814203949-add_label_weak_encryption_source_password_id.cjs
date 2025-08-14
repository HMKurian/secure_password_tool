'use strict';

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up(queryInterface, Sequelize) {
    // Add columns to existing UserPasswords table
    await queryInterface.addColumn('UserPasswords', 'label', {
      type: Sequelize.STRING,
      allowNull: true
    });
    await queryInterface.addColumn('UserPasswords', 'weak_encryption', {
      type: Sequelize.BOOLEAN,
      defaultValue: false
    });
    await queryInterface.addColumn('UserPasswords', 'source_password_id', {
      type: Sequelize.INTEGER,
      allowNull: true,
      references: {
        model: 'UserPasswords',
        key: 'id'
      },
      onUpdate: 'CASCADE',
      onDelete: 'SET NULL'
    });
  },

  async down(queryInterface, Sequelize) {
    // Remove columns if migration is reverted
    await queryInterface.removeColumn('UserPasswords', 'label');
    await queryInterface.removeColumn('UserPasswords', 'weak_encryption');
    await queryInterface.removeColumn('UserPasswords', 'source_password_id');
  }
};
