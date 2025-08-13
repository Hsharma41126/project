const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');

const Printer = sequelize.define('Printer', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  name: {
    type: DataTypes.STRING(100),
    allowNull: false
  },
  type: {
    type: DataTypes.ENUM('Kitchen Printer', 'Bar Printer', 'Receipt Printer', 'Main Printer'),
    allowNull: false
  },
  ip_address: {
    type: DataTypes.STRING(45),
    allowNull: true
  },
  port: {
    type: DataTypes.INTEGER,
    allowNull: true
  },
  status: {
    type: DataTypes.ENUM('online', 'offline', 'error'),
    defaultValue: 'offline'
  },
  is_active: {
    type: DataTypes.BOOLEAN,
    defaultValue: true
  },
  last_test: {
    type: DataTypes.DATE,
    allowNull: true
  }
}, {
  tableName: 'printers'
});

module.exports = Printer;